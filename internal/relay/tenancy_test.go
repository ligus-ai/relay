package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Tenancy (docs/tenancy.md). Adversarial: cross-tenant reads, writes and
// listings; a tenant named in a header; token confusion between tenants;
// pairing-code collisions; contacts and tunnel hosts.

// randKey is a fresh issuer key (testKey is a fixed one, the same every call).
func randKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type tenancyFixture struct {
	ts         *httptest.Server
	srv        *Server
	shared     ed25519.PrivateKey // LANGSTROTH_RELAY_TOKEN_PUBKEY: vouches for home
	acmeKey    ed25519.PrivateKey // acme's own issuer
	evilKey    ed25519.PrivateKey // nobody's
	acmeAdmin  string             // acme's static admin token
	acme, home string             // ordinary tokens
}

func (f *tenancyFixture) tok(k ed25519.PrivateKey, c TokenClaims) string {
	if c.Exp == 0 {
		c.Exp = uint64(time.Now().Add(time.Hour).Unix())
	}
	return issueToken(k, c)
}

func newTenancyFixture(t *testing.T, store Store, limits string) *tenancyFixture {
	t.Helper()
	t.Setenv("LANGSTROTH_RELAY_METRICS_TOKEN", "ops-metrics-token")
	f := newTenancyFixtureNoCheck(t, store, limits)
	if err := tenancyConfigError(); err != nil {
		t.Fatal(err)
	}
	return f
}

// newTenancyFixtureNoCheck builds the fixture without the startup check
// (a library caller of New).
func newTenancyFixtureNoCheck(t *testing.T, store Store, limits string) *tenancyFixture {
	t.Helper()
	f := &tenancyFixture{shared: randKey(t), acmeKey: randKey(t), evilKey: randKey(t), acmeAdmin: "acme-admin-token-0123456789abcdef"}
	if limits == "" {
		limits = "{}"
	}
	cfg := fmt.Sprintf(`{"defaults": %s, "tenants": [
	  {"id": "acme", "issuer_pubkeys": [%q], "shared_issuer": false, "admin_token_sha256": %q},
	  {"id": "home"}]}`, limits, pubHex(f.acmeKey), sha256hex(f.acmeAdmin))
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(f.shared))
	t.Setenv("LANGSTROTH_RELAY_TENANCY", cfg)
	f.srv = New(Options{Store: store, Membership: true})
	f.ts = httptest.NewServer(f.srv.Handler())
	t.Cleanup(f.ts.Close)
	f.acme = f.tok(f.acmeKey, TokenClaims{Sub: "alice", Tid: "acme"})
	f.home = f.tok(f.shared, TokenClaims{Sub: "alice", Tid: "home"})
	return f
}

func (f *tenancyFixture) envelopes(t *testing.T, tok, ws string) []Envelope {
	t.Helper()
	code, b := req(t, "GET", f.ts.URL+"/v1/workspaces/"+ws+"/envelopes", tok, nil)
	if code != 200 {
		t.Fatalf("GET %s: %d %s", ws, code, b)
	}
	var rows []Envelope
	_ = json.Unmarshal(b, &rows)
	return rows
}

func tenancyStores(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Run("memory", func(t *testing.T) { fn(t, newMemoryStore()) })
	t.Run("postgres", func(t *testing.T) {
		if os.Getenv("TEST_DATABASE_URL") == "" {
			t.Skip("set TEST_DATABASE_URL to run Postgres integration tests")
		}
		fn(t, pgStore(t))
	})
}

func TestTenancyCrossTenantReadsAndWrites(t *testing.T) {
	tenancyStores(t, func(t *testing.T, s Store) {
		f := newTenancyFixture(t, s, "")
		// Both tenants use the same workspace id: two unrelated rooms.
		if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/team/envelopes", f.acme, "acme-secret"); code != 200 {
			t.Fatal(code)
		}
		if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/team/keyring", f.acme, "acme-key"); code != 200 {
			t.Fatal(code)
		}
		if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/team/presence", f.acme, map[string]any{"device_id": "d", "data": "acme-dev"}); code != 200 {
			t.Fatal(code)
		}
		if rows := f.envelopes(t, f.home, "team"); len(rows) != 0 {
			t.Fatalf("home read acme's ciphertext: %+v", rows)
		}
		for _, path := range []string{"keyring", "presence", "candidates"} {
			_, b := req(t, "GET", f.ts.URL+"/v1/workspaces/team/"+path, f.home, nil)
			if strings.Contains(string(b), "acme") {
				t.Fatalf("home read acme's %s: %s", path, b)
			}
		}
		// home's write lands in home's room, with its own sequence.
		code, b := req(t, "POST", f.ts.URL+"/v1/workspaces/team/envelopes", f.home, "home-msg")
		if code != 200 || !strings.Contains(string(b), `"seq":1`) {
			t.Fatalf("home's first write: %d %s (a shared sequence would leak acme's activity)", code, b)
		}
		rows := f.envelopes(t, f.acme, "team")
		if len(rows) != 1 || string(rows[0].Body) != `"acme-secret"` {
			t.Fatalf("acme's room changed: %+v", rows)
		}
		// Paths can't climb into another tenant's namespace.
		for _, ws := range []string{"..%2Fhome%2Fteam", "home%2Fteam", "%2E%2E/home/team"} {
			code, b := req(t, "GET", f.ts.URL+"/v1/workspaces/"+ws+"/envelopes", f.acme, nil)
			if code == 200 && strings.Contains(string(b), "home-msg") {
				t.Fatalf("acme reached home's room via %q", ws)
			}
		}
		// Membership: acme claims "team"; home's claim is independent.
		if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/team/members/claim", f.acme, map[string]any{"login": "alice"}); code != 200 {
			t.Fatal(code)
		}
		if code, b := req(t, "POST", f.ts.URL+"/v1/workspaces/team/members/claim", f.home, map[string]any{"login": "alice"}); code != 200 || !strings.Contains(string(b), "true") {
			t.Fatalf("home's claim of its own team: %d %s", code, b)
		}
	})
}

func TestTenancyHeaderSpoofIgnored(t *testing.T) {
	f := newTenancyFixture(t, newMemoryStore(), "")
	if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/w/envelopes", f.home, "home-only"); code != 200 {
		t.Fatal(code)
	}
	r, _ := http.NewRequest("GET", f.ts.URL+"/v1/workspaces/w/envelopes", nil)
	r.Header.Set("Authorization", "Bearer "+f.acme)
	for _, h := range []string{"X-Ligus-Tenant", "X-Hive-Tenant", "X-Tenant-Id", "X-Tenant", "Tenant"} {
		r.Header.Set(h, "home")
	}
	q := r.URL.Query()
	q.Set("tenant", "home")
	q.Set("tid", "home")
	r.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	var rows []Envelope
	_ = json.NewDecoder(resp.Body).Decode(&rows)
	resp.Body.Close()
	if len(rows) != 0 {
		t.Fatalf("a header or query parameter moved acme into home: %+v", rows)
	}
	// No token at all is refused even with a tenant header.
	r2, _ := http.NewRequest("GET", f.ts.URL+"/v1/workspaces/w/envelopes", nil)
	r2.Header.Set("X-Ligus-Tenant", "home")
	resp, _ = http.DefaultClient.Do(r2)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tenant header without a token: %d", resp.StatusCode)
	}
}

func TestTenancyTokenConfusion(t *testing.T) {
	f := newTenancyFixture(t, newMemoryStore(), "")
	if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/w/envelopes", f.home, "home-only"); code != 200 {
		t.Fatal(code)
	}
	exp := uint64(time.Now().Add(-time.Minute).Unix())
	cases := map[string]string{
		// acme's own issuer can't vouch for home.
		"acme key, tid home": f.tok(f.acmeKey, TokenClaims{Sub: "alice", Tid: "home"}),
		// acme turned the shared issuer off for itself.
		"shared key, tid acme": f.tok(f.shared, TokenClaims{Sub: "alice", Tid: "acme"}),
		"acme key, no tid":     f.tok(f.acmeKey, TokenClaims{Sub: "alice"}),
		"shared key, no tid":   f.tok(f.shared, TokenClaims{Sub: "alice"}),
		"unknown tenant":       f.tok(f.shared, TokenClaims{Sub: "alice", Tid: "evil"}),
		"stranger's key":       f.tok(f.evilKey, TokenClaims{Sub: "alice", Tid: "home"}),
		"expired":              issueToken(f.shared, TokenClaims{Sub: "alice", Tid: "home", Exp: exp}),
		"tid case":             f.tok(f.shared, TokenClaims{Sub: "alice", Tid: "HOME"}),
		"not a token":          "home",
	}
	// A token whose signed claims say acme but whose unsigned copy (spliced
	// from another token) says home.
	acmeParts := strings.Split(f.tok(f.acmeKey, TokenClaims{Sub: "alice", Tid: "acme"}), ".")
	homeParts := strings.Split(f.home, ".")
	cases["spliced claims"] = acmeParts[0] + "." + homeParts[1] + "." + acmeParts[2]
	for name, tok := range cases {
		code, b := req(t, "GET", f.ts.URL+"/v1/workspaces/w/envelopes", tok, nil)
		if code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	// The pairing and contact routes are behind the same gate.
	if code, _ := req(t, "POST", f.ts.URL+"/v1/pair", cases["acme key, tid home"], map[string]any{"payload": "sealed1:" + strings.Repeat("A", 44)}); code != http.StatusUnauthorized {
		t.Errorf("pairing with a confused token: %d", code)
	}
}

func TestTenancyListingsAndAdminScope(t *testing.T) {
	tenancyStores(t, func(t *testing.T, s Store) {
		f := newTenancyFixture(t, s, "")
		for _, ws := range []string{"a1", "a2"} {
			req(t, "POST", f.ts.URL+"/v1/workspaces/"+ws+"/envelopes", f.acme, ws)
		}
		for _, ws := range []string{"a1", "h1"} {
			req(t, "POST", f.ts.URL+"/v1/workspaces/"+ws+"/envelopes", f.home, "home-"+ws)
		}
		rooms := func(tok, after string) (int, []string) {
			code, b := req(t, "GET", f.ts.URL+"/v1/tenant/rooms?after="+after, tok, nil)
			var out struct {
				Rooms []tenantRoomRow `json:"rooms"`
			}
			_ = json.Unmarshal(b, &out)
			ids := []string{}
			for _, r := range out.Rooms {
				ids = append(ids, r.ID)
			}
			return code, ids
		}
		code, ids := rooms(f.acmeAdmin, "")
		if code != 200 || strings.Join(ids, ",") != "a1,a2" {
			t.Fatalf("acme's static admin token lists: %d %v", code, ids)
		}
		// An "after" cursor can't escape the prefix: "a2" sorts before
		// "home/…" only inside acme's namespace.
		if _, ids := rooms(f.acmeAdmin, "a2"); len(ids) != 0 {
			t.Fatalf("listing past acme's last room: %v", ids)
		}
		homeAdmin := f.tok(f.shared, TokenClaims{Sub: "ops", Tid: "home", Caps: []string{tenantAdminCap}})
		if _, ids := rooms(homeAdmin, ""); strings.Join(ids, ",") != "a1,h1" {
			t.Fatalf("home's admin lists: %v", ids)
		}
		// An ordinary member token isn't an admin; nor is no token.
		if code, _ := rooms(f.home, ""); code != http.StatusUnauthorized {
			t.Fatalf("member token on the admin route: %d", code)
		}
		if code, _ := rooms("", ""); code != http.StatusUnauthorized {
			t.Fatalf("no token on the admin route: %d", code)
		}
		// The admin cap from acme's issuer can't administer home.
		forged := f.tok(f.acmeKey, TokenClaims{Sub: "ops", Tid: "home", Caps: []string{tenantAdminCap}})
		if code, _ := rooms(forged, ""); code != http.StatusUnauthorized {
			t.Fatalf("acme-signed admin token for home: %d", code)
		}
		// acme purges its a1; home's a1 is untouched.
		if code, b := req(t, "DELETE", f.ts.URL+"/v1/tenant/rooms/a1", f.acmeAdmin, nil); code != 200 {
			t.Fatalf("purge: %d %s", code, b)
		}
		if rows := f.envelopes(t, f.acme, "a1"); len(rows) != 0 {
			t.Fatalf("purged room still holds %d", len(rows))
		}
		if rows := f.envelopes(t, f.home, "a1"); len(rows) != 1 {
			t.Fatalf("acme's purge reached home's a1: %+v", rows)
		}
		code, b := req(t, "GET", f.ts.URL+"/v1/tenant", f.acmeAdmin, nil)
		if code != 200 || !strings.Contains(string(b), `"tenant":"acme"`) || !strings.Contains(string(b), `"rooms":1`) {
			t.Fatalf("tenant info: %d %s", code, b)
		}
	})
}

func TestTenancyPairingCodeCollision(t *testing.T) {
	f := newTenancyFixture(t, newMemoryStore(), "")
	prev := newPairCode
	newPairCode = func() string { return "ABCDEF" }
	t.Cleanup(func() { newPairCode = prev })
	pa, ph := "sealed1:"+strings.Repeat("A", 44), "sealed1:"+strings.Repeat("H", 44)
	for _, c := range []struct{ tok, payload string }{{f.acme, pa}, {f.home, ph}} {
		code, b := req(t, "POST", f.ts.URL+"/v1/pair", c.tok, map[string]any{"payload": c.payload})
		if code != 200 || !strings.Contains(string(b), "ABCDEF") {
			t.Fatalf("create: %d %s", code, b)
		}
	}
	code, b := req(t, "GET", f.ts.URL+"/v1/pair/ABCDEF", f.home, nil)
	if code != 200 || !strings.Contains(string(b), ph) {
		t.Fatalf("home resolved %d %s", code, b)
	}
	if code, _ := req(t, "GET", f.ts.URL+"/v1/pair/ABCDEF", f.home, nil); code != 404 {
		t.Fatalf("home's code is single-use: %d", code)
	}
	code, b = req(t, "GET", f.ts.URL+"/v1/pair/ABCDEF", f.acme, nil)
	if code != 200 || !strings.Contains(string(b), pa) {
		t.Fatalf("acme's code must survive home's resolve: %d %s", code, b)
	}
}

func TestTenancyPairingCapPerTenant(t *testing.T) {
	f := newTenancyFixture(t, newMemoryStore(), `{"max_pairings": 1}`)
	p := map[string]any{"payload": "sealed1:" + strings.Repeat("A", 44)}
	if code, _ := req(t, "POST", f.ts.URL+"/v1/pair", f.acme, p); code != 200 {
		t.Fatal(code)
	}
	if code, _ := req(t, "POST", f.ts.URL+"/v1/pair", f.acme, p); code != http.StatusServiceUnavailable {
		t.Fatalf("acme over its pairing cap: %d", code)
	}
	if code, _ := req(t, "POST", f.ts.URL+"/v1/pair", f.home, p); code != 200 {
		t.Fatalf("acme's codes must not use home's cap: %d", code)
	}
}

func TestTenancyContactsScoped(t *testing.T) {
	f := newTenancyFixture(t, newMemoryStore(), "")
	cid := "AAAAAAAAAAAAAAAAAAAAAA"
	key := strings.Repeat("A", 43)
	if code, b := req(t, "PUT", f.ts.URL+"/v1/contacts/"+cid, f.acme, map[string]any{"record": "acme-record", "writeKey": key}); code != 200 {
		t.Fatalf("acme put: %d %s", code, b)
	}
	if code, _ := req(t, "GET", f.ts.URL+"/v1/contacts/"+cid, f.home, nil); code != 404 {
		t.Fatalf("home read acme's contact: %d", code)
	}
	if code, _ := req(t, "POST", f.ts.URL+"/v1/contacts/"+cid+"/drop", f.home, map[string]any{"blob": "x"}); code != 404 {
		t.Fatalf("home dropped into acme's box: %d", code)
	}
	if code, b := req(t, "GET", f.ts.URL+"/v1/contacts/"+cid, f.acme, nil); code != 200 || !strings.Contains(string(b), "acme-record") {
		t.Fatalf("acme read its contact: %d %s", code, b)
	}
}

func TestTenancyQuotasAndRates(t *testing.T) {
	f := newTenancyFixture(t, newMemoryStore(), `{"max_bytes": 20, "max_rooms": 2, "rate": 0.001, "burst": 6}`)
	if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/a/envelopes", f.acme, "0123456789"); code != 200 { // 12 bytes
		t.Fatal(code)
	}
	if code, b := req(t, "POST", f.ts.URL+"/v1/workspaces/a/envelopes", f.acme, "abcdefghij"); code != http.StatusInsufficientStorage || !strings.Contains(string(b), "tenant storage") {
		t.Fatalf("acme over its bytes: %d %s", code, b)
	}
	if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/b/presence", f.acme, map[string]any{"device_id": "d", "data": 1}); code != 200 {
		t.Fatal(code)
	}
	if code, b := req(t, "POST", f.ts.URL+"/v1/workspaces/c/presence", f.acme, map[string]any{"device_id": "d", "data": 1}); code != http.StatusInsufficientStorage || !strings.Contains(string(b), "tenant room") {
		t.Fatalf("acme over its rooms: %d %s", code, b)
	}
	// home has its own bucket and quota.
	if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/a/envelopes", f.home, "0123456789"); code != 200 {
		t.Fatalf("home blocked by acme's usage: %d", code)
	}
	// acme has used 4 of its 6 requests; two more pass, the next is 429.
	for i := 0; i < 2; i++ {
		req(t, "GET", f.ts.URL+"/v1/workspaces/a/envelopes", f.acme, nil)
	}
	resp, _ := http.DefaultClient.Do(func() *http.Request {
		r, _ := http.NewRequest("GET", f.ts.URL+"/v1/workspaces/a/envelopes", nil)
		r.Header.Set("Authorization", "Bearer "+f.acme)
		return r
	}())
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("acme over its rate: %d", resp.StatusCode)
	}
	if code, _ := req(t, "GET", f.ts.URL+"/v1/workspaces/a/envelopes", f.home, nil); code != 200 {
		t.Fatalf("home throttled by acme: %d", code)
	}
	m := metricsBody(t, f.ts.URL)
	for _, want := range []string{
		`hive_relay_tenant_limit_rejections_total{tenant="acme",limit="tenant_bytes"} 1`,
		`hive_relay_tenant_limit_rejections_total{tenant="acme",limit="tenant_rooms"} 1`,
		`hive_relay_tenant_limit_rejections_total{tenant="acme",limit="tenant_rate"} 1`,
		`hive_relay_tenant_bytes{tenant="acme"} 12`,
		`hive_relay_tenant_rooms{tenant="home"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s\n%s", want, m)
		}
	}
	if strings.Contains(m, "/a") || strings.Contains(m, "alice") {
		t.Fatalf("metrics carry a room id or subject:\n%s", m)
	}
}

func TestTenancyMetricsCardinalityCap(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_METRICS_MAX_TENANTS", "1")
	f := newTenancyFixture(t, newMemoryStore(), "")
	req(t, "GET", f.ts.URL+"/v1/workspaces/a/envelopes", f.acme, nil)
	req(t, "GET", f.ts.URL+"/v1/workspaces/a/envelopes", f.home, nil)
	m := metricsBody(t, f.ts.URL)
	if !strings.Contains(m, `hive_relay_tenant_requests_total{tenant="acme"} 1`) ||
		!strings.Contains(m, `hive_relay_tenant_requests_total{tenant="_other"} 1`) ||
		strings.Contains(m, `tenant="home"`) {
		t.Fatalf("label cap:\n%s", m)
	}
}

func TestTenancyTunnelHostsBoundToTenant(t *testing.T) {
	sk := randKey(t)
	acmeKey := randKey(t)
	t.Setenv("LANGSTROTH_RELAY_METRICS_TOKEN", "ops-metrics-token")
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(sk))
	t.Setenv("LANGSTROTH_RELAY_TENANCY", fmt.Sprintf(`{"tenants": [
	  {"id": "acme", "issuer_pubkeys": [%q], "limits": {"max_hosts": 1}}, {"id": "home"}]}`, pubHex(acmeKey)))
	env := newTunnelEnv(t, nil, nil, nil)
	exp := uint64(time.Now().Add(time.Hour).Unix())
	acmeReg := issueToken(acmeKey, TokenClaims{Sub: "box", Tid: "acme", Exp: exp})
	confused := issueToken(acmeKey, TokenClaims{Sub: "box", Tid: "home", Exp: exp})
	homeReg := issueToken(sk, TokenClaims{Sub: "box", Tid: "home", Exp: exp})

	register := func(h *fakeHost, reg string) (welcome bool) {
		c := env.mustDial("/v1/tunnel/host")
		h.hello(c, map[string]any{"reg": reg})
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, data, err := c.ReadMessage()
		c.Close()
		return err == nil && strings.Contains(string(data), "welcome")
	}
	h1 := newFakeHost(t, env)
	if register(h1, "") || register(h1, confused) {
		t.Fatal("a host registered without a valid tenant token")
	}
	if !register(h1, acmeReg) {
		t.Fatal("acme host refused")
	}
	rec, _ := env.hub.store.TunnelHost(t.Context(), h1.id)
	if rec == nil || rec.Tenant != "acme" {
		t.Fatalf("host record: %+v", rec)
	}
	// The binding never moves: reconnecting with home's token keeps acme.
	register(h1, homeReg)
	if rec, _ := env.hub.store.TunnelHost(t.Context(), h1.id); rec.Tenant != "acme" {
		t.Fatalf("host moved to %q", rec.Tenant)
	}
	// acme's max_hosts is 1; home's isn't limited.
	if register(newFakeHost(t, env), acmeReg) {
		t.Fatal("acme registered past max_hosts")
	}
	if !register(newFakeHost(t, env), homeReg) {
		t.Fatal("home host refused")
	}
}

func TestTenancyPushPerDayPerTenant(t *testing.T) {
	h := &tunnelHub{now: time.Now, tenantPushDay: map[string]*dayCount{}}
	h.tenancy = &tenancyConf{tenants: map[string]*tenantConf{
		"acme": {id: "acme", limits: TenantLimits{PushPerDay: 2}},
		"home": {id: "home"},
	}}
	for i := 0; i < 2; i++ {
		if !h.tenantPushAllow("acme") {
			t.Fatal("under the limit")
		}
	}
	if h.tenantPushAllow("acme") {
		t.Fatal("acme pushed past push_per_day")
	}
	for i := 0; i < 10; i++ {
		if !h.tenantPushAllow("home") {
			t.Fatal("home limited by acme")
		}
	}
}

func TestTenancyConfigRefusals(t *testing.T) {
	k1, k2 := randKey(t), randKey(t)
	shared := []ed25519.PublicKey{k2.Public().(ed25519.PublicKey)}
	bad := map[string]string{
		"unknown field":       `{"tenants":[{"id":"a","issuer_pubkeys":["` + pubHex(k1) + `"],"color":"red"}]}`,
		"no tenants":          `{"tenants":[]}`,
		"bad id":              `{"tenants":[{"id":"A/b","issuer_pubkeys":["` + pubHex(k1) + `"]}]}`,
		"duplicate id":        `{"tenants":[{"id":"a"},{"id":"a"}]}`,
		"shared key reused":   `{"tenants":[{"id":"a","issuer_pubkeys":["` + pubHex(k2) + `"]}]}`,
		"key for two tenants": `{"tenants":[{"id":"a","issuer_pubkeys":["` + pubHex(k1) + `"]},{"id":"b","issuer_pubkeys":["` + pubHex(k1) + `"]}]}`,
		"no issuer":           `{"tenants":[{"id":"a","shared_issuer":false}]}`,
		"bad admin hash":      `{"tenants":[{"id":"a","admin_token_sha256":"xyz"}]}`,
		"negative limit":      `{"defaults":{"max_bytes":-1},"tenants":[{"id":"a"}]}`,
		"not json":            `tenants: a`,
	}
	for name, cfg := range bad {
		if _, err := parseTenancy([]byte(cfg), shared); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseTenancy([]byte(`{"tenants":[{"id":"a"}]}`), nil); err == nil {
		t.Error("a tenant with no issuer key and no shared key was accepted")
	}
	// Startup conflicts.
	t.Setenv("LANGSTROTH_RELAY_METRICS_TOKEN", "ops-metrics-token")
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(k2))
	t.Setenv("LANGSTROTH_RELAY_TENANCY", `{"tenants":[{"id":"a"}]}`)
	if err := tenancyConfigError(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	t.Setenv("LANGSTROTH_RELAY_ACCESS_TOKENS", "tok")
	if tenancyConfigError() == nil {
		t.Error("tenancy with a static allowlist was accepted")
	}
	t.Setenv("LANGSTROTH_RELAY_ACCESS_TOKENS", "")
	t.Setenv("LANGSTROTH_RELAY_TENANTS", "a")
	if tenancyConfigError() == nil {
		t.Error("tenancy with LANGSTROTH_RELAY_TENANTS was accepted")
	}
	t.Setenv("LANGSTROTH_RELAY_TENANTS", "")
	os.Unsetenv("LANGSTROTH_RELAY_TENANTS")
	t.Setenv("LANGSTROTH_RELAY_GITHUB_ROUTES", "on")
	if tenancyConfigError() == nil {
		t.Error("tenancy with the GitHub routes was accepted")
	}
	// A refused config at New denies everything rather than opening up.
	t.Setenv("LANGSTROTH_RELAY_GITHUB_ROUTES", "")
	t.Setenv("LANGSTROTH_RELAY_TENANCY", `{"tenants":[]}`)
	srv := New(Options{Store: newMemoryStore()})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("broken tenancy config served an open relay: %d", code)
	}
}

// Without tenancy the tenant routes don't exist and room keys are the ids.
func TestTenancyOffByDefault(t *testing.T) {
	ts := limitServer(t, nil)
	if code, _ := req(t, "GET", ts.URL+"/v1/tenant", "", nil); code != 404 {
		t.Fatalf("/v1/tenant without tenancy: %d", code)
	}
	if tc, err := tenancyFromEnv(); tc != nil || err != nil {
		t.Fatalf("tenancy on by default: %v %v", tc, err)
	}
}
