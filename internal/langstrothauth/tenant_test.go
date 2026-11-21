package langstrothauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/langstroth-ai/langstroth-relay/internal/relay"
)

const scimTokenB = "scim-token-for-tenant-b-0123456789abcdef"

// Two tenants with their own IdPs and disjoint workspaces.
func twoTenants(t *testing.T) (*harness, *mockIdP, *mockIdP) {
	clock := newClock()
	ia, ib := newMockIdP(t, clock), newMockIdP(t, clock)
	h := newHarness(t, clock,
		tenantSpec{id: "acme", idp: ia, workspaces: []string{"ws-acme"}, grants: map[string][]string{"eng": {"ws-acme"}}, scimToken: testSCIMToken, idpGroups: true},
		tenantSpec{id: "globex", idp: ib, workspaces: []string{"ws-globex"}, grants: map[string][]string{"eng": {"ws-globex"}}, scimToken: scimTokenB, idpGroups: true})
	return h, ia, ib
}

func TestTenantIsolationOfTokens(t *testing.T) {
	h, ia, ib := twoTenants(t)
	// The same person (same IdP subject string) at both IdPs, both in a
	// group called "eng". Each tenant's token carries only its own
	// workspaces.
	for _, m := range []*mockIdP{ia, ib} {
		m.set(func(m *mockIdP) { m.user.groups = []string{"eng"} })
	}
	d := newDevice("d1")
	ta := h.loginTokens("acme", d)
	tb := h.loginTokens("globex", d)
	if ta.status != 200 || tb.status != 200 {
		t.Fatalf("logins: %s / %s", fmtStatus(ta), fmtStatus(tb))
	}
	ca, _ := relay.VerifyToken(ta.Access, pub(h))
	cb, _ := relay.VerifyToken(tb.Access, pub(h))
	if strings.Join(ca.Workspaces, ",") != "ws-acme" || ca.Tid != "acme" {
		t.Fatalf("acme token: %+v", ca)
	}
	if strings.Join(cb.Workspaces, ",") != "ws-globex" || cb.Tid != "globex" {
		t.Fatalf("globex token: %+v", cb)
	}
	if ca.Sub == cb.Sub || ca.Uid == cb.Uid {
		t.Fatal("the same IdP subject in two tenants must be two users")
	}

	// acme's refresh token is invalid at globex.
	if r := h.refresh("globex", ta.Refresh, "", d); r.Error != "invalid_grant" {
		t.Fatalf("cross-tenant refresh: %s", fmtStatus(r))
	}
	// acme's code is invalid at globex.
	q, verifier := h.browserLogin("acme")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "client_id": {"ligus-desktop"}, "redirect_uri": {loopback}, "code_verifier": {verifier}}
	if r := h.redeem("globex", form, "code", d); r.Error != "invalid_grant" {
		t.Fatalf("cross-tenant code: %s", fmtStatus(r))
	}
	// And still valid at acme (the failed attempt did not consume it).
	if r := h.redeem("acme", form, "code", d); r.status != 200 {
		t.Fatalf("own-tenant code: %s", fmtStatus(r))
	}
	// A device code from acme cannot be polled at globex.
	resp, _ := http.PostForm(h.url("acme", "/device_authorization"), url.Values{"client_id": {"ligus-cli"}})
	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	decodeJSON(t, resp, &da)
	if r := h.postToken("globex", url.Values{"grant_type": {grantDevice}, "device_code": {da.DeviceCode}, "client_id": {"ligus-cli"}}); r.Error != "invalid_grant" {
		t.Fatalf("cross-tenant device code: %s", fmtStatus(r))
	}
	// Nor approved through globex's verification page.
	resp, _ = browser().PostForm(h.url("globex", "/device"), url.Values{"user_code": {da.UserCode}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("acme user code at globex: want 400, got %d", resp.StatusCode)
	}
}

// globex's IdP is malicious. It can only ever affect globex: an ID token it
// signs naming acme's issuer, or signed with acme's IdP key, is refused, and
// a groups claim naming acme's groups grants nothing outside globex.
func TestMaliciousIdPCannotMintForAnotherTenant(t *testing.T) {
	h, ia, ib := twoTenants(t)
	ia.set(func(m *mockIdP) { m.user.groups = []string{"eng"} })

	// 1. globex IdP claims to be acme's issuer.
	ib.set(func(m *mockIdP) { m.mutate = func(c map[string]any) { c["iss"] = ia.srv.URL } })
	if got := loginOutcome(t, h, "globex"); got == "" {
		t.Fatal("globex accepted a token naming acme's issuer")
	}
	// 2. globex IdP replays acme's audience.
	ib.set(func(m *mockIdP) { m.mutate = func(c map[string]any) { c["aud"] = "acme-client" } })
	if got := loginOutcome(t, h, "globex"); got == "" {
		t.Fatal("globex accepted a foreign audience")
	}
	// 3. globex IdP signs with a key acme's IdP publishes (but globex's does not).
	ib.set(func(m *mockIdP) { m.mutate = nil; m.signer = rsaMockKey("k1-acme", 2) })
	ia.set(func(m *mockIdP) { m.published = append(m.published, rsaMockKey("k1-acme", 2)) })
	if got := loginOutcome(t, h, "globex"); got == "" {
		t.Fatal("globex accepted a key from acme's JWKS")
	}
	// 4. globex IdP puts every group name it can think of in the claim.
	ib.set(func(m *mockIdP) {
		m.signer = rsaMockKey("k1", 0)
		m.user.groups = []string{"eng", "admins", "acme:eng", "*"}
	})
	d := newDevice("d1")
	tr := h.loginTokens("globex", d)
	if tr.status != 200 {
		t.Fatalf("globex login: %s", fmtStatus(tr))
	}
	c, _ := relay.VerifyToken(tr.Access, pub(h))
	for _, w := range c.Workspaces {
		if w != "ws-globex" {
			t.Fatalf("globex token reached %q", w)
		}
	}
	// 5. A login state minted for acme, delivered to globex's callback.
	cl := browser()
	q := url.Values{"response_type": {"code"}, "client_id": {"ligus-desktop"}, "redirect_uri": {loopback}, "state": {"s"},
		"code_challenge": {pkceChallenge("v")}, "code_challenge_method": {"S256"}}
	resp := mustGet(t, cl, h.url("acme", "/authorize?"+q.Encode()))
	toIdP, _ := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	resp = mustGet(t, cl, h.url("globex", "/callback?state="+url.QueryEscape(toIdP.Query().Get("state"))+"&code=x"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("acme state at globex callback: want 400, got %d", resp.StatusCode)
	}
}

func TestGrantsCannotNameAnotherTenantsWorkspace(t *testing.T) {
	h, _, _ := twoTenants(t)
	admin := httptestAdmin(t, h)
	code := adminDo(t, admin, "PUT", "/admin/v1/tenants/acme/grants/eng", map[string]any{"workspaces": []string{"ws-globex"}})
	if code != http.StatusForbidden {
		t.Fatalf("granting another tenant's workspace: want 403, got %d", code)
	}
	if code := adminDo(t, admin, "PUT", "/admin/v1/tenants/acme/grants/eng", map[string]any{"workspaces": []string{"*"}}); code != http.StatusForbidden {
		t.Fatalf("granting * in a multi-tenant deployment: want 403, got %d", code)
	}
	if code := adminDo(t, admin, "PUT", "/admin/v1/tenants/acme/grants/ops", map[string]any{"workspaces": []string{"ws-acme"}}); code != http.StatusOK {
		t.Fatalf("own workspace: %d", code)
	}
	// Even a grant row written straight into the store (bypassing the API)
	// is filtered by ownership at mint time.
	if err := h.store.SetGrant(t.Context(), "acme", "eng", []string{"ws-acme", "ws-globex", "*"}); err != nil {
		t.Fatal(err)
	}
	h.idps["acme"].set(func(m *mockIdP) { m.user.groups = []string{"eng"} })
	tr := h.loginTokens("acme", newDevice("d"))
	c, _ := relay.VerifyToken(tr.Access, pub(h))
	if strings.Join(c.Workspaces, ",") != "ws-acme" {
		t.Fatalf("mint-time ownership filter: %v", c.Workspaces)
	}
	// Admin API needs its token.
	if code := adminDoTok(t, admin, "", "GET", "/admin/v1/tenants", nil); code != http.StatusUnauthorized {
		t.Fatalf("admin without token: %d", code)
	}
}

func TestConfigRefusesOverlappingOwnership(t *testing.T) {
	base := func() *Config {
		t.Setenv("X_SECRET", "s")
		mk := func(id string, ws ...string) TenantConfig {
			return TenantConfig{ID: id, Workspaces: ws, OIDC: OIDCConfig{Issuer: "https://idp.example/" + id, ClientID: "c", ClientSecretEnv: "X_SECRET"}}
		}
		return &Config{PublicURL: "https://auth.example", Tenants: []TenantConfig{mk("a", "w1"), mk("b", "w2")}}
	}
	c := base()
	c.Tenants[1].Workspaces = []string{"w1"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "owned by both") {
		t.Fatalf("overlap: %v", err)
	}
	c = base()
	c.Tenants[0].Workspaces = []string{"*"}
	if err := c.Validate(); err == nil {
		t.Fatal("* with two tenants must be refused")
	}
	c = base()
	c.Tenants[0].Grants = map[string][]string{"g": {"w2"}}
	if err := c.Validate(); err == nil {
		t.Fatal("a seeded grant naming another tenant's workspace must be refused")
	}
	c = base()
	c.AccessTTL = Duration(2 * time.Hour)
	if err := c.Validate(); err == nil {
		t.Fatal("access_ttl above 1h must be refused")
	}
	c = base()
	c.Tenants[0].OIDC.AllowedAlgs = []string{"HS256"}
	if err := c.Validate(); err == nil {
		t.Fatal("HS256 must be refused")
	}
	c = base()
	c.Tenants[0].OIDC.Issuer = "http://idp.example"
	if err := c.Validate(); err == nil {
		t.Fatal("http issuer without allow_insecure_http must be refused")
	}
	c = base()
	c.Tenants[1].ID = "a"
	if err := c.Validate(); err == nil {
		t.Fatal("duplicate tenant id")
	}
	c = base()
	c.Tenants[0].RedirectURIs = []string{"http://evil.example/cb"}
	if err := c.Validate(); err == nil {
		t.Fatal("plain-http non-loopback redirect must be refused")
	}
	c = base()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

// ── relay interop ────────────────────────────────────────────────────────────

// Frozen vector: an hrt1 token in the exact shape langstroth-auth mints, signed by
// a fixed key. If either the issuer (langstroth-auth) or the verifier (relay)
// drifts in claim names or order, this breaks.
const frozenLigusAuthToken = "hrt1.eyJzdWIiOiJob21lOnVBQkMiLCJwbGFuIjoiIiwiZXhwIjoxOTAwMDAwOTAwLCJtYXhfbWVtYmVycyI6bnVsbCwicmV0ZW50aW9uX2RheXMiOm51bGwsInR1cm4iOmZhbHNlLCJjYXBzIjpbXSwid29ya3NwYWNlcyI6WyJ3cy1ob21lIl0sInRpZCI6ImhvbWUiLCJ1aWQiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImRpZCI6ImRldi0xIn0.PwAWGJ7vHsSCXv50QqOB94xmNsPgfYf1eedBZO190tjVWzZrFPftGTB2nhJhLRLAl16PVjRQGj1OwT4eOR1iDQ"

func frozenClaims() relay.TokenClaims {
	return relay.TokenClaims{Sub: "home:uABC", Exp: 1900000900, Caps: []string{}, Workspaces: []string{"ws-home"}, Tid: "home", Uid: "0123456789abcdef0123456789abcdef", Did: "dev-1"}
}

func TestMintedTokenVerifiesOnRelay(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	tok := relay.IssueToken(key, frozenClaims())
	if tok != frozenLigusAuthToken {
		t.Fatalf("hrt1 bytes drifted:\n got %s\nwant %s", tok, frozenLigusAuthToken)
	}
	// The relay verifier accepts the frozen bytes as-is.
	c, ok := relay.VerifyToken(frozenLigusAuthToken, key.Public().(ed25519.PublicKey))
	if !ok {
		t.Fatal("relay verifier rejects the langstroth-auth token")
	}
	b1, _ := json.Marshal(c)
	b2, _ := json.Marshal(frozenClaims())
	if !bytes.Equal(b1, b2) {
		t.Fatalf("round trip: %s vs %s", b1, b2)
	}
}

// End to end against a real relay in strict scope mode: the minted token
// reaches its workspace and nothing else; with LANGSTROTH_RELAY_TENANTS the relay
// also refuses another tenant's tokens.
func TestWorkspacesClaimScopesStrict(t *testing.T) {
	h, ia, ib := twoTenants(t)
	ia.set(func(m *mockIdP) { m.user.groups = []string{"eng"} })
	ib.set(func(m *mockIdP) { m.user.groups = []string{"eng"} })
	d := newDevice("d1")
	ta := h.loginTokens("acme", d)
	tb := h.loginTokens("globex", d)

	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", h.srv.PublicKeyHex())
	t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", "strict")
	t.Setenv("LANGSTROTH_RELAY_TENANTS", "acme")
	rs := relay.New(relay.Options{Store: relay.NewMemoryStore(), Entitlement: relay.EntitlementFromEnv()})
	relaySrv := httptestServer(t, rs.Handler())

	get := func(tok, ws string) int {
		req, _ := http.NewRequest("GET", relaySrv+"/v1/workspaces/"+ws+"/envelopes", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := get(ta.Access, "ws-acme"); c != http.StatusOK {
		t.Fatalf("acme token on its workspace: %d", c)
	}
	if c := get(ta.Access, "ws-globex"); c != http.StatusForbidden {
		t.Fatalf("acme token on globex workspace: %d", c)
	}
	if c := get(ta.Access, "ws-other"); c != http.StatusForbidden {
		t.Fatalf("acme token on an unlisted workspace: %d", c)
	}
	if c := get(tb.Access, "ws-globex"); c != http.StatusUnauthorized {
		t.Fatalf("globex token on an acme-only relay: %d", c)
	}
	// Expiry is enforced by the relay too.
	h.clock.Advance(time.Hour)
	ca, _ := relay.VerifyToken(ta.Access, pub(h))
	if !ca.IsExpired(h.clock.Now().Unix()) {
		t.Fatal("token must be expired an hour later")
	}
}

// TestIdPCannotGrantMembership (relay side): a token with workspaces:[W]
// reaches W on the relay (transport), but nothing langstroth-auth does adds a
// roster entry: the relay's membership roster for W stays empty, and the
// langstroth-auth API has no route that writes one. Refusal of the posted events
// by the workspace's signed-roster authz is proven in the Ligus client tests
// (crates/ligus-runtime/tests/ligus_auth_membership.rs).
func TestIdPCannotGrantMembership(t *testing.T) {
	h, _ := homeHarness(t)
	d := newDevice("d1")
	h.loginTokens("home", d)
	grantJIT(t, h, "home")
	tr := h.loginTokens("home", d)

	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", h.srv.PublicKeyHex())
	t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", "strict")
	rs := relay.New(relay.Options{Store: relay.NewMemoryStore(), Entitlement: relay.EntitlementFromEnv()})
	base := httptestServer(t, rs.Handler())
	// Transport: the token reaches W (reads and writes are forwarded).
	push, _ := http.NewRequest("POST", base+"/v1/workspaces/ws-home/envelopes", strings.NewReader(`{"opaque":"sealed"}`))
	push.Header.Set("Authorization", "Bearer "+tr.Access)
	push.Header.Set("Content-Type", "application/json")
	presp, err := http.DefaultClient.Do(push)
	if err != nil {
		t.Fatal(err)
	}
	presp.Body.Close()
	if presp.StatusCode != http.StatusOK {
		t.Fatalf("transport access to W: %d", presp.StatusCode)
	}
	rs2 := relay.New(relay.Options{Store: relay.NewMemoryStore(), Entitlement: relay.EntitlementFromEnv(), Membership: true})
	base = httptestServer(t, rs2.Handler())
	req, _ := http.NewRequest("GET", base+"/v1/workspaces/ws-home/members", nil)
	req.Header.Set("Authorization", "Bearer "+tr.Access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var members []map[string]any
	json.NewDecoder(resp.Body).Decode(&members)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(members) != 0 {
		t.Fatalf("langstroth-auth sign-in must not create roster entries: %v", members)
	}
	// No langstroth-auth route mentions members or rosters.
	for _, p := range []string{"/members", "/roster", "/workspaces/ws-home/members"} {
		resp, _ := http.Post(h.url("home", p), "application/json", strings.NewReader("{}"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("unexpected route %s: %d", p, resp.StatusCode)
		}
	}
}
