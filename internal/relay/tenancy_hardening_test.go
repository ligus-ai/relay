package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Adversarial review of tenancy and community limits (prove, then fix).

// F3: /metrics is public when LANGSTROTH_RELAY_METRICS_TOKEN is unset, and
// with tenancy it lists every tenant's id, request volume, rooms and bytes:
// one tenant (or anyone) learns who else shares the relay and how much they
// use it.
func TestTenancyMetricsNeedAToken(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_METRICS_TOKEN", "")
	f := newTenancyFixtureNoCheck(t, newMemoryStore(), "")
	if err := tenancyConfigError(); err == nil || !strings.Contains(err.Error(), "LANGSTROTH_RELAY_METRICS_TOKEN") {
		t.Fatalf("tenancy started without a metrics token: %v", err)
	}
	// A library caller that skips the startup check still gets no tenant
	// series on an open /metrics.
	req(t, "POST", f.ts.URL+"/v1/workspaces/w/envelopes", f.acme, 1)
	m := metricsBody(t, f.ts.URL)
	if strings.Contains(m, `tenant="acme"`) || strings.Contains(m, "hive_relay_tenant_") {
		t.Fatalf("open /metrics names tenants:\n%s", m)
	}
}

// barrierHosts holds every TunnelHostsOfTenant caller until n have arrived,
// so concurrent registrations all read the count before any writes.
type barrierHosts struct {
	TunnelStore
	n       int
	arrived chan struct{}
	release chan struct{}
}

func (b *barrierHosts) TunnelHostsOfTenant(ctx context.Context, tenant string) (int64, error) {
	n, err := b.TunnelStore.(tenantHostCounter).TunnelHostsOfTenant(ctx, tenant)
	b.arrived <- struct{}{}
	select {
	case <-b.release:
	case <-time.After(300 * time.Millisecond): // a serialized caller arrives alone
	}
	return n, err
}

// F4: max_hosts is a count-then-insert: hosts registering at the same time
// all see the count below the cap and all register.
func TestTenancyMaxHostsRace(t *testing.T) {
	acmeKey := randKey(t)
	t.Setenv("LANGSTROTH_RELAY_METRICS_TOKEN", "ops-metrics-token")
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", "")
	t.Setenv("LANGSTROTH_RELAY_TENANCY", fmt.Sprintf(`{"tenants": [{"id": "acme", "issuer_pubkeys": [%q], "limits": {"max_hosts": 1}}]}`, pubHex(acmeKey)))
	env := newTunnelEnv(t, nil, nil, nil)
	const n = 4
	b := &barrierHosts{TunnelStore: env.hub.store, n: n, arrived: make(chan struct{}, n), release: make(chan struct{})}
	env.hub.store = b
	go func() {
		for i := 0; i < n; i++ {
			<-b.arrived
		}
		close(b.release)
	}()
	reg := issueToken(acmeKey, TokenClaims{Sub: "box", Tid: "acme", Exp: uint64(time.Now().Add(time.Hour).Unix())})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, sk, _ := ed25519.GenerateKey(rand.Reader)
			pub := sk.Public().(ed25519.PublicKey)
			id := TunnelHostID(pub)
			nonce := []byte("0123456789abcdef0123456789abcdef")
			v := tunnelVersion
			m := &relayMsg{T: "hello", V: &v, HostID: id, HostPub: b64u(pub), Reg: reg,
				Sig: b64u(ed25519.Sign(sk, tunnelCtx("host-auth", []byte(id), nonce)))}
			_, _ = env.hub.admitHost(t.Context(), m, nonce)
		}()
	}
	wg.Wait()
	got, _ := b.TunnelStore.(tenantHostCounter).TunnelHostsOfTenant(t.Context(), "acme")
	if got > 1 {
		t.Fatalf("max_hosts 1, but %d hosts registered concurrently", got)
	}
}

// F5: the memory store created a room on a presence or candidate write
// without a last-write time (0), so the next hourly retention pass expired a
// room created a minute earlier (Postgres stamps it with the creation time).
func TestDeviceBlobRoomNotExpiredAtOnce(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		if err := s.PutPresence(qctx(writeQuota{}), "fresh", "d1", raw(`{"online":true}`)); err != nil {
			t.Fatal(err)
		}
		n, err := s.(roomStore).PruneIdleRooms(bg, time.Now().Add(-24*time.Hour).Unix())
		if err != nil || n != 0 {
			t.Fatalf("retention expired %d rooms written just now (err %v)", n, err)
		}
		if m, _ := s.PresenceBlobs(bg, "fresh"); len(m) != 1 {
			t.Fatalf("presence of a fresh room wiped: %v", m)
		}
	})
}

// F6: the memory store kept every expired room's struct forever, even one
// that never held an envelope (no sequence to keep) and has no roster, so
// creating and abandoning rooms grew the heap and the byte budget without
// bound. Such a room is now dropped whole when it expires or is purged.
func TestExpiredEmptyRoomFreesMemory(t *testing.T) {
	s := newMemoryStore()
	for i := 0; i < 100; i++ {
		room := fmt.Sprintf("spray-%d", i)
		if err := s.PutPresence(qctx(writeQuota{}), room, "d", raw(`1`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AppendEnvelope(qctx(writeQuota{}), "kept", raw(`1`), ""); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PruneIdleRooms(bg, time.Now().Add(time.Hour).Unix()); err != nil || n != 101 {
		t.Fatalf("expired %d (%v)", n, err)
	}
	s.mu.RLock()
	left, budget := len(s.workspaces), s.storeBytes
	s.mu.RUnlock()
	if left != 1 {
		t.Fatalf("%d expired room structs kept; only the one with a sequence should stay", left)
	}
	if want := int64(wsOverheadBytes + len("kept")); budget != want {
		t.Fatalf("store budget %d after expiry, want %d", budget, want)
	}
	// The kept room continues its sequence.
	if seq, _ := s.AppendEnvelope(qctx(writeQuota{}), "kept", raw(`2`), ""); seq != 2 {
		t.Fatalf("seq %d", seq)
	}
	// Purging a room without a sequence drops it too.
	_ = s.PutPresence(qctx(writeQuota{}), "p", "d", raw(`1`))
	if _, err := s.PurgeRoom(bg, "p"); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	_, still := s.workspaces["p"]
	s.mu.RUnlock()
	if still {
		t.Fatal("a purged room with no sequence stayed in memory")
	}
}

// F7: Postgres PurgeRoom deleted the room's envelopes before taking the
// room's row lock, so an append in flight (its row update done, its envelope
// not yet committed) survived the purge while its relay_rooms row was
// deleted: stored bytes nobody counts, so the room and tenant quotas and
// retention stop seeing them.
func TestPG_PurgeRacingAppendStaysConsistent(t *testing.T) {
	s := pgStore(t)
	ctx := qctx(writeQuota{Tenant: "acme"})
	if _, err := s.AppendEnvelope(ctx, "acme/r", raw(`"first"`), ""); err != nil {
		t.Fatal(err)
	}
	// An append in flight: accounted and inserted, not committed.
	tx, err := s.pool.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(bg) }()
	seq, err := s.nextSeqTx(ctx, tx, "ws:acme/r")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.touchRoomTx(ctx, tx, "acme/r", 8, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(bg, `INSERT INTO relay_envelopes (workspace, seq, body, created_at) VALUES ('acme/r', $1, '"second"', 1)`, seq); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.PurgeRoom(bg, "acme/r"); done <- err }()
	time.Sleep(300 * time.Millisecond) // the purge reaches the row lock
	if err := tx.Commit(bg); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var stored, counted int64
	if err := s.pool.QueryRow(bg, `SELECT count(*) FROM relay_envelopes WHERE workspace = 'acme/r'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	_ = s.pool.QueryRow(bg, `SELECT envelopes FROM relay_rooms WHERE workspace = 'acme/r'`).Scan(&counted)
	if stored != counted {
		t.Fatalf("after a purge raced an append: %d envelopes stored, %d counted", stored, counted)
	}
	if b, r, _ := s.TenantUsage(bg, "acme"); stored == 0 && (b != 0 || r != 0) {
		t.Fatalf("tenant usage after purge: %d bytes %d rooms", b, r)
	}
}

// F8: LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT keys on the address (IPv6 /64)
// when there is no token subject, so a client rotating addresses creates
// rooms without bound; the byte caps don't count rooms with no envelopes
// (presence only), and on Postgres nothing bounded the room count.
// LANGSTROTH_RELAY_MAX_ROOMS is a relay-wide room cap.
func TestRoomCapSurvivesAddressRotation(t *testing.T) {
	ts := limitServer(t, map[string]string{
		"LANGSTROTH_RELAY_TRUSTED_PROXIES":      "127.0.0.1",
		"LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT": "1",
		"LANGSTROTH_RELAY_MAX_ROOMS":            "3",
	})
	created := 0
	for i := 0; i < 6; i++ {
		ip := fmt.Sprintf("2001:db8:%x::1", i+1) // a fresh /64 each time
		resp, b := send(t, "POST", ts.URL+fmt.Sprintf("/v1/workspaces/r%d/presence", i), ip, map[string]any{"device_id": "d", "data": 1})
		switch resp.StatusCode {
		case 200:
			created++
		case http.StatusInsufficientStorage:
			wantRefusal(t, resp, b, http.StatusInsufficientStorage, "total_rooms")
		default:
			t.Fatalf("room %d: %d %s", i, resp.StatusCode, b)
		}
	}
	if created != 3 {
		t.Fatalf("%d rooms created from rotating addresses past a relay cap of 3", created)
	}
}

func TestRelayRoomCapStore(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		q := qctx(writeQuota{TotalMaxRooms: 2})
		for i := 0; i < 2; i++ {
			if err := s.PutPresence(q, fmt.Sprintf("room-%d", i), "d", raw(`1`)); err != nil {
				t.Fatal(err)
			}
		}
		wantQuota(t, s.PutPresence(q, "room-2", "d", raw(`1`)), limTotalRooms)
		// Existing rooms keep working.
		if _, err := s.AppendEnvelope(q, "room-0", raw(`1`), ""); err != nil {
			t.Fatal(err)
		}
	})
}

type countingRooms struct {
	*memoryStore
	calls atomic.Int64
}

func (c *countingRooms) RoomTotals(ctx context.Context) (int64, int64, error) {
	c.calls.Add(1)
	return c.memoryStore.RoomTotals(ctx)
}

// F10: every /metrics scrape ran the room totals (on Postgres a count and sum
// over every row of relay_rooms), and /metrics is open without a metrics
// token and exempt from the per-client rate, so anyone could make the relay
// scan the table in a loop.
func TestMetricsRoomTotalsCached(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_METRICS_TOKEN", "")
	st := &countingRooms{memoryStore: newMemoryStore()}
	srv := New(Options{Store: st, Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for i := 0; i < 20; i++ {
		if !strings.Contains(metricsBody(t, ts.URL), "hive_relay_rooms 0") {
			t.Fatal("no room gauge")
		}
	}
	if n := st.calls.Load(); n > 1 {
		t.Fatalf("20 scrapes ran the room totals %d times", n)
	}
}

// Regression sweep (held): ids that look like another tenant's key stay in
// the caller's namespace; a tenant admin only reaches its own rooms; a token
// without tid is refused on every route family; a pre-tenancy room is hidden.
func TestTenancyNamespaceEscapes(t *testing.T) {
	st := newMemoryStore()
	if _, err := st.AppendEnvelope(bg, "team", raw(`"pre-tenancy"`), ""); err != nil {
		t.Fatal(err)
	}
	f := newTenancyFixture(t, st, "")
	if code, _ := req(t, "POST", f.ts.URL+"/v1/workspaces/team/envelopes", f.home, "home-secret"); code != 200 {
		t.Fatal(code)
	}
	if rows := f.envelopes(t, f.acme, "team"); len(rows) != 0 {
		t.Fatalf("acme sees another namespace's room: %+v", rows)
	}
	// acme names home's storage key through an encoded slash, a dot segment
	// and a unicode lookalike: each lands under acme/.
	for _, id := range []string{"home%2Fteam", "..%2Fhome%2Fteam", "home%E2%88%95team", "%2Fhome%2Fteam"} {
		code, b := req(t, "GET", f.ts.URL+"/v1/workspaces/"+id+"/envelopes", f.acme, nil)
		if code == 200 && strings.Contains(string(b), "secret") {
			t.Fatalf("%s reached home's room: %s", id, b)
		}
		req(t, "POST", f.ts.URL+"/v1/workspaces/"+id+"/envelopes", f.acme, "acme-write")
	}
	if rows := f.envelopes(t, f.home, "team"); len(rows) != 1 || string(rows[0].Body) != `"home-secret"` {
		t.Fatalf("home's room changed: %+v", rows)
	}
	st.mu.RLock()
	for id, w := range st.workspaces {
		if w.live && w.tenant == "acme" && !strings.HasPrefix(id, "acme/") {
			t.Errorf("acme wrote outside its prefix: %q", id)
		}
	}
	if len(st.workspaces["team"].envelopes) != 1 {
		t.Error("the pre-tenancy room changed")
	}
	st.mu.RUnlock()
	// acme's admin purging "../home/team" or "home%2Fteam" never touches home.
	for _, id := range []string{"home%2Fteam", "..%2Fhome%2Fteam"} {
		r, _ := http.NewRequest("DELETE", f.ts.URL+"/v1/tenant/rooms/"+id, nil)
		r.Header.Set("Authorization", "Bearer "+f.acmeAdmin)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if rows := f.envelopes(t, f.home, "team"); len(rows) != 1 {
		t.Fatal("acme's admin purged home's room")
	}
	// No tid: refused everywhere the gate or the tenant admin guards.
	noTid := f.tok(f.shared, TokenClaims{Sub: "alice", Caps: []string{tenantAdminCap}})
	cid := strings.Repeat("A", 22)
	for _, rt := range [][2]string{
		{"GET", "/v1/workspaces/w/presence"}, {"POST", "/v1/workspaces/w/keyring"},
		{"GET", "/v1/workspaces/w/members"}, {"POST", "/v1/pair"}, {"GET", "/v1/pair/ABCDEF"},
		{"GET", "/v1/contacts/" + cid}, {"GET", "/v1/tenant"}, {"GET", "/v1/tenant/rooms"},
	} {
		if code, b := req(t, rt[0], f.ts.URL+rt[1], noTid, map[string]any{}); code != http.StatusUnauthorized {
			t.Errorf("%s %s without tid: %d %s", rt[0], rt[1], code, b)
		}
	}
}

// Held: pods migrating at once run the rooms backfill exactly once (the
// migration runs under pg_advisory_xact_lock and records itself), and the
// backfill counts a keyring-only room.
func TestPG_ConcurrentMigrateBackfillsOnce(t *testing.T) {
	s := pgStore(t)
	if _, err := s.pool.Exec(bg, `INSERT INTO relay_envelopes (workspace, seq, body, created_at) VALUES ('old', 1, '"abc"', 100), ('old', 2, '"de"', NULL);
		INSERT INTO relay_keyring (workspace, blob) VALUES ('keys-only', '{"k":1}');
		DELETE FROM relay_rooms; DELETE FROM relay_migrations WHERE name = 'rooms_backfill_v1'`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.migrate(bg) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var b, n, lw int64
	if err := s.pool.QueryRow(bg, `SELECT bytes, envelopes, last_write FROM relay_rooms WHERE workspace = 'old'`).Scan(&b, &n, &lw); err != nil || b != 9 || n != 2 || lw != 100 {
		t.Fatalf("old: %d bytes %d envelopes last_write %d (%v)", b, n, lw, err)
	}
	if err := s.pool.QueryRow(bg, `SELECT bytes, envelopes FROM relay_rooms WHERE workspace = 'keys-only'`).Scan(&b, &n); err != nil || b != 7 || n != 0 {
		t.Fatalf("keys-only: %d bytes %d envelopes (%v)", b, n, err)
	}
}
