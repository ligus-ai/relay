package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Community limits (docs/tenancy.md): per-room, per-client, total and tenant
// quotas on both stores; idle-room retention never touches a room in use.

// roomStores runs fn against the memory store and, with TEST_DATABASE_URL,
// Postgres.
func roomStores(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Run("memory", func(t *testing.T) { fn(t, newMemoryStore()) })
	t.Run("postgres", func(t *testing.T) {
		if os.Getenv("TEST_DATABASE_URL") == "" {
			t.Skip("set TEST_DATABASE_URL to run Postgres integration tests")
		}
		fn(t, pgStore(t))
	})
}

func qctx(q writeQuota) context.Context { return withQuota(context.Background(), &q) }

func wantQuota(t *testing.T, err error, limit string) {
	t.Helper()
	var qe *quotaError
	if !errors.As(err, &qe) || qe.limit != limit {
		t.Fatalf("want quota %s, got %v", limit, err)
	}
}

func TestRoomByteQuota(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		ctx := qctx(writeQuota{RoomMaxBytes: 100})
		if _, err := s.AppendEnvelope(ctx, "r", raw(`"`+strings.Repeat("a", 58)+`"`), "k1"); err != nil { // 60 bytes
			t.Fatal(err)
		}
		_, err := s.AppendEnvelope(ctx, "r", raw(`"`+strings.Repeat("b", 48)+`"`), "k2") // 50: over
		wantQuota(t, err, limRoomBytes)
		if !errors.Is(err, ErrStoreFull) {
			t.Fatal("a room byte quota must map to 507 (ErrStoreFull)")
		}
		// A re-push of a stored envelope still answers its seq when full.
		if seq, err := s.AppendEnvelope(ctx, "r", raw(`"x"`), "k1"); err != nil || seq != 1 {
			t.Fatalf("idempotent re-push on a full room: seq %d err %v", seq, err)
		}
		if _, err := s.AppendEnvelope(ctx, "r", raw(`"`+strings.Repeat("c", 38)+`"`), "k3"); err != nil { // 40: exactly 100
			t.Fatal(err)
		}
		// Key rotations count toward the same quota.
		wantQuota(t, s.AppendKeyRotation(ctx, "r", raw(`{}`)), limRoomBytes)
		// Other rooms are unaffected, and the refused writes left nothing.
		if _, err := s.AppendEnvelope(ctx, "other", raw(`"y"`), ""); err != nil {
			t.Fatal(err)
		}
		rows, _ := s.EnvelopesAfter(context.Background(), "r", 0)
		if len(rows) != 2 || rows[1].Seq != 2 {
			t.Fatalf("a refused append must not consume a seq or store a row: %+v", rows)
		}
		// Without a quota in the context (direct callers) nothing is refused.
		if _, err := s.AppendEnvelope(context.Background(), "r", raw(`"`+strings.Repeat("d", 200)+`"`), ""); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRoomEnvelopeQuota(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		ctx := qctx(writeQuota{RoomMaxEnvelopes: 2})
		for i := 0; i < 2; i++ {
			if _, err := s.AppendEnvelope(ctx, "r", raw(`{}`), ""); err != nil {
				t.Fatal(err)
			}
		}
		_, err := s.AppendEnvelope(ctx, "r", raw(`{}`), "")
		wantQuota(t, err, limRoomEnvelopes)
		// Key rotations aren't envelopes.
		if err := s.AppendKeyRotation(ctx, "r", raw(`{}`)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestTotalRoomByteQuota(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		ctx := qctx(writeQuota{TotalMaxBytes: 10})
		if _, err := s.AppendEnvelope(ctx, "a", raw(`"123"`), ""); err != nil { // 5
			t.Fatal(err)
		}
		if _, err := s.AppendEnvelope(ctx, "b", raw(`"123"`), ""); err != nil { // 10
			t.Fatal(err)
		}
		_, err := s.AppendEnvelope(ctx, "c", raw(`1`), "")
		wantQuota(t, err, limTotalBytes)
	})
}

func TestClientRoomLimit(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		alice := qctx(writeQuota{Creator: roomCreatorTag("ip:203.0.113.1"), CreatorMaxRooms: 2})
		bob := qctx(writeQuota{Creator: roomCreatorTag("ip:203.0.113.2"), CreatorMaxRooms: 2})
		if _, err := s.AppendEnvelope(alice, "r1", raw(`{}`), ""); err != nil {
			t.Fatal(err)
		}
		// Any first write creates a room, presence included.
		if err := s.PutPresence(alice, "r2", "dev", raw(`{}`)); err != nil {
			t.Fatal(err)
		}
		_, err := s.AppendEnvelope(alice, "r3", raw(`{}`), "")
		wantQuota(t, err, limClientRooms)
		if errors.Is(err, ErrStoreFull) {
			t.Fatal("a client room limit is a 429, not a 507")
		}
		if err := s.PutCandidate(alice, "r3", "dev", raw(`{}`)); err == nil {
			t.Fatal("a candidate write must not create a room past the limit either")
		}
		// Writing to rooms that exist is fine, and so is another client.
		if _, err := s.AppendEnvelope(alice, "r1", raw(`{}`), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AppendEnvelope(bob, "r3", raw(`{}`), ""); err != nil {
			t.Fatal(err)
		}
		// alice may write to bob's room: it isn't hers to count.
		if _, err := s.AppendEnvelope(alice, "r3", raw(`{}`), ""); err != nil {
			t.Fatal(err)
		}
		// A purged room stops counting.
		if _, err := s.(roomStore).PurgeRoom(context.Background(), "r1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AppendEnvelope(alice, "r4", raw(`{}`), ""); err != nil {
			t.Fatalf("after a purge: %v", err)
		}
	})
}

func TestTenantQuotaStore(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		acme := qctx(writeQuota{Tenant: "acme", TenantMaxBytes: 8, TenantMaxRooms: 2})
		home := qctx(writeQuota{Tenant: "home", TenantMaxBytes: 8, TenantMaxRooms: 2})
		if _, err := s.AppendEnvelope(acme, "acme/a", raw(`"12"`), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AppendEnvelope(acme, "acme/b", raw(`"12"`), ""); err != nil {
			t.Fatal(err)
		}
		wantQuota(t, s.PutPresence(acme, "acme/c", "dev", raw(`1`)), limTenantRooms)
		_, err := s.AppendEnvelope(acme, "acme/a", raw(`"1"`), "") // 8 + 3 > 8
		wantQuota(t, err, limTenantBytes)
		// One tenant's usage never limits another.
		if _, err := s.AppendEnvelope(home, "home/a", raw(`"1234"`), ""); err != nil {
			t.Fatal(err)
		}
		rs := s.(roomStore)
		if b, r, _ := rs.TenantUsage(context.Background(), "acme"); b != 8 || r != 2 {
			t.Fatalf("acme usage: %d bytes %d rooms", b, r)
		}
		if b, r, _ := rs.TenantUsage(context.Background(), "home"); b != 6 || r != 1 {
			t.Fatalf("home usage: %d bytes %d rooms", b, r)
		}
		rooms, _ := rs.ListRooms(context.Background(), "acme", "", 10)
		if len(rooms) != 2 || rooms[0].Room != "acme/a" || rooms[1].Room != "acme/b" {
			t.Fatalf("acme rooms: %+v", rooms)
		}
	})
}

// setIdle backdates a room's last write.
func setIdle(t *testing.T, s Store, room string, at int64) {
	t.Helper()
	switch st := s.(type) {
	case *memoryStore:
		st.mu.Lock()
		st.workspaces[room].lastWrite = at
		for i := range st.workspaces[room].envAt {
			st.workspaces[room].envAt[i] = at
		}
		st.mu.Unlock()
	case *postgresStore:
		if _, err := st.pool.Exec(bg, `UPDATE relay_rooms SET last_write = $2 WHERE workspace = $1`, room, at); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(bg, `UPDATE relay_envelopes SET created_at = $2 WHERE workspace = $1`, room, at); err != nil {
			t.Fatal(err)
		}
	}
}

// Retention deletes whole idle rooms only. A room in use keeps every
// envelope however old, its founder seed (seq 1) and its keyring; an expired
// room keeps its sequence and roster, so returning devices' cursors stay
// valid and the room can't be claimed by someone else.
func TestIdleRoomRetentionKeepsWhatClientsNeed(t *testing.T) {
	roomStores(t, func(t *testing.T, s Store) {
		ctx := qctx(writeQuota{Creator: roomCreatorTag("ip:198.51.100.7"), CreatorMaxRooms: 2})
		old := time.Now().Add(-90 * 24 * time.Hour).Unix()
		for _, room := range []string{"active", "idle"} {
			for i := 0; i < 3; i++ {
				if _, err := s.AppendEnvelope(ctx, room, raw(`{"seed":true}`), ""); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.AppendKeyRotation(ctx, room, raw(`{"epoch":1}`)); err != nil {
				t.Fatal(err)
			}
			setIdle(t, s, room, old)
		}
		if err := s.UpsertMember(context.Background(), "idle", "acct:owner", "owner", "owner", "", 1); err != nil {
			t.Fatal(err)
		}
		// The active room is written today; its old envelopes stay.
		if _, err := s.AppendEnvelope(ctx, "active", raw(`{"chat":1}`), ""); err != nil {
			t.Fatal(err)
		}
		rs := s.(roomStore)
		n, err := rs.PruneIdleRooms(context.Background(), time.Now().Add(-30*24*time.Hour).Unix())
		if err != nil || n != 1 {
			t.Fatalf("expired %d rooms, err %v; want 1", n, err)
		}
		rows, _ := s.EnvelopesAfter(context.Background(), "active", 0)
		if len(rows) != 4 || rows[0].Seq != 1 {
			t.Fatalf("an active room must keep its whole log from seq 1: %+v", rows)
		}
		if k, _ := s.KeyRotations(context.Background(), "active"); len(k) != 1 {
			t.Fatalf("an active room must keep its keyring: %d", len(k))
		}
		if rows, _ := s.EnvelopesAfter(context.Background(), "idle", 0); len(rows) != 0 {
			t.Fatalf("idle room still holds %d envelopes", len(rows))
		}
		if role, ok, _ := s.MemberRole(context.Background(), "idle", "acct:owner"); !ok || role != "owner" {
			t.Fatal("an expired room must keep its roster (else anyone could claim it)")
		}
		seq, err := s.AppendEnvelope(ctx, "idle", raw(`{}`), "")
		if err != nil || seq != 4 {
			t.Fatalf("an expired room continues its sequence: seq %d err %v", seq, err)
		}
		// The expired room stopped counting for its creator, then counted
		// again when written: active + idle = 2, so a third room is refused.
		_, err = s.AppendEnvelope(ctx, "third", raw(`{}`), "")
		wantQuota(t, err, limClientRooms)
		// A cutoff in the past expires nothing that was just written.
		if n, _ := rs.PruneIdleRooms(context.Background(), time.Now().Add(-time.Hour).Unix()); n != 0 {
			t.Fatalf("expired %d fresh rooms", n)
		}
	})
}

func TestRoomAccountingSurvivesSnapshot(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	ctx := qctx(writeQuota{Tenant: "acme", Creator: "c1", CreatorMaxRooms: 1})
	if _, err := s.AppendEnvelope(ctx, "acme/r", raw(`"abc"`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	s2 := newMemoryStoreWithPersistence(dir)
	_, err := s2.AppendEnvelope(ctx, "acme/r2", raw(`1`), "")
	wantQuota(t, err, limClientRooms)
	if b, r, _ := s2.TenantUsage(context.Background(), "acme"); b != 5 || r != 1 {
		t.Fatalf("restored acme usage: %d bytes %d rooms", b, r)
	}
}

// ── Over HTTP ────────────────────────────────────────────────────────────────

func limitServer(t *testing.T, env map[string]string) *httptest.Server {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func metricsBody(t *testing.T, url string) string {
	t.Helper()
	_, b := req(t, "GET", url+"/metrics", os.Getenv("LANGSTROTH_RELAY_METRICS_TOKEN"), nil)
	return string(b)
}

func TestHTTPRoomQuota507(t *testing.T) {
	ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_ROOM_MAX_BYTES": "16"})
	if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", "0123456789"); code != 200 {
		t.Fatalf("first push: %d", code)
	}
	code, body := req(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", "9876543210")
	if code != http.StatusInsufficientStorage || !strings.Contains(string(body), "room storage quota") {
		t.Fatalf("over the room quota: %d %s", code, body)
	}
	// The room stays readable.
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil); code != 200 {
		t.Fatalf("read a full room: %d", code)
	}
	if m := metricsBody(t, ts.URL); !strings.Contains(m, `hive_relay_limit_rejections_total{limit="room_bytes"} 1`) ||
		!strings.Contains(m, "hive_relay_rooms 1") {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestHTTPEnvelopeQuotaAndClientRooms(t *testing.T) {
	ts := limitServer(t, map[string]string{
		"LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES":   "1",
		"LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT": "2",
	})
	if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/a/envelopes", "", 1); code != 200 {
		t.Fatal(code)
	}
	if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/a/envelopes", "", 2); code != http.StatusInsufficientStorage {
		t.Fatalf("envelope quota: %d", code)
	}
	if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/b/presence", "", map[string]any{"device_id": "d", "data": 1}); code != 200 {
		t.Fatal(code)
	}
	code, body := req(t, "POST", ts.URL+"/v1/workspaces/c/envelopes", "", 1)
	if code != http.StatusTooManyRequests || !strings.Contains(string(body), "too many rooms") {
		t.Fatalf("third room from one client: %d %s", code, body)
	}
	// Reads never create a room.
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/d/envelopes", "", nil); code != 200 {
		t.Fatalf("read of a new room: %d", code)
	}
}

func TestHTTPRateLimitsSay429WithRetryAfter(t *testing.T) {
	ts := limitServer(t, map[string]string{
		"LANGSTROTH_RELAY_IP_RATE": "0.001", "LANGSTROTH_RELAY_IP_BURST": "3",
	})
	for i := 0; i < 3; i++ {
		if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil); code != 200 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	resp, err := http.Get(ts.URL + "/v1/workspaces/w/envelopes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("over the IP rate: %d Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Health and metrics stay reachable for probes and scrapers.
	if code, _ := req(t, "GET", ts.URL+"/v1/health", "", nil); code != 200 {
		t.Fatalf("health under the IP rate: %d", code)
	}
	if m := metricsBody(t, ts.URL); !strings.Contains(m, `hive_relay_limit_rejections_total{limit="ip_rate"} 1`) {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestHTTPRoomRate(t *testing.T) {
	ts := limitServer(t, map[string]string{
		"LANGSTROTH_RELAY_ROOM_RATE": "0.001", "LANGSTROTH_RELAY_ROOM_BURST": "2",
	})
	for i := 0; i < 2; i++ {
		if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/hot/envelopes", "", nil); code != 200 {
			t.Fatal(code)
		}
	}
	if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/hot/envelopes", "", 1); code != http.StatusTooManyRequests {
		t.Fatalf("hot room: %d", code)
	}
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/cold/envelopes", "", nil); code != 200 {
		t.Fatalf("another room must not share the hot room's bucket: %d", code)
	}
}

func TestLimitsOffByDefault(t *testing.T) {
	l := communityLimitsFromEnv()
	if l.roomMaxBytes != 0 || l.roomMaxEnvelopes != 0 || l.totalMaxBytes != 0 || l.maxRoomsPerClient != 0 ||
		l.roomRetention != 0 || l.ip != nil || l.room != nil {
		t.Fatalf("a limit is on by default: %+v", l)
	}
	ts := limitServer(t, nil)
	for i := 0; i < 50; i++ {
		if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/w"+string(rune('a'+i%26))+"/envelopes", "", i); code != 200 {
			t.Fatalf("push %d: %d", i, code)
		}
	}
}

func TestTunnelPushLimitsFromEnv(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_TUNNEL_PUSH_RATE", "0.5")
	t.Setenv("LANGSTROTH_RELAY_TUNNEL_PUSH_BURST", "2")
	t.Setenv("LANGSTROTH_RELAY_TUNNEL_PUSH_PER_DAY", "7")
	policy, _ := newEnvTunnelPolicy("open", "", nil)
	srv := New(Options{Store: newMemoryStore(), TunnelPolicy: policy})
	defer srv.ShutdownTunnels()
	if l := srv.tunnel.lim; l.PushRate != 0.5 || l.PushBurst != 2 || l.PushPerDay != 7 {
		t.Fatalf("push limits: %v/%v/%v", l.PushRate, l.PushBurst, l.PushPerDay)
	}
}

// The migration backfills relay_rooms once from rooms written before it
// existed, and later writes add to the backfilled counters.
func TestPG_RoomBackfillAndPruneAccounting(t *testing.T) {
	s := pgStore(t)
	if _, err := s.pool.Exec(bg, `INSERT INTO relay_envelopes (workspace, seq, body, created_at) VALUES ('legacy', 1, '"abc"', 100), ('legacy', 2, '"de"', 200)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(bg, `DELETE FROM relay_migrations WHERE name = 'rooms_backfill_v1'`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(bg); err != nil {
		t.Fatal(err)
	}
	var bytes, envs, lw int64
	if err := s.pool.QueryRow(bg, `SELECT bytes, envelopes, last_write FROM relay_rooms WHERE workspace = 'legacy'`).Scan(&bytes, &envs, &lw); err != nil {
		t.Fatal(err)
	}
	if bytes != 9 || envs != 2 || lw != 200 {
		t.Fatalf("backfill: %d bytes %d envelopes last_write %d", bytes, envs, lw)
	}
	// A second migrate doesn't backfill again (the counters would double).
	if err := s.migrate(bg); err != nil {
		t.Fatal(err)
	}
	ctx := qctx(writeQuota{Tenant: "acme"})
	for i := 0; i < 3; i++ {
		if _, err := s.AppendEnvelope(ctx, "acme/r", raw(`"1234"`), ""); err != nil { // 6 bytes each
			t.Fatal(err)
		}
	}
	if err := s.pool.QueryRow(bg, `SELECT bytes, envelopes FROM relay_rooms WHERE workspace = 'acme/r'`).Scan(&bytes, &envs); err != nil || bytes != 18 || envs != 3 {
		t.Fatalf("after appends: %d bytes %d envelopes (%v)", bytes, envs, err)
	}
	if b, _, _ := s.TenantUsage(bg, "acme"); b != 18 {
		t.Fatalf("tenant bytes: %d", b)
	}
}
