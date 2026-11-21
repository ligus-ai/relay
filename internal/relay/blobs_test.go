package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Blob channel (blobs.go, docs/blobs.md). Every test runs against the memory
// store and, with TEST_DATABASE_URL, Postgres.

func blobStores(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Run("memory", func(t *testing.T) { fn(t, newMemoryStore()) })
	t.Run("postgres", func(t *testing.T) {
		if os.Getenv("TEST_DATABASE_URL") == "" {
			t.Skip("set TEST_DATABASE_URL to run Postgres integration tests")
		}
		fn(t, pgStore(t))
	})
}

func seedRoom(t *testing.T, s Store, room string) {
	t.Helper()
	if _, err := s.AppendEnvelope(bg, room, raw(`{"ct":"seed"}`), ""); err != nil {
		t.Fatal(err)
	}
}

func testBlob(room, uploader string, size int) (BlobMeta, []byte) {
	data := bytes.Repeat([]byte{0xA5}, size)
	sum := sha256.Sum256(data)
	return BlobMeta{Room: room, ID: newBlobID(), Uploader: blobUploaderTag(uploader), Size: int64(size),
		SHA256: hex.EncodeToString(sum[:]), CreatedAt: time.Now().Unix()}, data
}

func putTestBlob(s Store, room, uploader string, size int, q blobQuota) (BlobMeta, error) {
	m, d := testBlob(room, uploader, size)
	return m, s.(blobStore).PutBlob(bg, m, d, q)
}

// checkBlobUsage proves Postgres's running totals equal the stored rows.
func checkBlobUsage(t *testing.T, s Store) {
	t.Helper()
	ps, ok := s.(*postgresStore)
	if !ok {
		return
	}
	var bad int64
	if err := ps.pool.QueryRow(bg, `
WITH want AS (
  SELECT 'r|' || workspace AS scope, sum(size)::bigint AS b, count(*)::bigint AS c FROM relay_blobs GROUP BY workspace
  UNION ALL SELECT 'w|' || workspace || '|' || uploader, sum(size)::bigint, count(*)::bigint FROM relay_blobs GROUP BY workspace, uploader
  UNION ALL SELECT 't|' || tenant, sum(size)::bigint, count(*)::bigint FROM relay_blobs WHERE tenant <> '' GROUP BY tenant
  UNION ALL SELECT 'total', coalesce(sum(size), 0)::bigint, count(*)::bigint FROM relay_blobs)
SELECT count(*) FROM want FULL JOIN relay_blob_usage u USING (scope)
WHERE coalesce(want.b, 0) <> coalesce(u.bytes, 0) OR coalesce(want.c, 0) <> coalesce(u.count, 0)`).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatalf("%d relay_blob_usage scopes disagree with relay_blobs", bad)
	}
}

func expireBlob(t *testing.T, s Store, room, id string, at int64) {
	t.Helper()
	switch st := s.(type) {
	case *memoryStore:
		st.mu.Lock()
		st.blobs[room][id].meta.ExpiresAt = at
		st.mu.Unlock()
	case *postgresStore:
		if _, err := st.pool.Exec(bg, `UPDATE relay_blobs SET expires_at = $3 WHERE workspace = $1 AND id = $2`, room, id, at); err != nil {
			t.Fatal(err)
		}
	}
}

func blobQuotaErr(t *testing.T, err error, limit string) {
	t.Helper()
	wantQuota(t, err, limit)
	if !errors.Is(err, ErrStoreFull) {
		t.Fatalf("%s must answer 507 (ErrStoreFull)", limit)
	}
}

// ── Ids ──────────────────────────────────────────────────────────────────────

func TestBlobIDsAreRandomAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20000; i++ {
		id := newBlobID()
		if !validBlobID(id) || len(id) != blobIDLen {
			t.Fatalf("malformed id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q after %d", id, i)
		}
		seen[id] = true
	}
	for _, bad := range []string{"", "../x", strings.Repeat("a", 42), strings.Repeat("a", 44),
		strings.Repeat("a", 42) + "/", strings.Repeat("a", 42) + "=", strings.Repeat("a", 42) + "%"} {
		if validBlobID(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// ── Store level ──────────────────────────────────────────────────────────────

func TestBlobStoreRoundTripAndIsolation(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		bs := s.(blobStore)
		seedRoom(t, s, "w1")
		seedRoom(t, s, "w2")
		m, d := testBlob("w1", "ip:a", 1000)
		if err := bs.PutBlob(bg, m, d, blobQuota{}); err != nil {
			t.Fatal(err)
		}
		got, data, ok, err := bs.GetBlob(bg, "w1", m.ID, time.Now().Unix())
		if err != nil || !ok || !bytes.Equal(data, d) || got.SHA256 != m.SHA256 || got.Size != 1000 {
			t.Fatalf("get: ok=%v err=%v meta=%+v", ok, err, got)
		}
		// Another workspace can't read or delete it by id.
		if _, _, ok, _ := bs.GetBlob(bg, "w2", m.ID, time.Now().Unix()); ok {
			t.Fatal("a blob is readable from another workspace")
		}
		if ok, _ := bs.DeleteBlob(bg, "w2", m.ID); ok {
			t.Fatal("a blob is deletable from another workspace")
		}
		if _, _, ok, _ := bs.GetBlob(bg, "w1", m.ID, time.Now().Unix()); !ok {
			t.Fatal("deleting from another workspace removed the blob")
		}
		// A room that holds nothing can't take blobs (they never create a room).
		if _, err := putTestBlob(s, "fresh", "ip:a", 10, blobQuota{}); !errors.Is(err, errNoRoom) {
			t.Fatalf("blob into a room that holds nothing: %v", err)
		}
		if ok, _ := bs.DeleteBlob(bg, "w1", m.ID); !ok {
			t.Fatal("delete")
		}
		if _, _, ok, _ := bs.GetBlob(bg, "w1", m.ID, time.Now().Unix()); ok {
			t.Fatal("deleted blob still readable")
		}
		checkBlobUsage(t, s)
	})
}

func TestBlobQuotasEachCode(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		seedRoom(t, s, "r")
		seedRoom(t, s, "r2")
		// Room count.
		q := blobQuota{RoomMaxCount: 2}
		for i := 0; i < 2; i++ {
			if _, err := putTestBlob(s, "r", "ip:a", 10, q); err != nil {
				t.Fatal(err)
			}
		}
		_, err := putTestBlob(s, "r", "ip:a", 10, q)
		blobQuotaErr(t, err, limBlobRoomCount)
		// Room bytes (20 stored so far).
		_, err = putTestBlob(s, "r", "ip:a", 81, blobQuota{RoomMaxBytes: 100})
		blobQuotaErr(t, err, limBlobRoomBytes)
		if _, err := putTestBlob(s, "r", "ip:a", 80, blobQuota{RoomMaxBytes: 100}); err != nil {
			t.Fatalf("exactly at the room byte quota: %v", err)
		}
		// Writer count and bytes: ip:a has 3 blobs / 100 bytes in r; ip:b none.
		_, err = putTestBlob(s, "r", "ip:a", 1, blobQuota{WriterMaxCount: 3})
		blobQuotaErr(t, err, limBlobWriterCount)
		if _, err := putTestBlob(s, "r", "ip:b", 1, blobQuota{WriterMaxCount: 3}); err != nil {
			t.Fatalf("another writer is not limited by ip:a's count: %v", err)
		}
		_, err = putTestBlob(s, "r", "ip:a", 1, blobQuota{WriterMaxBytes: 100})
		blobQuotaErr(t, err, limBlobWriterBytes)
		// Per writer per workspace: ip:a has nothing in r2.
		if _, err := putTestBlob(s, "r2", "ip:a", 50, blobQuota{WriterMaxBytes: 100, WriterMaxCount: 3}); err != nil {
			t.Fatalf("writer quota is per workspace: %v", err)
		}
		// Relay-wide bytes: 151 stored.
		_, err = putTestBlob(s, "r2", "ip:c", 50, blobQuota{TotalMaxBytes: 200})
		blobQuotaErr(t, err, limBlobTotalBytes)
		// Refusals stored nothing.
		checkBlobUsage(t, s)
		if _, err := putTestBlob(s, "r2", "ip:c", 49, blobQuota{TotalMaxBytes: 200}); err != nil {
			t.Fatalf("a refused upload must not consume quota: %v", err)
		}
		checkBlobUsage(t, s)
	})
}

func TestBlobTenantQuotas(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		tctx := qctx(writeQuota{Tenant: "acme"})
		for _, room := range []string{"acme/a", "acme/b"} {
			if _, err := s.AppendEnvelope(tctx, room, raw(`{}`), ""); err != nil {
				t.Fatal(err)
			}
		}
		seedRoom(t, s, "plain")
		q := blobQuota{TenantMaxCount: 2, TenantMaxBytes: 100}
		if _, err := putTestBlob(s, "acme/a", "ip:a", 40, q); err != nil {
			t.Fatal(err)
		}
		if _, err := putTestBlob(s, "acme/b", "ip:a", 40, q); err != nil {
			t.Fatal(err)
		}
		_, err := putTestBlob(s, "acme/b", "ip:z", 1, q)
		blobQuotaErr(t, err, limBlobTenantCount)
		_, err = putTestBlob(s, "acme/a", "ip:z", 21, blobQuota{TenantMaxBytes: 100})
		blobQuotaErr(t, err, limBlobTenantBytes)
		// The tenant is the room's, never the uploader's claim.
		m, d := testBlob("acme/a", "ip:z", 20)
		m.Tenant = "other"
		if err := s.(blobStore).PutBlob(bg, m, d, blobQuota{TenantMaxBytes: 100}); err != nil {
			t.Fatal(err)
		}
		got, _, ok, _ := s.(blobStore).GetBlob(bg, "acme/a", m.ID, time.Now().Unix())
		if !ok || got.Tenant != "acme" {
			t.Fatalf("blob tenant %q, want the room's", got.Tenant)
		}
		// A room without a tenant isn't under a tenant quota.
		if _, err := putTestBlob(s, "plain", "ip:a", 500, q); err != nil {
			t.Fatal(err)
		}
		checkBlobUsage(t, s)
	})
}

// Concurrent uploads can't overshoot a quota: exactly the limit succeed, and
// the stored totals match.
func TestBlobQuotaConcurrentRace(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		seedRoom(t, s, "race")
		const limit, tries = 5, 40
		var ok, refused atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < tries; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := putTestBlob(s, "race", fmt.Sprintf("ip:%d", i%3), 100, blobQuota{RoomMaxCount: limit, RoomMaxBytes: 100 * limit, TotalMaxBytes: 100 * limit})
				var qe *quotaError
				switch {
				case err == nil:
					ok.Add(1)
				case errors.As(err, &qe):
					refused.Add(1)
				default:
					t.Errorf("upload %d: %v", i, err)
				}
			}(i)
		}
		wg.Wait()
		if ok.Load() != limit || refused.Load() != tries-limit {
			t.Fatalf("%d stored, %d refused; want %d and %d", ok.Load(), refused.Load(), limit, tries-limit)
		}
		checkBlobUsage(t, s)
	})
}

func TestBlobRetentionDeleteAndRoomExpiry(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		bs := s.(blobStore)
		seedRoom(t, s, "keep")
		seedRoom(t, s, "gone")
		q := blobQuota{RoomMaxCount: 1}
		old, err := putTestBlob(s, "keep", "ip:a", 10, q)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().Unix()
		// An expired blob is gone at once, before the sweep runs.
		expireBlob(t, s, "keep", old.ID, now-1)
		if _, _, ok, _ := bs.GetBlob(bg, "keep", old.ID, now); ok {
			t.Fatal("an expired blob is still served")
		}
		if n, err := bs.PruneExpiredBlobs(bg, now); err != nil || n != 1 {
			t.Fatalf("prune: %d %v", n, err)
		}
		checkBlobUsage(t, s)
		// Its quota is free again.
		if _, err := putTestBlob(s, "keep", "ip:a", 10, q); err != nil {
			t.Fatalf("after expiry: %v", err)
		}
		// A blob without an expiry is kept by the sweep.
		if n, _ := bs.PruneExpiredBlobs(bg, now+1e9); n != 0 {
			t.Fatalf("pruned %d blobs that never expire", n)
		}
		// A purged room loses its blobs; an idle-expired room too.
		g, err := putTestBlob(s, "gone", "ip:a", 10, blobQuota{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.(roomStore).PurgeRoom(bg, "gone"); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, _ := bs.GetBlob(bg, "gone", g.ID, now); ok {
			t.Fatal("a purged room's blob survived")
		}
		checkBlobUsage(t, s)
		seedRoom(t, s, "idle")
		i, err := putTestBlob(s, "idle", "ip:a", 10, blobQuota{})
		if err != nil {
			t.Fatal(err)
		}
		setIdle(t, s, "idle", now-1000)
		if _, err := s.(roomStore).PruneIdleRooms(bg, now-10); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, _ := bs.GetBlob(bg, "idle", i.ID, now); ok {
			t.Fatal("an idle-expired room's blob survived")
		}
		checkBlobUsage(t, s)
	})
}

func TestBlobDeleteByUploader(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		bs := s.(blobStore)
		seedRoom(t, s, "w")
		seedRoom(t, s, "w2")
		mine, _ := putTestBlob(s, "w", "sub:bob", 10, blobQuota{})
		_, _ = putTestBlob(s, "w", "sub:bob", 10, blobQuota{})
		other, _ := putTestBlob(s, "w2", "sub:bob", 10, blobQuota{})
		theirs, _ := putTestBlob(s, "w", "sub:alice", 10, blobQuota{})
		if n, err := bs.DeleteBlobsByUploader(bg, "w", blobUploaderTag("sub:bob")); err != nil || n != 2 {
			t.Fatalf("deleted %d %v", n, err)
		}
		now := time.Now().Unix()
		if _, _, ok, _ := bs.GetBlob(bg, "w", mine.ID, now); ok {
			t.Fatal("bob's blob survived")
		}
		for _, k := range []struct{ room, id string }{{"w2", other.ID}, {"w", theirs.ID}} {
			if _, _, ok, _ := bs.GetBlob(bg, k.room, k.id, now); !ok {
				t.Fatalf("%s/%s removed with bob's blobs", k.room, k.id)
			}
		}
		checkBlobUsage(t, s)
	})
}

func TestBlobSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	seedRoom(t, s, "w")
	m, d := testBlob("w", "ip:a", 4096)
	m.ExpiresAt = time.Now().Unix() + 3600
	if err := s.PutBlob(bg, m, d, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	gone, gd := testBlob("w", "ip:a", 10)
	gone.ExpiresAt = time.Now().Unix() + 3600
	if err := s.PutBlob(bg, gone, gd, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	expireBlob(t, s, "w", gone.ID, time.Now().Unix()-1)
	budget := s.storeBytes
	if err := s.Flush(bg); err != nil {
		t.Fatal(err)
	}
	r := newMemoryStoreWithPersistence(dir)
	got, data, ok, _ := r.GetBlob(bg, "w", m.ID, time.Now().Unix())
	if !ok || !bytes.Equal(data, d) || got.SHA256 != m.SHA256 || got.Uploader != m.Uploader || got.ExpiresAt != m.ExpiresAt {
		t.Fatalf("restored blob: ok=%v meta=%+v", ok, got)
	}
	if _, _, ok, _ := r.GetBlob(bg, "w", gone.ID, 0); ok {
		t.Fatal("an expired blob was restored")
	}
	want := budget - (10 + blobOverheadBytes + int64(len("w")))
	if r.storeBytes != want {
		t.Fatalf("restored budget %d, want %d", r.storeBytes, want)
	}
	if r.blobTotal.count != 1 || r.blobTotal.bytes != 4096 {
		t.Fatalf("restored totals %+v", r.blobTotal)
	}
}

// Blobs count toward the memory store budget: they can't get round it.
func TestBlobMemoryBudget(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_STORE_BYTES", "20000")
	s := newMemoryStore()
	seedRoom(t, s, "w")
	if _, err := putTestBlob(s, "w", "ip:a", 15000, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	if _, err := putTestBlob(s, "w", "ip:a", 15000, blobQuota{}); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("over the store budget: %v", err)
	}
	if ok, _ := s.DeleteBlob(bg, "w", firstBlobID(s, "w")); !ok {
		t.Fatal("delete")
	}
	if _, err := putTestBlob(s, "w", "ip:a", 15000, blobQuota{}); err != nil {
		t.Fatalf("budget not given back on delete: %v", err)
	}
}

func firstBlobID(s *memoryStore, room string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id := range s.blobs[room] {
		return id
	}
	return ""
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

type blobResp struct {
	ID        string `json:"id"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ExpiresAt int64  `json:"expiresAt"`
	Error     string `json:"error"`
}

func blobHTTP(t *testing.T, method, url, token string, body []byte) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	r, _ := http.NewRequest(method, url, rdr)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func blobServer(t *testing.T, s Store, env map[string]string) *httptest.Server {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	srv := New(Options{Store: s, Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func seedHTTP(t *testing.T, url, ws, token string) {
	t.Helper()
	if code, b := req(t, "POST", url+"/v1/workspaces/"+ws+"/envelopes", token, map[string]string{"ct": "seed"}); code != 200 {
		t.Fatalf("seed %s: %d %s", ws, code, b)
	}
}

func TestHTTPBlobRoundTrip(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		ts := blobServer(t, s, nil)
		seedHTTP(t, ts.URL, "w1", "")
		seedHTTP(t, ts.URL, "w2", "")
		data := []byte("\x00sealed ciphertext \xff")
		resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w1/blobs", "", data)
		var br blobResp
		_ = json.Unmarshal(b, &br)
		sum := sha256.Sum256(data)
		if resp.StatusCode != http.StatusCreated || !validBlobID(br.ID) || br.Size != int64(len(data)) ||
			br.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("upload: %d %s", resp.StatusCode, b)
		}
		if want := time.Now().Add(30 * 24 * time.Hour).Unix(); br.ExpiresAt < want-60 || br.ExpiresAt > want+60 {
			t.Fatalf("default retention: expiresAt %d, want about %d", br.ExpiresAt, want)
		}
		resp, got := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w1/blobs/"+br.ID, "", nil)
		h := resp.Header
		if resp.StatusCode != 200 || !bytes.Equal(got, data) || h.Get("Content-Type") != "application/octet-stream" ||
			h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Disposition") != "attachment" ||
			h.Get("Cache-Control") != "no-store" || h.Get("Content-Length") != fmt.Sprint(len(data)) {
			t.Fatalf("download: %d %v %q", resp.StatusCode, h, got)
		}
		// Unknown, malformed, other-workspace: the same 404.
		for _, p := range []string{"/v1/workspaces/w2/blobs/" + br.ID, "/v1/workspaces/w1/blobs/" + newBlobID(),
			"/v1/workspaces/w1/blobs/short", "/v1/workspaces/w1/blobs/" + strings.Repeat("%2E", 15)} {
			resp, b := blobHTTP(t, "GET", ts.URL+p, "", nil)
			if resp.StatusCode != 404 || !strings.Contains(string(b), `"blob_not_found"`) {
				t.Fatalf("GET %s: %d %s", p, resp.StatusCode, b)
			}
		}
		// No listing, no client-chosen ids.
		if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w1/blobs", "", nil); resp.StatusCode == 200 {
			t.Fatal("the blob collection is listable")
		}
		if resp, _ := blobHTTP(t, "PUT", ts.URL+"/v1/workspaces/w1/blobs/"+newBlobID(), "", data); resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("PUT: %d", resp.StatusCode)
		}
		// Delete from another workspace: 204 but nothing removed.
		if resp, _ := blobHTTP(t, "DELETE", ts.URL+"/v1/workspaces/w2/blobs/"+br.ID, "", nil); resp.StatusCode != 204 {
			t.Fatalf("delete elsewhere: %d", resp.StatusCode)
		}
		if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w1/blobs/"+br.ID, "", nil); resp.StatusCode != 200 {
			t.Fatal("delete from another workspace removed the blob")
		}
		for i := 0; i < 2; i++ {
			if resp, _ := blobHTTP(t, "DELETE", ts.URL+"/v1/workspaces/w1/blobs/"+br.ID, "", nil); resp.StatusCode != 204 {
				t.Fatalf("delete #%d: %d", i, resp.StatusCode)
			}
		}
		if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w1/blobs/"+br.ID, "", nil); resp.StatusCode != 404 {
			t.Fatal("deleted blob still served")
		}
		// Empty body, a workspace that holds nothing.
		if resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w1/blobs", "", nil); resp.StatusCode != 400 || !strings.Contains(string(b), "empty_blob") {
			t.Fatalf("empty: %d %s", resp.StatusCode, b)
		}
		if resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/nothing/blobs", "", data); resp.StatusCode != 404 || !strings.Contains(string(b), "no_workspace") {
			t.Fatalf("no room: %d %s", resp.StatusCode, b)
		}
		checkBlobUsage(t, s)
	})
}

func TestHTTPBlobTooLarge(t *testing.T) {
	ts := blobServer(t, newMemoryStore(), map[string]string{"LANGSTROTH_RELAY_BLOB_MAX_BYTES": "1000"})
	seedHTTP(t, ts.URL, "w", "")
	if resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", make([]byte, 1001)); resp.StatusCode != 413 ||
		!strings.Contains(string(b), `"blob_too_large"`) || !strings.Contains(string(b), `"maxBytes":1000`) {
		t.Fatalf("over the size: %d %s", resp.StatusCode, b)
	}
	// Chunked, no Content-Length: the reader cap still holds.
	r, _ := http.NewRequest("POST", ts.URL+"/v1/workspaces/w/blobs", io.MultiReader(bytes.NewReader(make([]byte, 600)), bytes.NewReader(make([]byte, 600))))
	r.ContentLength = -1
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("chunked over the size: %d", resp.StatusCode)
	}
	if resp, _ := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", make([]byte, 1000)); resp.StatusCode != 201 {
		t.Fatalf("exactly the size: %d", resp.StatusCode)
	}
	// Larger than the 4 MiB JSON body cap is fine for a blob.
	ts2 := blobServer(t, newMemoryStore(), map[string]string{"LANGSTROTH_RELAY_BLOB_MAX_BYTES": fmt.Sprint(6 << 20)})
	seedHTTP(t, ts2.URL, "w", "")
	if resp, b := blobHTTP(t, "POST", ts2.URL+"/v1/workspaces/w/blobs", "", make([]byte, 5<<20)); resp.StatusCode != 201 {
		t.Fatalf("5 MiB blob: %d %s", resp.StatusCode, b)
	}
}

func TestHTTPBlobQuota507AndRate429(t *testing.T) {
	ts := blobServer(t, newMemoryStore(), map[string]string{
		"LANGSTROTH_RELAY_BLOB_ROOM_MAX_COUNT": "1",
		"LANGSTROTH_RELAY_BLOB_RATE":           "0.001",
		"LANGSTROTH_RELAY_BLOB_BURST":          "2",
	})
	seedHTTP(t, ts.URL, "w", "")
	if resp, _ := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", []byte("a")); resp.StatusCode != 201 {
		t.Fatalf("first: %d", resp.StatusCode)
	}
	resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", []byte("b"))
	var rb refusalBody
	_ = json.Unmarshal(b, &rb)
	if resp.StatusCode != http.StatusInsufficientStorage || rb.Error != limBlobRoomCount || resp.Header.Get("Retry-After") == "" || rb.RetryAfter < 1 {
		t.Fatalf("room count: %d %v %s", resp.StatusCode, resp.Header, b)
	}
	resp, b = blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", []byte("c"))
	_ = json.Unmarshal(b, &rb)
	if resp.StatusCode != http.StatusTooManyRequests || rb.Error != limBlobRate || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("rate: %d %s", resp.StatusCode, b)
	}
	m := metricsBody(t, ts.URL)
	for _, l := range []string{limBlobRoomCount, limBlobRate} {
		if !strings.Contains(m, `hive_relay_limit_rejections_total{limit="`+l+`"} 1`) {
			t.Fatalf("metrics miss %s:\n%s", l, m)
		}
	}
	// Reads and deletes aren't under the upload rate.
	for i := 0; i < 5; i++ {
		if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w/blobs/"+newBlobID(), "", nil); resp.StatusCode != 404 {
			t.Fatalf("read under the upload rate: %d", resp.StatusCode)
		}
	}
}

func TestHTTPBlobTotalQuotaRetryAfter(t *testing.T) {
	ts := blobServer(t, newMemoryStore(), map[string]string{"LANGSTROTH_RELAY_BLOB_TOTAL_MAX_BYTES": "10"})
	seedHTTP(t, ts.URL, "w", "")
	if resp, _ := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", make([]byte, 10)); resp.StatusCode != 201 {
		t.Fatal("first")
	}
	resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", []byte("x"))
	if resp.StatusCode != 507 || !strings.Contains(string(b), limBlobTotalBytes) || resp.Header.Get("Retry-After") != fmt.Sprint(int(retryStoreFull.Seconds())) {
		t.Fatalf("total: %d %v %s", resp.StatusCode, resp.Header.Get("Retry-After"), b)
	}
}

func TestHTTPBlobsOff404(t *testing.T) {
	ts := blobServer(t, newMemoryStore(), map[string]string{"LANGSTROTH_RELAY_BLOBS": "off"})
	seedHTTP(t, ts.URL, "w", "")
	for _, m := range []string{"POST", "GET", "DELETE"} {
		p := "/v1/workspaces/w/blobs"
		if m != "POST" {
			p += "/" + newBlobID()
		}
		if resp, _ := blobHTTP(t, m, ts.URL+p, "", []byte("x")); resp.StatusCode != 404 {
			t.Fatalf("%s with blobs off: %d", m, resp.StatusCode)
		}
	}
}

// Under a token-gated relay every blob route needs a valid token.
func TestHTTPBlobAuthRequired(t *testing.T) {
	sk := testKey(t)
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	tok := issueToken(sk, TokenClaims{Sub: "alice", Exp: uint64(time.Now().Add(time.Hour).Unix())})
	seedHTTP(t, ts.URL, "w", tok)
	resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", tok, []byte("secret"))
	var br blobResp
	_ = json.Unmarshal(b, &br)
	if resp.StatusCode != 201 {
		t.Fatalf("upload with a token: %d %s", resp.StatusCode, b)
	}
	forged := issueToken(testKeyOther(t), TokenClaims{Sub: "alice", Exp: uint64(time.Now().Add(time.Hour).Unix())})
	for _, bad := range []string{"", "garbage", forged} {
		for _, c := range []struct{ m, p string }{{"POST", "/v1/workspaces/w/blobs"}, {"GET", "/v1/workspaces/w/blobs/" + br.ID}, {"DELETE", "/v1/workspaces/w/blobs/" + br.ID}} {
			if resp, _ := blobHTTP(t, c.m, ts.URL+c.p, bad, []byte("x")); resp.StatusCode != 401 {
				t.Fatalf("%s %s with token %q: %d", c.m, c.p, bad, resp.StatusCode)
			}
		}
	}
	if resp, got := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w/blobs/"+br.ID, tok, nil); resp.StatusCode != 200 || string(got) != "secret" {
		t.Fatalf("download with a token: %d", resp.StatusCode)
	}
}

func testKeyOther(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// With relay membership, a workspace's roster gates blobs like envelopes, and
// removing a member deletes the blobs they uploaded there.
func TestHTTPBlobMembership(t *testing.T) {
	ts, sk := membershipServer(t)
	tk := func(sub string) string {
		return issueToken(sk, TokenClaims{Sub: sub, Exp: uint64(time.Now().Add(time.Hour).Unix())})
	}
	owner, bob, eve := tk("owner"), tk("bob"), tk("eve")
	if code, b := req(t, "POST", ts.URL+"/v1/workspaces/team/members/claim", owner, map[string]string{"login": "o"}); code != 200 {
		t.Fatalf("claim: %d %s", code, b)
	}
	if code, b := req(t, "POST", ts.URL+"/v1/workspaces/team/members", owner, map[string]string{"account": "bob", "role": "contributor"}); code != 200 {
		t.Fatalf("add bob: %d %s", code, b)
	}
	seedHTTP(t, ts.URL, "team", owner)
	up := func(tok string) (int, string) {
		resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/team/blobs", tok, []byte("bytes"))
		var br blobResp
		_ = json.Unmarshal(b, &br)
		return resp.StatusCode, br.ID
	}
	if code, _ := up(eve); code != 403 {
		t.Fatalf("a non-member uploaded: %d", code)
	}
	code, bobBlob := up(bob)
	if code != 201 {
		t.Fatalf("bob upload: %d", code)
	}
	_, ownerBlob := up(owner)
	if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/team/blobs/"+bobBlob, eve, nil); resp.StatusCode != 403 {
		t.Fatalf("a non-member read: %d", resp.StatusCode)
	}
	if resp, _ := blobHTTP(t, "DELETE", ts.URL+"/v1/workspaces/team/blobs/"+bobBlob, eve, nil); resp.StatusCode != 403 {
		t.Fatalf("a non-member deleted: %d", resp.StatusCode)
	}
	if code, b := req(t, "DELETE", ts.URL+"/v1/workspaces/team/members/bob", owner, nil); code != 200 {
		t.Fatalf("remove bob: %d %s", code, b)
	}
	if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/team/blobs/"+bobBlob, owner, nil); resp.StatusCode != 404 {
		t.Fatalf("a removed member's blob is still served: %d", resp.StatusCode)
	}
	if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/team/blobs/"+ownerBlob, owner, nil); resp.StatusCode != 200 {
		t.Fatalf("another member's blob went with bob's: %d", resp.StatusCode)
	}
}

// Tenancy: a blob is under its tenant's namespace and quotas.
func TestHTTPBlobTenancy(t *testing.T) {
	tenancyStores(t, func(t *testing.T, s Store) {
		f := newTenancyFixture(t, s, `{"blob_max_count": 1}`)
		seedHTTP(t, f.ts.URL, "w", f.acme)
		seedHTTP(t, f.ts.URL, "w", f.home)
		resp, b := blobHTTP(t, "POST", f.ts.URL+"/v1/workspaces/w/blobs", f.acme, []byte("acme bytes"))
		var br blobResp
		_ = json.Unmarshal(b, &br)
		if resp.StatusCode != 201 {
			t.Fatalf("acme upload: %d %s", resp.StatusCode, b)
		}
		// Same workspace name, other tenant: not visible, not deletable.
		if resp, _ := blobHTTP(t, "GET", f.ts.URL+"/v1/workspaces/w/blobs/"+br.ID, f.home, nil); resp.StatusCode != 404 {
			t.Fatalf("cross-tenant read: %d", resp.StatusCode)
		}
		_, _ = blobHTTP(t, "DELETE", f.ts.URL+"/v1/workspaces/w/blobs/"+br.ID, f.home, nil)
		if resp, _ := blobHTTP(t, "GET", f.ts.URL+"/v1/workspaces/w/blobs/"+br.ID, f.acme, nil); resp.StatusCode != 200 {
			t.Fatalf("cross-tenant delete removed it: %d", resp.StatusCode)
		}
		resp, b = blobHTTP(t, "POST", f.ts.URL+"/v1/workspaces/w/blobs", f.acme, []byte("second"))
		if resp.StatusCode != 507 || !strings.Contains(string(b), limBlobTenantCount) {
			t.Fatalf("tenant count: %d %s", resp.StatusCode, b)
		}
		// home's own quota is separate.
		if resp, b := blobHTTP(t, "POST", f.ts.URL+"/v1/workspaces/w/blobs", f.home, []byte("home")); resp.StatusCode != 201 {
			t.Fatalf("home upload: %d %s", resp.StatusCode, b)
		}
		checkBlobUsage(t, s)
	})
}

func TestBlobConfigDefaults(t *testing.T) {
	c := blobConfigFromEnv()
	if !c.enabled || c.maxBytes != 25<<20 || c.roomMaxBytes != 512<<20 || c.roomMaxCount != 2000 ||
		c.writerMaxBytes != defaultBlobWriterMaxBytes || c.writerMaxCount != defaultBlobWriterMaxCount || c.totalMaxBytes != 0 || c.retention != 30*24*time.Hour || c.rate == nil ||
		c.inflight == nil || c.inflight.max != 16 || c.inflight.perWriter != 4 ||
		c.download == nil || c.download.rate != 0.5 || c.download.burst != 100 ||
		c.clientDownload == nil || c.clientDownload.rate != 2 || c.clientDownload.burst != 60 {
		t.Fatalf("defaults: %+v", c)
	}
	t.Setenv("LANGSTROTH_RELAY_BLOB_MAX_BYTES", "0")
	if blobConfigFromEnv().maxBytes != 25<<20 {
		t.Fatal("a zero blob size cap must keep the default, never be unlimited")
	}
	for _, v := range []string{"off", "OFF", "0", "false"} {
		if blobsEnabled(v) {
			t.Fatalf("%q left blobs on", v)
		}
	}
}
