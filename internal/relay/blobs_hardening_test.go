package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Second adversarial review of the blob channel (prove-then-fix).

// An upload that takes longer than the server's write timeout must still get
// its answer: otherwise the blob is stored, the client never learns its id,
// retries, and each retry burns quota on an orphan.
func TestHTTPBlobSlowUploadOutlivesWriteTimeout(t *testing.T) {
	s := newMemoryStore()
	srv := New(Options{Store: s, Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Config.ReadTimeout = 300 * time.Millisecond
	ts.Config.WriteTimeout = 300 * time.Millisecond
	ts.Start()
	t.Cleanup(ts.Close)
	seedHTTP(t, ts.URL, "w", "")

	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < 8; i++ {
			_, _ = pw.Write([]byte("chunk-of-ciphertext"))
			time.Sleep(100 * time.Millisecond)
		}
		_ = pw.Close()
	}()
	r, _ := http.NewRequest("POST", ts.URL+"/v1/workspaces/w/blobs", pr)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("slow upload lost its answer: %v (stored blobs: %d)", err, s.blobTotal.count)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("slow upload: %d %s", resp.StatusCode, b)
	}
}

// stalledUpload starts an upload that sends some bytes and then waits for
// release; it returns once the server holds the request.
func stalledUpload(t *testing.T, url, token string) (release func() (int, []byte)) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() }) // never leave the server holding it
	r, _ := http.NewRequest("POST", url, pr)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	type res struct {
		code int
		body []byte
	}
	done := make(chan res, 1)
	go func() {
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			done <- res{code: -1, body: []byte(err.Error())}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		done <- res{resp.StatusCode, b}
	}()
	if _, err := pw.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // the handler is now reading the body
	return func() (int, []byte) {
		_ = pw.Close()
		r := <-done
		return r.code, r.body
	}
}

// Every upload in flight holds up to the blob size cap in memory for up to
// the transfer window. Without a bound on concurrent uploads, a client that
// opens many uploads and never finishes them (slowloris) exhausts the heap.
func TestHTTPBlobUploadsInFlightCapped(t *testing.T) {
	sk := testKey(t)
	t.Setenv("LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT", "2")
	t.Setenv("LANGSTROTH_RELAY_BLOB_WRITER_INFLIGHT", "1")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	tk := func(sub string) string {
		return issueToken(sk, TokenClaims{Sub: sub, Exp: uint64(time.Now().Add(time.Hour).Unix())})
	}
	alice, bob, carol := tk("alice"), tk("bob"), tk("carol")
	seedHTTP(t, ts.URL, "w", alice)
	url := ts.URL + "/v1/workspaces/w/blobs"

	a1 := stalledUpload(t, url, alice)
	// alice's second concurrent upload: over her own in-flight cap.
	resp, b := blobHTTP(t, "POST", url, alice, []byte("x"))
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(b), limBlobInflight) || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second upload in flight for one writer: %d %s", resp.StatusCode, b)
	}
	b1 := stalledUpload(t, url, bob)
	// The relay-wide cap (2) is now full: carol is refused too.
	resp, b = blobHTTP(t, "POST", url, carol, []byte("x"))
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(b), limBlobInflight) {
		t.Fatalf("upload past the relay-wide in-flight cap: %d %s", resp.StatusCode, b)
	}
	if code, b := a1(); code != http.StatusCreated {
		t.Fatalf("stalled upload a1: %d %s", code, b)
	}
	if code, b := b1(); code != http.StatusCreated {
		t.Fatalf("stalled upload b1: %d %s", code, b)
	}
	// Slots are given back.
	if resp, b := blobHTTP(t, "POST", url, carol, []byte("x")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("after the uploads finished: %d %s", resp.StatusCode, b)
	}
	if resp, b := blobHTTP(t, "POST", url, alice, []byte("x")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("alice after hers finished: %d %s", resp.StatusCode, b)
	}
}

// The memory store's JSON snapshot is rewritten every few seconds. Blob
// bytes inside it (base64) make every flush rewrite every attachment: a
// workspace's 512 MiB quota becomes ~700 MB of JSON every 5 s. The snapshot
// must hold only metadata; the bytes live in their own files.
func TestBlobSnapshotKeepsBytesOutOfJSON(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	seedRoom(t, s, "w")
	m, d := testBlob("w", "ip:a", 256<<10)
	if err := s.PutBlob(bg, m, d, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(bg); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, snapshotFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 32<<10 {
		t.Fatalf("snapshot is %d bytes for one 256 KiB blob: blob bytes ride the JSON", fi.Size())
	}
	r := newMemoryStoreWithPersistence(dir)
	if _, data, ok, _ := r.GetBlob(bg, "w", m.ID, time.Now().Unix()); !ok || !bytes.Equal(data, d) {
		t.Fatalf("blob not restored: ok=%v", ok)
	}
	// Deleting removes its file; a restore then doesn't bring it back even
	// from a snapshot written before the delete.
	if ok, _ := r.DeleteBlob(bg, "w", m.ID); !ok {
		t.Fatal("delete")
	}
	r2 := newMemoryStoreWithPersistence(dir) // the snapshot still lists it
	if _, _, ok, _ := r2.GetBlob(bg, "w", m.ID, time.Now().Unix()); ok {
		t.Fatal("a deleted blob came back from the snapshot")
	}
	if r2.blobTotal.count != 0 {
		t.Fatalf("totals after restore: %+v", r2.blobTotal)
	}
}

// A blob file on disk that no snapshot lists (an upload that landed just
// before a crash) is removed at boot, and a corrupted file isn't served.
func TestBlobSnapshotOrphanAndCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	seedRoom(t, s, "w")
	keep, kd := testBlob("w", "ip:a", 100)
	if err := s.PutBlob(bg, keep, kd, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	bad, bd := testBlob("w", "ip:a", 100)
	if err := s.PutBlob(bg, bad, bd, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(bg); err != nil {
		t.Fatal(err)
	}
	orphan, od := testBlob("w", "ip:a", 100) // written after the last flush
	if err := s.PutBlob(bg, orphan, od, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	// Corrupt one stored file (same length, other bytes).
	if err := os.WriteFile(s.blobFile("w", bad.ID), bytes.Repeat([]byte{1}, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newMemoryStoreWithPersistence(dir)
	if _, _, ok, _ := r.GetBlob(bg, "w", keep.ID, time.Now().Unix()); !ok {
		t.Fatal("intact blob lost")
	}
	if _, _, ok, _ := r.GetBlob(bg, "w", bad.ID, time.Now().Unix()); ok {
		t.Fatal("a corrupted blob file was served")
	}
	if _, err := os.Stat(r.blobFile("w", orphan.ID)); !os.IsNotExist(err) {
		t.Fatalf("orphan blob file left on disk: %v", err)
	}
	if r.blobTotal.count != 1 {
		t.Fatalf("totals %+v", r.blobTotal)
	}
}

// A snapshot written before blob files (bytes inline) still restores, and
// its bytes move out to files.
func TestBlobSnapshotInlineBytesMigrate(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	seedRoom(t, s, "w")
	m, d := testBlob("w", "ip:a", 1000)
	snap := s.toSnapshot()
	snap.Blobs = []blobSnap{{Room: "w", ID: m.ID, Uploader: m.Uploader, Size: m.Size, SHA256: m.SHA256, CreatedAt: m.CreatedAt, Data: d}}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, snapshotFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r := newMemoryStoreWithPersistence(dir)
	if _, data, ok, _ := r.GetBlob(bg, "w", m.ID, time.Now().Unix()); !ok || !bytes.Equal(data, d) {
		t.Fatal("inline blob not restored")
	}
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	r2 := newMemoryStoreWithPersistence(dir)
	if _, data, ok, _ := r2.GetBlob(bg, "w", m.ID, time.Now().Unix()); !ok || !bytes.Equal(data, d) {
		t.Fatal("blob lost after its bytes moved to a file")
	}
}

// Deleting a blob an identified writer uploaded is bound to that writer: a
// fellow writer who learned the id (every reader of the workspace log does)
// can't delete it. A workspace Admin can (relay membership), and blobs
// uploaded without an identity stay a capability.
func TestHTTPBlobDeleteBoundToUploader(t *testing.T) {
	ts, sk := membershipServer(t)
	tk := func(sub string) string {
		return issueToken(sk, TokenClaims{Sub: sub, Exp: uint64(time.Now().Add(time.Hour).Unix())})
	}
	owner, admin, bob, carol := tk("owner"), tk("admin"), tk("bob"), tk("carol")
	up := func(ws, tok string) string {
		t.Helper()
		resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/"+ws+"/blobs", tok, []byte("bytes"))
		var br blobResp
		_ = json.Unmarshal(b, &br)
		if resp.StatusCode != 201 {
			t.Fatalf("upload: %d %s", resp.StatusCode, b)
		}
		return br.ID
	}
	del := func(ws, id, tok string) (int, string) {
		resp, b := blobHTTP(t, "DELETE", ts.URL+"/v1/workspaces/"+ws+"/blobs/"+id, tok, nil)
		return resp.StatusCode, string(b)
	}
	get := func(ws, id, tok string) int {
		resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/"+ws+"/blobs/"+id, tok, nil)
		return resp.StatusCode
	}

	// Unclaimed workspace, identified writers.
	seedHTTP(t, ts.URL, "open", bob)
	b1 := up("open", bob)
	if code, body := del("open", b1, carol); code != http.StatusForbidden || !strings.Contains(body, "blob_not_yours") {
		t.Fatalf("carol deleted bob's blob: %d %s", code, body)
	}
	if get("open", b1, bob) != 200 {
		t.Fatal("bob's blob gone after a refused delete")
	}
	if code, _ := del("open", b1, ""); code == http.StatusNoContent {
		t.Fatalf("an anonymous caller deleted bob's blob: %d", code)
	}
	if code, _ := del("open", b1, bob); code != http.StatusNoContent {
		t.Fatalf("bob deleting his own: %d", code)
	}
	if get("open", b1, bob) != 404 {
		t.Fatal("bob's delete didn't delete")
	}
	// Absent ids still answer 204.
	if code, _ := del("open", newBlobID(), carol); code != http.StatusNoContent {
		t.Fatalf("absent id: %d", code)
	}
	// (An upload without an identity stays a capability: TestHTTPBlobRoundTrip
	// on the open relay, TestBlobStoreDeleteOwnership.)

	// Claimed workspace: Admin+ may delete anyone's blob, Contributors only
	// their own.
	if code, b := req(t, "POST", ts.URL+"/v1/workspaces/team/members/claim", owner, map[string]string{"login": "o"}); code != 200 {
		t.Fatalf("claim: %d %s", code, b)
	}
	for acct, role := range map[string]string{"admin": "admin", "bob": "contributor", "carol": "contributor"} {
		if code, b := req(t, "POST", ts.URL+"/v1/workspaces/team/members", owner, map[string]string{"account": acct, "role": role}); code != 200 {
			t.Fatalf("add %s: %d %s", acct, code, b)
		}
	}
	seedHTTP(t, ts.URL, "team", owner)
	b2, b3 := up("team", bob), up("team", bob)
	if code, _ := del("team", b2, carol); code != http.StatusForbidden {
		t.Fatalf("a contributor deleted another's blob: %d", code)
	}
	if code, _ := del("team", b2, admin); code != http.StatusNoContent || get("team", b2, owner) != 404 {
		t.Fatalf("admin deleting a member's blob: %d", code)
	}
	if code, _ := del("team", b3, owner); code != http.StatusNoContent || get("team", b3, owner) != 404 {
		t.Fatalf("owner deleting a member's blob: %d", code)
	}
	// An owner's blob can't be deleted by a contributor either.
	o1 := up("team", owner)
	if code, _ := del("team", o1, bob); code != http.StatusForbidden {
		t.Fatalf("a contributor deleted the owner's blob: %d", code)
	}
}

// The store-level ownership check, on both stores.
func TestBlobStoreDeleteOwnership(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		seedRoom(t, s, "w")
		bs := s.(blobStore)
		m, d := testBlob("w", "sub:bob", 10)
		m.Bound = true
		if err := bs.PutBlob(bg, m, d, blobQuota{}); err != nil {
			t.Fatal(err)
		}
		carol := blobDeleter{Uploader: blobUploaderTag("sub:carol")}
		if res, err := bs.DeleteBlobAs(bg, "w", m.ID, carol); err != nil || res != blobDeleteRefused {
			t.Fatalf("carol: %v %v", res, err)
		}
		if res, err := bs.DeleteBlobAs(bg, "w", m.ID, blobDeleter{Uploader: m.Uploader}); err != nil || res != blobDeleteDone {
			t.Fatalf("bob: %v %v", res, err)
		}
		if res, err := bs.DeleteBlobAs(bg, "w", m.ID, blobDeleter{Uploader: m.Uploader}); err != nil || res != blobDeleteAbsent {
			t.Fatalf("again: %v %v", res, err)
		}
		n, d2 := testBlob("w", "ip:1.2.3.4", 10) // unbound: a capability
		if err := bs.PutBlob(bg, n, d2, blobQuota{}); err != nil {
			t.Fatal(err)
		}
		if res, err := bs.DeleteBlobAs(bg, "w", n.ID, carol); err != nil || res != blobDeleteDone {
			t.Fatalf("unbound: %v %v", res, err)
		}
		o, d3 := testBlob("w", "sub:bob", 10)
		o.Bound = true
		if err := bs.PutBlob(bg, o, d3, blobQuota{}); err != nil {
			t.Fatal(err)
		}
		if res, err := bs.DeleteBlobAs(bg, "w", o.ID, blobDeleter{Uploader: carol.Uploader, Any: true}); err != nil || res != blobDeleteDone {
			t.Fatalf("admin: %v %v", res, err)
		}
		checkBlobUsage(t, s)
	})
}

// The binding survives a memory-store restart and a Postgres table that
// predates the column gets it.
func TestBlobBoundPersists(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	seedRoom(t, s, "w")
	m, d := testBlob("w", "sub:bob", 10)
	m.Bound = true
	if err := s.PutBlob(bg, m, d, blobQuota{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(bg); err != nil {
		t.Fatal(err)
	}
	r := newMemoryStoreWithPersistence(dir)
	if res, _ := r.DeleteBlobAs(bg, "w", m.ID, blobDeleter{Uploader: blobUploaderTag("sub:carol")}); res != blobDeleteRefused {
		t.Fatalf("binding lost on restore: %v", res)
	}
	if os.Getenv("TEST_DATABASE_URL") == "" {
		return
	}
	ps := pgStore(t)
	if _, err := ps.pool.Exec(bg, `ALTER TABLE relay_blobs DROP COLUMN bound`); err != nil {
		t.Fatal(err)
	}
	if err := ps.migrate(bg); err != nil {
		t.Fatal(err)
	}
	seedRoom(t, ps, "w")
	if err := ps.PutBlob(bg, m, d, blobQuota{}); err != nil {
		t.Fatalf("upload after the migration: %v", err)
	}
	if res, _ := ps.DeleteBlobAs(bg, "w", m.ID, blobDeleter{Uploader: blobUploaderTag("sub:carol")}); res != blobDeleteRefused {
		t.Fatalf("postgres binding: %v", res)
	}
}

// Downloads were limited only by the general read rate (100/s, burst 400 per
// client): one 25 MiB upload could be fetched gigabytes a second, and on an
// open relay (tokenless reads) a blob URL works as a public download link.
// A per-blob and a per-downloader rate stop the relay serving as a
// distribution point.
func TestHTTPBlobDownloadRate(t *testing.T) {
	ts := blobServer(t, newMemoryStore(), map[string]string{
		"LANGSTROTH_RELAY_BLOB_DOWNLOAD_RATE":         "0.001",
		"LANGSTROTH_RELAY_BLOB_DOWNLOAD_BURST":        "2",
		"LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_RATE":  "0.001",
		"LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_BURST": "3",
	})
	seedHTTP(t, ts.URL, "w", "")
	up := func() string {
		resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", "", []byte("bytes"))
		var br blobResp
		_ = json.Unmarshal(b, &br)
		if resp.StatusCode != 201 {
			t.Fatalf("upload: %d %s", resp.StatusCode, b)
		}
		return br.ID
	}
	a, b := up(), up()
	get := func(id string) (int, string) {
		resp, body := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w/blobs/"+id, "", nil)
		return resp.StatusCode, string(body)
	}
	for i := 0; i < 2; i++ {
		if code, _ := get(a); code != 200 {
			t.Fatalf("download %d: %d", i, code)
		}
	}
	if code, body := get(a); code != http.StatusTooManyRequests || !strings.Contains(body, limBlobDownloadRate) {
		t.Fatalf("third download of one blob: %d %s", code, body)
	}
	// Unknown ids don't spend a blob's budget, and another blob has its own.
	if code, _ := get(newBlobID()); code != 404 {
		t.Fatalf("unknown id: %d", code)
	}
	if code, _ := get(b); code != 200 {
		t.Fatalf("other blob: %d", code)
	}
	// This client has now had 3 downloads (burst 3): refused whatever the
	// blob, though b's own budget allows one more.
	if code, body := get(b); code != http.StatusTooManyRequests || !strings.Contains(body, limBlobDownloadRate) {
		t.Fatalf("past the per-client download rate: %d %s", code, body)
	}
}

// A client that opens an upload and then trickles (or sends nothing) held
// its upload slot for the whole five-minute window, so a few such clients
// kept every slot and blocked uploads for everyone. An idle timeout and a
// minimum average rate cut them off.
func TestHTTPBlobSlowlorisCutOff(t *testing.T) {
	idle, grace := blobIdleTimeout, blobRateGrace
	blobIdleTimeout, blobRateGrace = 300*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { blobIdleTimeout, blobRateGrace = idle, grace })
	t.Setenv("LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT", "1")
	ts := blobServer(t, newMemoryStore(), nil)
	seedHTTP(t, ts.URL, "w", "")
	url := ts.URL + "/v1/workspaces/w/blobs"

	// Stalled: sends a few bytes, then nothing.
	_ = stalledUpload(t, url, "")
	time.Sleep(600 * time.Millisecond)
	if resp, b := blobHTTP(t, "POST", url, "", []byte("x")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("a stalled upload still holds the slot: %d %s", resp.StatusCode, b)
	}

	// Trickling: a byte every 100 ms beats the idle timeout but not the rate.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				if _, err := pw.Write([]byte{1}); err != nil {
					return
				}
			}
		}
	}()
	done := make(chan int, 1)
	go func() {
		r, _ := http.NewRequest("POST", url, pr)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			done <- -1
			return
		}
		_ = resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case code := <-done:
		if code == http.StatusCreated {
			t.Fatalf("a trickled upload was accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a trickling upload was not cut off")
	}
	if resp, b := blobHTTP(t, "POST", url, "", []byte("x")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("after the trickler was cut off: %d %s", resp.StatusCode, b)
	}
}

// Concurrent uploads, deletes, expiry and a room purge leave the Postgres
// running totals equal to the stored rows, never negative.
func TestBlobUsageConsistentUnderChurn(t *testing.T) {
	blobStores(t, func(t *testing.T, s Store) {
		bs := s.(blobStore)
		rooms := []string{"a", "b", "c"}
		for _, r := range rooms {
			seedRoom(t, s, r)
		}
		var mu sync.Mutex
		var ids []BlobMeta
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 15; i++ {
					room := rooms[(g+i)%len(rooms)]
					m, err := putTestBlob(s, room, fmt.Sprintf("ip:%d", g%3), 100+i, blobQuota{RoomMaxCount: 30, WriterMaxBytes: 4000})
					if err == nil {
						mu.Lock()
						ids = append(ids, m)
						mu.Unlock()
					}
					mu.Lock()
					if len(ids) > 0 && i%2 == 0 {
						victim := ids[0]
						ids = ids[1:]
						mu.Unlock()
						_, _ = bs.DeleteBlob(bg, victim.Room, victim.ID)
					} else {
						mu.Unlock()
					}
					if i == 7 && g == 0 {
						if rs, ok := s.(roomStore); ok {
							_, _ = rs.PurgeRoom(bg, "c")
						}
					}
					if i%5 == 0 {
						_, _ = bs.PruneExpiredBlobs(bg, time.Now().Unix())
					}
				}
			}(g)
		}
		wg.Wait()
		checkBlobUsage(t, s)
		if ps, ok := s.(*postgresStore); ok {
			var neg int64
			if err := ps.pool.QueryRow(bg, `SELECT count(*) FROM relay_blob_usage WHERE bytes < 0 OR count < 0`).Scan(&neg); err != nil || neg != 0 {
				t.Fatalf("negative usage rows: %d %v", neg, err)
			}
		}
		if ms, ok := s.(*memoryStore); ok {
			ms.mu.RLock()
			defer ms.mu.RUnlock()
			if ms.blobTotal.bytes < 0 || ms.blobTotal.count < 0 {
				t.Fatalf("negative totals %+v", ms.blobTotal)
			}
		}
	})
}

// An expired or revoked-key token can't upload, read or delete; a token
// scoped to another workspace can't either.
func TestHTTPBlobExpiredAndScopedTokens(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", "claims")
	sk := testKey(t)
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	good := issueToken(sk, TokenClaims{Sub: "alice", Exp: uint64(time.Now().Add(time.Hour).Unix()), Workspaces: []string{"a"}})
	expired := issueToken(sk, TokenClaims{Sub: "alice", Exp: uint64(time.Now().Add(-time.Minute).Unix()), Workspaces: []string{"a"}})
	otherWS := issueToken(sk, TokenClaims{Sub: "alice", Exp: uint64(time.Now().Add(time.Hour).Unix()), Workspaces: []string{"b"}})
	seedHTTP(t, ts.URL, "a", good)
	resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/a/blobs", good, []byte("x"))
	var br blobResp
	_ = json.Unmarshal(b, &br)
	if resp.StatusCode != 201 {
		t.Fatalf("upload: %d %s", resp.StatusCode, b)
	}
	for _, c := range []struct {
		tok  string
		want int
	}{{expired, 401}, {otherWS, 403}} {
		for _, m := range []struct{ m, p string }{{"POST", "/v1/workspaces/a/blobs"}, {"GET", "/v1/workspaces/a/blobs/" + br.ID}, {"DELETE", "/v1/workspaces/a/blobs/" + br.ID}} {
			if resp, _ := blobHTTP(t, m.m, ts.URL+m.p, c.tok, []byte("x")); resp.StatusCode != c.want {
				t.Fatalf("%s %s: %d, want %d", m.m, m.p, resp.StatusCode, c.want)
			}
		}
	}
	if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/a/blobs/"+br.ID, good, nil); resp.StatusCode != 200 {
		t.Fatal("blob gone")
	}
}
