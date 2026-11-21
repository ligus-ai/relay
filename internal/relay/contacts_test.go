package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newCID() string      { return randB64(cidRawBytes) }
func newWriteKey() string { return randB64(writeKeyRawBytes) }

func contactTestServer(t *testing.T, o Options) *httptest.Server {
	t.Helper()
	if o.Store == nil {
		o.Store = newMemoryStore()
	}
	if o.Entitlement == nil {
		o.Entitlement = entitlementPolicy{kind: entOpen}
	}
	ts := httptest.NewServer(New(o).Handler())
	t.Cleanup(ts.Close)
	return ts
}

// creq sends a raw request; hdr is "Name: value" pairs.
func creq(t *testing.T, method, url, body string, hdr ...string) (int, http.Header, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hdr {
		k, v, _ := strings.Cut(h, ": ")
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func keyHdr(k string) string { return contactKeyHeader + ": " + k }

func putBody(record, writeKey string) string {
	if writeKey == "" {
		return `{"record":` + record + `}`
	}
	return `{"record":` + record + `,"writeKey":"` + writeKey + `"}`
}

// TestContactWriteKeyRequired (spec S8): the first write sets the key; every
// later write, and delete, needs it.
func TestContactWriteKeyRequired(t *testing.T) {
	ts := contactTestServer(t, Options{})
	cid, key, other := newCID(), newWriteKey(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid

	if st, _, _ := creq(t, "PUT", u, putBody(`{"v":1}`, "")); st != 401 {
		t.Fatalf("create without a key: %d, want 401", st)
	}
	if st, _, _ := creq(t, "PUT", u, putBody(`{"v":1}`, "short")); st != 400 {
		t.Fatalf("create with a malformed key: %d, want 400", st)
	}
	st, _, body := creq(t, "PUT", u, putBody(`{"v":1, "x":"keep  spacing"}`, key))
	if st != 200 || !strings.Contains(body, `"created":true`) {
		t.Fatalf("create: %d %s", st, body)
	}
	// Fetch returns the record byte for byte.
	st, hdr, body := creq(t, "GET", u, "")
	if st != 200 || !strings.HasPrefix(body, `{"record":{"v":1, "x":"keep  spacing"},"updatedAt":`) {
		t.Fatalf("get: %d %s", st, body)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("get: Cache-Control %q", hdr.Get("Cache-Control"))
	}
	// The key hash never leaves the relay.
	if strings.Contains(body, sha256hex(key)) || strings.Contains(body, key) {
		t.Fatal("get leaked the write key or its hash")
	}

	// Update: no key → 401; another key (header or body) → 403; header and body
	// disagreeing → 400; the right key in the header → 200.
	if st, _, _ := creq(t, "PUT", u, putBody(`{"v":2}`, "")); st != 401 {
		t.Fatalf("update without key: %d", st)
	}
	if st, _, _ := creq(t, "PUT", u, putBody(`{"v":2}`, ""), keyHdr(other)); st != 403 {
		t.Fatalf("update with another key: %d", st)
	}
	if st, _, _ := creq(t, "PUT", u, putBody(`{"v":2}`, other)); st != 403 {
		t.Fatalf("squat with another body key: %d", st)
	}
	if st, _, _ := creq(t, "PUT", u, putBody(`{"v":2}`, other), keyHdr(key)); st != 400 {
		t.Fatalf("header/body keys differ: %d", st)
	}
	if st, _, body := creq(t, "PUT", u, putBody(`{"v":2}`, ""), keyHdr(key)); st != 200 || !strings.Contains(body, `"created":false`) {
		t.Fatalf("update: %d %s", st, body)
	}
	if _, _, body := creq(t, "GET", u, ""); !strings.HasPrefix(body, `{"record":{"v":2},`) {
		t.Fatalf("after update: %s", body)
	}

	// Delete: no key 401, wrong key 403, right key 200, then 404 everywhere.
	if st, _, _ := creq(t, "DELETE", u, ""); st != 401 {
		t.Fatalf("delete without key: %d", st)
	}
	if st, _, _ := creq(t, "DELETE", u, "", keyHdr(other)); st != 403 {
		t.Fatalf("delete with another key: %d", st)
	}
	if st, _, _ := creq(t, "DELETE", u, "", keyHdr(key)); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if st, _, _ := creq(t, "GET", u, ""); st != 404 {
		t.Fatalf("get after delete: %d", st)
	}
	if st, _, _ := creq(t, "DELETE", u, "", keyHdr(key)); st != 404 {
		t.Fatalf("second delete: %d", st)
	}
	// After delete the cid is free; a new key owns it.
	if st, _, _ := creq(t, "PUT", u, putBody(`{"v":3}`, other)); st != 200 {
		t.Fatalf("recreate: %d", st)
	}
}

func TestContactIDAndBodyValidation(t *testing.T) {
	ts := contactTestServer(t, Options{})
	key := newWriteKey()
	for _, bad := range []string{
		"short",
		randB64(15),
		randB64(17),
		base64.URLEncoding.EncodeToString(make([]byte, 16)), // padded
		strings.Repeat("A", 22) + "%2F",
	} {
		if st, _, _ := creq(t, "GET", ts.URL+"/v1/contacts/"+bad, ""); st != 400 && st != 404 {
			t.Errorf("cid %q: GET %d, want 400", bad, st)
		}
		if st, _, _ := creq(t, "PUT", ts.URL+"/v1/contacts/"+bad, putBody(`{}`, key)); st != 400 && st != 404 {
			t.Errorf("cid %q: PUT %d, want 400", bad, st)
		}
	}
	u := ts.URL + "/v1/contacts/" + newCID()
	for _, body := range []string{`{"writeKey":"` + key + `"}`, putBody(`null`, key), `{not json`} {
		if st, _, _ := creq(t, "PUT", u, body); st != 400 {
			t.Errorf("PUT %s: %d, want 400", body, st)
		}
	}
	if st, _, _ := creq(t, "GET", ts.URL+"/v1/contacts/"+newCID(), ""); st != 404 {
		t.Errorf("unknown cid: %d, want 404", st)
	}
}

func TestContactSizeCaps(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_CONTACT_MAX_RECORD_BYTES", "1024")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_MAX_DROP_BYTES", "512")
	ts := contactTestServer(t, Options{})
	cid, key := newCID(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid

	fits := `"` + strings.Repeat("a", 1000) + `"`
	if st, _, body := creq(t, "PUT", u, putBody(fits, key)); st != 200 {
		t.Fatalf("record at the cap: %d %s", st, body)
	}
	over := `"` + strings.Repeat("a", 1100) + `"`
	if st, _, _ := creq(t, "PUT", u, putBody(over, ""), keyHdr(key)); st != 413 {
		t.Fatalf("record over the cap: %d, want 413", st)
	}
	huge := `"` + strings.Repeat("a", 64<<10) + `"`
	if st, _, _ := creq(t, "PUT", u, putBody(huge, ""), keyHdr(key)); st != 413 {
		t.Fatalf("record far over the cap: %d, want 413", st)
	}
	if st, _, _ := creq(t, "POST", u+"/drop", `{"blob":"`+strings.Repeat("b", 500)+`"}`); st != 200 {
		t.Fatalf("drop at the cap: %d", st)
	}
	if st, _, _ := creq(t, "POST", u+"/drop", `{"blob":"`+strings.Repeat("b", 600)+`"}`); st != 413 {
		t.Fatalf("drop over the cap: %d, want 413", st)
	}
	if st, _, _ := creq(t, "POST", u+"/drop", `{"blob":null}`); st != 400 {
		t.Fatalf("null drop: %d, want 400", st)
	}
}

// TestContactDropReadNeedsKey (spec S8): anyone may drop; only the key holder
// reads or deletes the box.
func TestContactDropReadNeedsKey(t *testing.T) {
	ts := contactTestServer(t, Options{})
	cid, key := newCID(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid

	// No record → no box.
	if st, _, _ := creq(t, "POST", u+"/drop", `{"blob":"x"}`); st != 404 {
		t.Fatalf("drop to an unknown cid: %d, want 404", st)
	}
	creq(t, "PUT", u, putBody(`{}`, key))
	for i := 1; i <= 3; i++ {
		st, _, body := creq(t, "POST", u+"/drop", `{"blob":{"sealed": "`+strings.Repeat("z", i)+`"}}`)
		if st != 200 || body != `{"ok":true}` {
			t.Fatalf("drop %d: %d %s", i, st, body)
		}
	}
	if st, _, _ := creq(t, "GET", u+"/drop", ""); st != 401 {
		t.Fatalf("read without key: %d", st)
	}
	if st, _, _ := creq(t, "GET", u+"/drop", "", keyHdr(newWriteKey())); st != 403 {
		t.Fatalf("read with another key: %d", st)
	}
	if st, _, _ := creq(t, "DELETE", u+"/drop?through=9", "", keyHdr(newWriteKey())); st != 403 {
		t.Fatalf("ack with another key: %d", st)
	}
	st, _, body := creq(t, "GET", u+"/drop?after=0", "", keyHdr(key))
	var page struct {
		Items []ContactDrop `json:"items"`
		More  bool          `json:"more"`
	}
	if st != 200 || json.Unmarshal([]byte(body), &page) != nil || len(page.Items) != 3 || page.More {
		t.Fatalf("read: %d %s", st, body)
	}
	// Seqs are consecutive from the box's base (contactSeqBase).
	b := page.Items[0].Seq - 1
	sq := func(n uint64) string { return strconv.FormatUint(b+n, 10) }
	if page.Items[0].Seq == 0 || page.Items[2].Seq != b+3 || string(page.Items[2].Blob) != `{"sealed": "zzz"}` || page.Items[0].CreatedAt == 0 {
		t.Fatalf("items: %+v", page.Items)
	}
	// Cursor + paging.
	_, _, body = creq(t, "GET", u+"/drop?after="+sq(1)+"&limit=1", "", keyHdr(key))
	if !strings.HasPrefix(body, `{"items":[{"seq":`+sq(2)+`,`) || !strings.Contains(body, `"more":true`) {
		t.Fatalf("after=1 limit=1: %s", body)
	}
	// Reading is non-destructive; ack deletes through a seq.
	if st, _, _ := creq(t, "DELETE", u+"/drop", "", keyHdr(key)); st != 400 {
		t.Fatalf("ack without through: %d", st)
	}
	if st, _, body := creq(t, "DELETE", u+"/drop?through="+sq(2), "", keyHdr(key)); st != 200 || body != `{"deleted":2,"ok":true}` {
		t.Fatalf("ack: %d %s", st, body)
	}
	_, _, body = creq(t, "GET", u+"/drop", "", keyHdr(key))
	if !strings.HasPrefix(body, `{"items":[{"seq":`+sq(3)+`,`) || strings.Count(body, `"seq"`) != 1 {
		t.Fatalf("after ack: %s", body)
	}
	// Deleting the record deletes the box.
	creq(t, "DELETE", u, "", keyHdr(key))
	newKey := newWriteKey()
	creq(t, "PUT", u, putBody(`{}`, newKey))
	if _, _, body := creq(t, "GET", u+"/drop", "", keyHdr(newKey)); body != `{"items":[],"more":false}` {
		t.Fatalf("box survived its record: %s", body)
	}
}

func TestContactDropBoxBounds(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_MAX_ROWS", "5")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_MAX_BOX_BYTES", "100")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_RATE", "0")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_CID_RATE", "0")
	ts := contactTestServer(t, Options{})
	cid, key := newCID(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid
	creq(t, "PUT", u, putBody(`{}`, key))

	// Row cap: 8 tiny drops keep the newest 5.
	for i := 0; i < 8; i++ {
		creq(t, "POST", u+"/drop", `{"blob":1}`)
	}
	_, _, body := creq(t, "GET", u+"/drop", "", keyHdr(key))
	var first struct {
		Items []ContactDrop `json:"items"`
	}
	if json.Unmarshal([]byte(body), &first) != nil || len(first.Items) == 0 {
		t.Fatalf("row cap: %s", body)
	}
	b := first.Items[0].Seq - 4 // the box's base: drop i has seq b+i
	sq := func(n uint64) string { return strconv.FormatUint(b+n, 10) }
	if strings.Count(body, `"seq"`) != 5 || !strings.HasPrefix(body, `{"items":[{"seq":`+sq(4)+`,`) {
		t.Fatalf("row cap: %s", body)
	}
	// Byte cap: 40-byte blobs, 100-byte box → newest 2 remain.
	for i := 0; i < 3; i++ {
		creq(t, "POST", u+"/drop", `{"blob":"`+strings.Repeat("q", 38)+`"}`)
	}
	_, _, body = creq(t, "GET", u+"/drop", "", keyHdr(key))
	if strings.Count(body, `"seq"`) != 2 || !strings.HasPrefix(body, `{"items":[{"seq":`+sq(10)+`,`) {
		t.Fatalf("byte cap: %s", body)
	}
}

// TestContactDropRateLimit (spec S8): drops are limited per (sender, box) with
// the account-invite defaults, and per box across senders.
func TestContactDropRateLimit(t *testing.T) {
	ts := contactTestServer(t, Options{})
	cid, key := newCID(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid
	creq(t, "PUT", u, putBody(`{}`, key))
	ok, limited := 0, 0
	for i := 0; i < 15; i++ {
		switch st, _, _ := creq(t, "POST", u+"/drop", `{"blob":"x"}`); st {
		case 200:
			ok++
		case 429:
			limited++
		default:
			t.Fatalf("drop: %d", st)
		}
	}
	if ok != int(defaultInviteBurst) || limited != 15-ok {
		t.Fatalf("per-sender drop limit: ok=%d limited=%d, want burst %v", ok, limited, defaultInviteBurst)
	}
	// Another box from the same sender is a separate bucket.
	cid2 := newCID()
	creq(t, "PUT", ts.URL+"/v1/contacts/"+cid2, putBody(`{}`, newWriteKey()))
	if st, _, _ := creq(t, "POST", ts.URL+"/v1/contacts/"+cid2+"/drop", `{"blob":"x"}`); st != 200 {
		t.Fatalf("other box: %d", st)
	}

	// Per-box cap across senders.
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_RATE", "0")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_CID_RATE", "0.001")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_CID_BURST", "3")
	ts2 := contactTestServer(t, Options{})
	u2 := ts2.URL + "/v1/contacts/" + cid
	creq(t, "PUT", u2, putBody(`{}`, key))
	for i := 0; i < 3; i++ {
		if st, _, _ := creq(t, "POST", u2+"/drop", `{"blob":"x"}`); st != 200 {
			t.Fatalf("drop %d: %d", i, st)
		}
	}
	if st, _, _ := creq(t, "POST", u2+"/drop", `{"blob":"x"}`); st != 429 {
		t.Fatalf("per-box limit: %d, want 429", st)
	}
}

func TestContactWriteAndCreateRateLimits(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_CONTACT_CREATE_RATE", "0.001")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_CREATE_BURST", "2")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_WRITE_RATE", "0.001")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_WRITE_BURST", "2")
	ts := contactTestServer(t, Options{})
	key := newWriteKey()
	cids := []string{newCID(), newCID(), newCID()}
	for i, cid := range cids {
		want := 200
		if i == 2 {
			want = 429
		}
		if st, _, _ := creq(t, "PUT", ts.URL+"/v1/contacts/"+cid, putBody(`{}`, key)); st != want {
			t.Fatalf("create %d: %d, want %d", i, st, want)
		}
	}
	u := ts.URL + "/v1/contacts/" + cids[0]
	// A stranger's wrong-key attempts never spend the owner's write budget.
	for i := 0; i < 5; i++ {
		if st, _, _ := creq(t, "PUT", u, putBody(`{}`, ""), keyHdr(newWriteKey())); st != 403 {
			t.Fatalf("stranger update: %d", st)
		}
	}
	for i := 0; i < 2; i++ {
		if st, _, _ := creq(t, "PUT", u, putBody(`{}`, ""), keyHdr(key)); st != 200 {
			t.Fatalf("owner update %d: %d", i, st)
		}
	}
	if st, _, _ := creq(t, "PUT", u, putBody(`{}`, ""), keyHdr(key)); st != 429 {
		t.Fatalf("owner update past the limit: %d, want 429", st)
	}
}

// No forge token is ever accepted on the contacts routes: carrying one is
// refused, it never substitutes for the contact key, and it never reaches the
// GitHub verifier.
func TestContactRoutesRefuseForgeTokens(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}, GitHubRoutes: true})
	called := 0
	srv.verify = func(context.Context, string) (*githubUser, error) {
		called++
		return &githubUser{ID: 1, Login: "alice"}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	cid, key := newCID(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid
	creq(t, "PUT", u, putBody(`{}`, key))
	creq(t, "POST", u+"/drop", `{"blob":"x"}`)

	forge := []string{
		"X-Hive-Github-Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"X-Ligus-Github-Token: gho_abcdefghijklmnopqrstuvwxyz",
		"X-Ligus-Gitlab-Token: glpat-xxxxxxxxxxxxxxxxxxxx",
		"X-Ligus-Forge-Token: whatever-token",
		"Authorization: Bearer github_pat_11AAAAAAA0abcdefghijkl",
		"Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	}
	routes := []struct{ method, path, body string }{
		{"PUT", "", putBody(`{"v":9}`, "")},
		{"GET", "", ""},
		{"DELETE", "", ""},
		{"POST", "/drop", `{"blob":"x"}`},
		{"GET", "/drop", ""},
		{"DELETE", "/drop?through=1", ""},
	}
	for _, f := range forge {
		for _, rt := range routes {
			// Even alongside the right contact key, a forge token is refused.
			st, _, body := creq(t, rt.method, u+rt.path, rt.body, f, keyHdr(key))
			if st != 400 || !strings.Contains(body, "forge tokens are not accepted") {
				t.Errorf("%s %s with %q: %d %s", rt.method, rt.path, strings.SplitN(f, ":", 2)[0], st, body)
			}
			if strings.Contains(body, "ghp_") || strings.Contains(body, "glpat") {
				t.Errorf("response echoed the token")
			}
		}
	}
	// A forge token alone never stands in for the contact key.
	if st, _, _ := creq(t, "GET", u+"/drop", ""); st != 401 {
		t.Fatalf("drop read without key: %d", st)
	}
	if called != 0 {
		t.Fatalf("contacts routes reached the GitHub verifier %d times", called)
	}
	// Nothing changed: the record is intact.
	if _, _, body := creq(t, "GET", u, ""); !strings.HasPrefix(body, `{"record":{},`) {
		t.Fatalf("record changed: %s", body)
	}
}

func TestContactRoutesBehindEntitlementGate(t *testing.T) {
	ts := contactTestServer(t, Options{Entitlement: entitlementPolicy{kind: entTokens, tokenHashes: []string{sha256hex("good")}}})
	u := ts.URL + "/v1/contacts/" + newCID()
	if st, _, _ := creq(t, "GET", u, ""); st != 401 {
		t.Fatalf("no relay token: %d, want 401", st)
	}
	if st, _, _ := creq(t, "PUT", u, putBody(`{}`, newWriteKey()), "Authorization: Bearer good"); st != 200 {
		t.Fatalf("with relay token: %d", st)
	}
}

func TestContactExpiry(t *testing.T) {
	ms := newMemoryStore()
	ctx := context.Background()
	kh := sha256hex(newWriteKey())
	cid := newCID()
	if _, err := ms.PutContact(ctx, cid, kh, raw(`{}`), 100, 200, ContactLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.AppendContactDrop(ctx, cid, raw(`"x"`), 150, ContactLimits{}); err != nil {
		t.Fatal(err)
	}
	if r, _ := ms.GetContact(ctx, cid, 199); r == nil {
		t.Fatal("live record hidden")
	}
	if r, _ := ms.GetContact(ctx, cid, 200); r != nil {
		t.Fatal("expired record served")
	}
	if _, err := ms.AppendContactDrop(ctx, cid, raw(`"x"`), 201, ContactLimits{}); err != ErrContactNotFound {
		t.Fatalf("drop to expired: %v", err)
	}
	// An expired cid is free again, with an empty box.
	kh2 := sha256hex(newWriteKey())
	if created, err := ms.PutContact(ctx, cid, kh2, raw(`{}`), 300, 400, ContactLimits{}); err != nil || !created {
		t.Fatalf("reclaim: %v %v", created, err)
	}
	if items, _, _ := ms.ContactDropsAfter(ctx, cid, kh2, 0, 0, 0, 300); len(items) != 0 {
		t.Fatalf("old drops survived: %+v", items)
	}
}

// The relay sets TTL from LANGSTROTH_RELAY_CONTACT_TTL_DAYS and refreshes it on
// every update.
func TestContactTTLFromEnv(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_CONTACT_TTL_DAYS", "2")
	ts := contactTestServer(t, Options{})
	_, _, body := creq(t, "PUT", ts.URL+"/v1/contacts/"+newCID(), putBody(`{}`, newWriteKey()))
	var r struct{ UpdatedAt, ExpiresAt int64 }
	if err := json.Unmarshal([]byte(body), &r); err != nil || r.ExpiresAt-r.UpdatedAt != 2*86400 {
		t.Fatalf("ttl: %s", body)
	}
}

func TestContactCapacityAndStoreBudget(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_CONTACTS", "2")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_CREATE_RATE", "0")
	ts := contactTestServer(t, Options{})
	for i, want := range []int{200, 200, 507} {
		if st, _, _ := creq(t, "PUT", ts.URL+"/v1/contacts/"+newCID(), putBody(`{}`, newWriteKey())); st != want {
			t.Fatalf("create %d: %d, want %d", i, st, want)
		}
	}

	// Memory store byte budget covers records and drops, and frees on delete.
	ms := newMemoryStore()
	ms.maxStoreBytes = 2000
	ctx := context.Background()
	kh := sha256hex(newWriteKey())
	cid := newCID()
	if _, err := ms.PutContact(ctx, cid, kh, raw(`"`+strings.Repeat("a", 1000)+`"`), 1, 1e12, ContactLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.AppendContactDrop(ctx, cid, raw(`"`+strings.Repeat("b", 900)+`"`), 1, ContactLimits{}); err != ErrStoreFull {
		t.Fatalf("drop past the budget: %v", err)
	}
	if err := ms.DeleteContact(ctx, cid, kh, 1); err != nil {
		t.Fatal(err)
	}
	if ms.storeBytes != 0 {
		t.Fatalf("budget not released: %d", ms.storeBytes)
	}
}

func TestContactSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := newMemoryStoreWithPersistence(dir)
	kh := sha256hex(newWriteKey())
	cid := newCID()
	if _, err := s.PutContact(ctx, cid, kh, raw(`{"a":  1}`), 10, 1e12, ContactLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendContactDrop(ctx, cid, raw(`"sealed"`), 11, ContactLimits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, snapshotFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode: %v %v", info, err)
	}
	r := newMemoryStoreWithPersistence(dir)
	rec, _ := r.GetContact(ctx, cid, 12)
	if rec == nil || string(rec.Record) != `{"a":  1}` || rec.WriteKeyHash != kh {
		t.Fatalf("record after restore: %+v", rec)
	}
	items, _, err := r.ContactDropsAfter(ctx, cid, kh, 0, 0, 0, 12)
	if err != nil || len(items) != 1 || string(items[0].Blob) != `"sealed"` {
		t.Fatalf("drops after restore: %+v %v", items, err)
	}
	if seq, _ := r.AppendContactDrop(ctx, cid, raw(`"n"`), 13, ContactLimits{}); seq != items[0].Seq+1 {
		t.Fatalf("seq after restore: %d", seq)
	}
	if r.storeBytes != s.storeBytes+3 {
		t.Fatalf("budget after restore: %d vs %d", r.storeBytes, s.storeBytes)
	}
}

func TestContactPrune(t *testing.T) {
	ms := newMemoryStore()
	ctx := context.Background()
	kh := sha256hex(newWriteKey())
	live, dead := newCID(), newCID()
	ms.PutContact(ctx, live, kh, raw(`{}`), 0, 1e12, ContactLimits{})
	ms.PutContact(ctx, dead, kh, raw(`{}`), 0, 50, ContactLimits{})
	ms.AppendContactDrop(ctx, live, raw(`"old"`), 10, ContactLimits{})
	ms.AppendContactDrop(ctx, live, raw(`"new"`), 90, ContactLimits{})
	n, err := ms.PruneContacts(ctx, 100, 50*time.Second, 0)
	if err != nil || n != 2 { // the expired record + the drop older than 50 s
		t.Fatalf("prune: %d %v", n, err)
	}
	if ms.contactCount() != 1 {
		t.Fatalf("expired record kept")
	}
	items, _, _ := ms.ContactDropsAfter(ctx, live, kh, 0, 0, 0, 100)
	if len(items) != 1 || string(items[0].Blob) != `"new"` {
		t.Fatalf("drops after prune: %+v", items)
	}
}

func TestContactsOffAndStoreWithoutContacts(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_CONTACTS", "off")
	ts := contactTestServer(t, Options{})
	if st, _, _ := creq(t, "GET", ts.URL+"/v1/contacts/"+newCID(), ""); st != 404 {
		t.Fatalf("contacts off: %d, want 404", st)
	}
	t.Setenv("LANGSTROTH_RELAY_CONTACTS", "")
	// A downstream Store that doesn't implement ContactStore → 404, as on v0.2.
	ts2 := contactTestServer(t, Options{Store: storeOnly{newMemoryStore()}})
	if st, _, _ := creq(t, "GET", ts2.URL+"/v1/contacts/"+newCID(), ""); st != 404 {
		t.Fatalf("store without contacts: %d, want 404", st)
	}
}

// storeOnly hides every optional interface of the wrapped store.
type storeOnly struct{ Store }

// TestContactRoutesAdditive (spec S8): the existing routes' answers are
// unchanged by the contact routes (the byte-level check is
// TestExistingRoutesMatchGolden).
func TestContactRoutesAdditive(t *testing.T) {
	ts := contactTestServer(t, Options{})
	ws := ts.URL + "/v1/workspaces/w1/envelopes"
	if st, _, body := creq(t, "POST", ws, `{"ct":"A"}`); st != 200 || body != `{"seq":1}` {
		t.Fatalf("envelope append changed: %d %s", st, body)
	}
	creq(t, "PUT", ts.URL+"/v1/contacts/"+newCID(), putBody(`{}`, newWriteKey()))
	if st, _, body := creq(t, "GET", ws, ""); st != 200 || body != `[{"seq":1,"body":{"ct":"A"}}]` {
		t.Fatalf("envelope list changed: %d %s", st, body)
	}
}

// ── GitHub routes (deprecated, off by default) ───────────────────────────────

var githubRouteSamples = []struct{ method, path string }{
	{"POST", "/v1/directory/register"},
	{"GET", "/v1/directory/alice"},
	{"POST", "/v1/account/register"},
	{"POST", "/v1/account/heartbeat"},
	{"GET", "/v1/account/inbox"},
	{"GET", "/v1/account/devices"},
	{"POST", "/v1/account/visibility"},
	{"POST", "/v1/account/invites"},
	{"GET", "/v1/friends"},
	{"GET", "/v1/friends/presence"},
	{"GET", "/v1/friends/github:2/devices"},
	{"DELETE", "/v1/friends/github:2"},
	{"POST", "/v1/friends/requests"},
	{"GET", "/v1/friends/requests"},
	{"POST", "/v1/friends/requests/x/accept"},
	{"POST", "/v1/friends/requests/x/reject"},
}

func TestGitHubRoutesOffByDefault(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_GITHUB_ROUTES", "")
	t.Setenv("LANGSTROTH_RELAY_GITHUB_SOCIAL", "")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	called := 0
	srv.verify = func(context.Context, string) (*githubUser, error) {
		called++
		return &githubUser{ID: 1, Login: "a"}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for _, rt := range githubRouteSamples {
		st, hdr, _ := creq(t, rt.method, ts.URL+rt.path, `{"deviceId":"d","toLogin":"b"}`, "X-Hive-Github-Token: tok:alice:1")
		if st != 404 {
			t.Errorf("%s %s: %d, want 404", rt.method, rt.path, st)
		}
		if hdr.Get("Deprecation") != "" {
			t.Errorf("%s %s: deprecation header on a 404", rt.method, rt.path)
		}
	}
	if called != 0 {
		t.Fatalf("GitHub verifier called %d times with the routes off", called)
	}
}

func TestGitHubRoutesEnabledByEnv(t *testing.T) {
	for _, env := range []struct{ name, val string }{
		{"LANGSTROTH_RELAY_GITHUB_ROUTES", "on"},
		{"LANGSTROTH_RELAY_GITHUB_ROUTES", "1"},
		{"LANGSTROTH_RELAY_GITHUB_SOCIAL", "1"},
	} {
		t.Run(env.name, func(t *testing.T) {
			t.Setenv(env.name, env.val)
			srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
			srv.verify = func(context.Context, string) (*githubUser, error) { return &githubUser{ID: 1, Login: "alice"}, nil }
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			st, hdr, body := creq(t, "POST", ts.URL+"/v1/account/register", `{"deviceId":"d1"}`, "X-Hive-Github-Token: tok:alice:1")
			if st != 200 || body != `{"accountId":"github:1","githubId":1,"login":"alice"}` {
				t.Fatalf("register: %d %s", st, body)
			}
			if hdr.Get("Deprecation") != githubRoutesDeprecatedAt || !strings.Contains(hdr.Get("Link"), `rel="deprecation"`) {
				t.Fatalf("deprecation headers: %v", hdr)
			}
			// Every GitHub route answers (not 404) and is marked deprecated.
			for _, rt := range githubRouteSamples {
				st, hdr, _ := creq(t, rt.method, ts.URL+rt.path, `{}`, "X-Hive-Github-Token: tok:alice:1")
				if st == 404 && hdr.Get("Deprecation") == "" {
					t.Errorf("%s %s: unregistered with the routes on", rt.method, rt.path)
				}
				if hdr.Get("Deprecation") == "" {
					t.Errorf("%s %s: no deprecation header", rt.method, rt.path)
				}
			}
			// Non-GitHub routes carry no deprecation header.
			if _, hdr, _ := creq(t, "GET", ts.URL+"/v1/health", ""); hdr.Get("Deprecation") != "" {
				t.Fatal("health marked deprecated")
			}
		})
	}
}

// Records and blobs must be valid UTF-8. The relay promises them back byte
// for byte, but the JSON snapshot rewrites invalid UTF-8 to U+FFFD on restart
// (a signed record then stops verifying) and Postgres TEXT refuses it (500 and
// an error log per request). Refuse it up front on every store.
func TestContactRejectsInvalidUTF8(t *testing.T) {
	ts := contactTestServer(t, Options{})
	cid, key := newCID(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid
	if st, _, body := creq(t, "PUT", u, putBody("{\"sig\":\"a\xffb\"}", key)); st != 400 {
		t.Fatalf("record with invalid UTF-8: %d %s, want 400", st, body)
	}
	if st, _, _ := creq(t, "PUT", u, putBody(`{"sig":"ok é"}`, key)); st != 200 {
		t.Fatalf("valid record: %d", st)
	}
	if st, _, body := creq(t, "POST", u+"/drop", "{\"blob\":\"\xc3\"}"); st != 400 {
		t.Fatalf("drop with invalid UTF-8: %d %s, want 400", st, body)
	}
	if _, _, body := creq(t, "GET", u+"/drop", "", keyHdr(key)); body != `{"items":[],"more":false}` {
		t.Fatalf("invalid drop stored: %q", body)
	}
}

// An IPv6 client is keyed by its /64, but one /48 (a free tunnel-broker
// allocation) holds 65536 of them. With only the /64 key, one /48 could create
// 65536 x burst records at once: enough to fill the memory store's
// LANGSTROTH_RELAY_MAX_CONTACTS for every user, or a Postgres disk. Creates are
// also limited per /48.
func TestContactCreateLimitedPerIPv6Slash48(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_CONTACT_CREATE_RATE", "0.001")
	t.Setenv("LANGSTROTH_RELAY_CONTACT_CREATE_BURST", "2")
	h := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}}).Handler()
	put := func(remote string) int {
		req := httptest.NewRequest("PUT", "/v1/contacts/"+newCID(), strings.NewReader(putBody(`{}`, newWriteKey())))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	ok := 0
	for i := 0; i < 200; i++ {
		if put(fmt.Sprintf("[2001:db8:1:%x::1]:4000", i)) == 200 {
			ok++
		}
	}
	// 2 per /64 alone would admit 200; the /48 bucket (16x the burst) caps it.
	if ok > 32 {
		t.Fatalf("one /48 created %d records by rotating its /64s", ok)
	}
	// Another /48, and IPv4 clients, keep their own budget.
	if st := put("[2001:db8:2::1]:4000"); st != 200 {
		t.Fatalf("another /48: %d", st)
	}
	if st := put("192.0.2.7:4000"); st != 200 {
		t.Fatalf("ipv4 client: %d", st)
	}
}

// Reclaim-hold tombstones (an expired record's key hash) don't count toward
// LANGSTROTH_RELAY_MAX_CONTACTS: they hold no record or drops, and counting them
// would cut the store's capacity to live records by every record that expired
// in the last hold period.
func TestContactTombstonesOutsideMaxContacts(t *testing.T) {
	ms := newMemoryStore()
	ctx := context.Background()
	hold := 1000 * time.Second
	lim := ContactLimits{MaxContacts: 2, ReclaimHold: hold}
	kh := sha256hex(newWriteKey())
	a, b := newCID(), newCID()
	ms.PutContact(ctx, a, kh, raw(`{}`), 0, 50, lim)
	ms.PutContact(ctx, b, kh, raw(`{}`), 0, 50, lim)
	if _, err := ms.PutContact(ctx, newCID(), kh, raw(`{}`), 10, 500, lim); err != ErrContactsFull {
		t.Fatalf("cap with two live records: %v", err)
	}
	if _, err := ms.PruneContacts(ctx, 100, 0, hold); err != nil {
		t.Fatal(err)
	}
	if ms.contactCount() != 2 {
		t.Fatalf("tombstones: %d, want 2", ms.contactCount())
	}
	c := newCID()
	if _, err := ms.PutContact(ctx, c, kh, raw(`{}`), 101, 500, lim); err != nil {
		t.Fatalf("create with only tombstones held: %v", err)
	}
	// The owner reclaiming a tombstone makes it live again and counts.
	if _, err := ms.PutContact(ctx, a, kh, raw(`{}`), 102, 500, lim); err != nil {
		t.Fatalf("owner reclaim: %v", err)
	}
	if _, err := ms.PutContact(ctx, newCID(), kh, raw(`{}`), 103, 500, lim); err != ErrContactsFull {
		t.Fatalf("cap after reclaim: %v", err)
	}
}

// TestContactDropFloodKeepsUnreadInvites (R6): a handful of IPs that know a
// cid can fill the drop box within the default rate limits. Eviction takes
// from the heaviest sender first, so the flood evicts the flood and an unread
// invite from another sender survives it.
func TestContactDropFloodKeepsUnreadInvites(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_CONTACT_DROP_MAX_BOX_BYTES", "16384")
	h := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}}).Handler()
	do := func(method, path, remote, body string, hdr ...string) (int, string) {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.RemoteAddr = remote
		for _, kv := range hdr {
			k, v, _ := strings.Cut(kv, ": ")
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	cid, key := newCID(), newWriteKey()
	u := "/v1/contacts/" + cid
	if st, body := do("PUT", u, "198.51.100.1:1000", putBody(`{}`, key)); st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}
	if st, _ := do("POST", u+"/drop", "192.0.2.10:1000", `{"blob":"real-invite"}`); st != 200 {
		t.Fatalf("invite drop: %d", st)
	}
	flood := `{"blob":"` + strings.Repeat("f", 1000) + `"}`
	accepted := 0
	for ip := 1; ip <= 6; ip++ {
		for i := 0; i < 20; i++ {
			if st, _ := do("POST", u+"/drop", fmt.Sprintf("203.0.113.%d:1000", ip), flood); st == 200 {
				accepted++
			}
		}
	}
	if accepted*1000 <= 16384 {
		t.Fatalf("flood too small to test eviction: %d drops accepted", accepted)
	}
	st, body := do("GET", u+"/drop?limit=1000", "198.51.100.1:1000", "", keyHdr(key))
	if st != 200 {
		t.Fatalf("list: %d %s", st, body)
	}
	if !strings.Contains(body, `"blob":"real-invite"`) {
		t.Fatalf("the flood (%d drops from 6 IPs) evicted the unread invite: %d items", accepted, strings.Count(body, `"seq"`))
	}
}
