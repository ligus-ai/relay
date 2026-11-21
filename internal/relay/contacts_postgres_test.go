package relay

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// contactStoreConformance checks ContactStore semantics; it runs against the
// memory store always and against Postgres when TEST_DATABASE_URL is set.
func contactStoreConformance(t *testing.T, cs ContactStore) {
	ctx := context.Background()
	kh, other := sha256hex(newWriteKey()), sha256hex(newWriteKey())
	cid := newCID()
	lim := ContactLimits{DropMaxRows: 3, DropMaxBoxBytes: 20}

	if r, err := cs.GetContact(ctx, cid, 10); err != nil || r != nil {
		t.Fatalf("get unknown: %v %v", r, err)
	}
	if created, err := cs.PutContact(ctx, cid, kh, raw(`{"a":  1}`), 10, 1000, lim); err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if _, err := cs.PutContact(ctx, cid, other, raw(`{}`), 11, 1000, lim); err != ErrContactKey {
		t.Fatalf("squat: %v", err)
	}
	if created, err := cs.PutContact(ctx, cid, kh, raw(`{"a":  2}`), 12, 1012, lim); err != nil || created {
		t.Fatalf("update: %v %v", created, err)
	}
	r, err := cs.GetContact(ctx, cid, 13)
	if err != nil || r == nil || string(r.Record) != `{"a":  2}` || r.UpdatedAt != 12 || r.ExpiresAt != 1012 || r.WriteKeyHash != kh {
		t.Fatalf("get: %+v %v", r, err)
	}

	// Drops: row cap 3, byte cap 20 (blobs of 6 bytes → 3 fit). Seqs count up
	// from the box's base, contactSeqBase(creation time).
	b := contactSeqBase(10)
	for i := 0; i < 5; i++ {
		seq, err := cs.AppendContactDrop(ctx, cid, raw(`"abcd"`), int64(20+i), lim)
		if err != nil || seq != b+uint64(i+1) {
			t.Fatalf("drop %d: %d %v", i, seq, err)
		}
	}
	items, more, err := cs.ContactDropsAfter(ctx, cid, kh, 0, 0, 0, 30)
	if err != nil || more || len(items) != 3 || items[0].Seq != b+3 || string(items[2].Blob) != `"abcd"` || items[2].CreatedAt != 24 {
		t.Fatalf("drops after cap: %+v %v %v", items, more, err)
	}
	if _, err := cs.AppendContactDrop(ctx, cid, raw(`"0123456789012"`), 25, lim); err != nil { // 15 bytes
		t.Fatal(err)
	}
	items, _, _ = cs.ContactDropsAfter(ctx, cid, kh, 0, 0, 0, 30)
	if len(items) != 1 || items[0].Seq != b+6 {
		t.Fatalf("byte cap: %+v", items)
	}
	cs.AppendContactDrop(ctx, cid, raw(`"x"`), 26, lim)
	items, more, _ = cs.ContactDropsAfter(ctx, cid, kh, 0, 1, 0, 30)
	if len(items) != 1 || !more {
		t.Fatalf("paging: %+v %v", items, more)
	}
	if _, _, err := cs.ContactDropsAfter(ctx, cid, other, 0, 0, 0, 30); err != ErrContactKey {
		t.Fatalf("read with another key: %v", err)
	}
	if _, err := cs.AckContactDrops(ctx, cid, other, 99, 30); err != ErrContactKey {
		t.Fatalf("ack with another key: %v", err)
	}
	if n, err := cs.AckContactDrops(ctx, cid, kh, b+6, 30); err != nil || n != 1 {
		t.Fatalf("ack: %d %v", n, err)
	}
	items, _, _ = cs.ContactDropsAfter(ctx, cid, kh, 0, 0, 0, 30)
	if len(items) != 1 || items[0].Seq != b+7 {
		t.Fatalf("after ack: %+v", items)
	}

	// Delete needs the key and removes the box.
	if err := cs.DeleteContact(ctx, cid, other, 30); err != ErrContactKey {
		t.Fatalf("delete with another key: %v", err)
	}
	if err := cs.DeleteContact(ctx, cid, kh, 30); err != nil {
		t.Fatal(err)
	}
	if err := cs.DeleteContact(ctx, cid, kh, 30); err != ErrContactNotFound {
		t.Fatalf("second delete: %v", err)
	}
	if _, err := cs.AppendContactDrop(ctx, cid, raw(`1`), 31, lim); err != ErrContactNotFound {
		t.Fatalf("drop after delete: %v", err)
	}
	cs.PutContact(ctx, cid, other, raw(`{}`), 32, 1000, lim)
	if seq, _ := cs.AppendContactDrop(ctx, cid, raw(`1`), 33, lim); seq != contactSeqBase(32)+1 {
		t.Fatalf("seq after recreate: %d", seq)
	}

	// Expiry frees the cid; prune removes expired records and old drops.
	exp := newCID()
	cs.PutContact(ctx, exp, kh, raw(`{}`), 0, 50, lim)
	cs.AppendContactDrop(ctx, exp, raw(`1`), 1, lim)
	if r, _ := cs.GetContact(ctx, exp, 50); r != nil {
		t.Fatal("expired record served")
	}
	if created, err := cs.PutContact(ctx, exp, other, raw(`{}`), 60, 2000, lim); err != nil || !created {
		t.Fatalf("reclaim expired: %v %v", created, err)
	}
	if items, _, _ := cs.ContactDropsAfter(ctx, exp, other, 0, 0, 0, 61); len(items) != 0 {
		t.Fatalf("expired box survived: %+v", items)
	}
	gone := newCID()
	cs.PutContact(ctx, gone, kh, raw(`{}`), 0, 70, lim)
	n, err := cs.PruneContacts(ctx, 100, 0, 0)
	if err != nil || n < 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if r, _ := cs.GetContact(ctx, gone, 0); r != nil {
		t.Fatal("pruned record still present")
	}
	// Age-based drop retention.
	cs.AppendContactDrop(ctx, exp, raw(`"old"`), 100, lim)
	cs.AppendContactDrop(ctx, exp, raw(`"new"`), 500, lim)
	if _, err := cs.PruneContacts(ctx, 600, 200*time.Second, 0); err != nil {
		t.Fatal(err)
	}
	items, _, _ = cs.ContactDropsAfter(ctx, exp, other, 0, 0, 0, 600)
	if len(items) != 1 || string(items[0].Blob) != `"new"` {
		t.Fatalf("age prune: %+v", items)
	}
}

func TestContactStoreMemory(t *testing.T) { contactStoreConformance(t, newMemoryStore()) }

func TestPG_ContactStore(t *testing.T) {
	s := pgStore(t)
	if _, err := s.pool.Exec(bg, `TRUNCATE relay_contacts, relay_contact_drop`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(bg, `DELETE FROM relay_seq WHERE scope LIKE 'cdrop:%'`); err != nil {
		t.Fatal(err)
	}
	contactStoreConformance(t, s)
}

// Over HTTP on Postgres: records and blobs come back byte for byte.
func TestPG_ContactRoutesByteExact(t *testing.T) {
	s := pgStore(t)
	ts := contactTestServer(t, Options{Store: s})
	cid, key := newCID(), newWriteKey()
	u := ts.URL + "/v1/contacts/" + cid
	if st, _, body := creq(t, "PUT", u, putBody(`{"v": 1,  "s":"x"}`, key)); st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}
	if _, _, body := creq(t, "GET", u, ""); !strings.HasPrefix(body, `{"record":{"v": 1,  "s":"x"},"updatedAt":`) {
		t.Fatalf("get: %s", body)
	}
	creq(t, "POST", u+"/drop", `{"blob":{"c": "t"}}`)
	if _, _, body := creq(t, "GET", u+"/drop", "", keyHdr(key)); !strings.Contains(body, `"blob":{"c": "t"}`) {
		t.Fatalf("drop list: %s", body)
	}
}

// contactSeqMonotonicConformance: a drop-box seq never repeats for a cid, even
// when the record is deleted or expires and is created again. Several devices
// of one account read the box with their own after= cursors and ack with
// through=; a seq that restarts at 1 hides new drops from a device whose cursor
// is past them and lets its stale ack delete drops nobody has read.
func contactSeqMonotonicConformance(t *testing.T, cs ContactStore) {
	ctx := context.Background()
	kh := sha256hex(newWriteKey())
	cid := newCID()
	lim := ContactLimits{}
	if _, err := cs.PutContact(ctx, cid, kh, raw(`{}`), 1000, 5000, lim); err != nil {
		t.Fatal(err)
	}
	var last uint64
	for i := 0; i < 3; i++ {
		seq, err := cs.AppendContactDrop(ctx, cid, raw(`"a"`), 1001, lim)
		if err != nil {
			t.Fatal(err)
		}
		last = seq
	}
	cursor := last // device B has read everything so far

	// Delete and create again (a later second): seq continues past the cursor.
	if err := cs.DeleteContact(ctx, cid, kh, 1002); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.PutContact(ctx, cid, kh, raw(`{}`), 2000, 5000, lim); err != nil {
		t.Fatal(err)
	}
	seq, err := cs.AppendContactDrop(ctx, cid, raw(`"new"`), 2001, lim)
	if err != nil {
		t.Fatal(err)
	}
	if seq <= cursor {
		t.Fatalf("seq restarted after delete: %d <= cursor %d", seq, cursor)
	}
	if n, err := cs.AckContactDrops(ctx, cid, kh, cursor, 2002); err != nil || n != 0 {
		t.Fatalf("stale ack deleted unread drops: %d %v", n, err)
	}
	items, _, err := cs.ContactDropsAfter(ctx, cid, kh, cursor, 0, 0, 2003)
	if err != nil || len(items) != 1 || items[0].Seq != seq {
		t.Fatalf("new drop hidden from a device past the old seq: %+v %v", items, err)
	}
	cursor = seq

	// Expiry, then the owner's next heartbeat creates the record again.
	if _, err := cs.PutContact(ctx, cid, kh, raw(`{}`), 6000, 9000, lim); err != nil {
		t.Fatal(err)
	}
	seq, err = cs.AppendContactDrop(ctx, cid, raw(`"after-expiry"`), 6001, lim)
	if err != nil {
		t.Fatal(err)
	}
	if seq <= cursor {
		t.Fatalf("seq restarted after expiry: %d <= cursor %d", seq, cursor)
	}
}

func TestContactSeqMonotonicMemory(t *testing.T) {
	contactSeqMonotonicConformance(t, newMemoryStore())
}

func TestPG_ContactSeqMonotonic(t *testing.T) { contactSeqMonotonicConformance(t, pgStore(t)) }

// contactReclaimHoldConformance: after a record expires, its cid stays
// reserved for the old write key for ContactLimits.ReclaimHold. Anyone who
// learned the cid (co-members, invitees, a forwarded link) could otherwise
// claim it the moment the owner is offline past the TTL and receive the drops
// meant for the owner.
func contactReclaimHoldConformance(t *testing.T, cs ContactStore) {
	ctx := context.Background()
	owner, stranger := sha256hex(newWriteKey()), sha256hex(newWriteKey())
	lim := ContactLimits{ReclaimHold: 1000 * time.Second}
	hold := 1000 * time.Second

	cid := newCID()
	if _, err := cs.PutContact(ctx, cid, owner, raw(`{"o":1}`), 100, 200, lim); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppendContactDrop(ctx, cid, raw(`"old"`), 150, lim); err != nil {
		t.Fatal(err)
	}
	// Expired, not yet pruned: a stranger is refused, the record stays hidden.
	if _, err := cs.PutContact(ctx, cid, stranger, raw(`{"evil":1}`), 201, 5000, lim); err != ErrContactKey {
		t.Fatalf("stranger claimed an expired cid during the hold: %v", err)
	}
	if r, _ := cs.GetContact(ctx, cid, 202); r != nil {
		t.Fatalf("expired record served: %s", r.Record)
	}
	// Prune keeps the hold.
	if _, err := cs.PruneContacts(ctx, 300, 0, hold); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.PutContact(ctx, cid, stranger, raw(`{"evil":1}`), 301, 5000, lim); err != ErrContactKey {
		t.Fatalf("stranger claimed an expired cid after prune: %v", err)
	}
	// The owner's next heartbeat creates it again, with an empty box.
	if created, err := cs.PutContact(ctx, cid, owner, raw(`{"o":2}`), 400, 5000, lim); err != nil || !created {
		t.Fatalf("owner reclaim: %v %v", created, err)
	}
	if items, _, err := cs.ContactDropsAfter(ctx, cid, owner, 0, 0, 0, 401); err != nil || len(items) != 0 {
		t.Fatalf("expired box survived: %+v %v", items, err)
	}
	if r, _ := cs.GetContact(ctx, cid, 401); r == nil || string(r.Record) != `{"o":2}` {
		t.Fatalf("owner record: %+v", r)
	}

	// After the hold the cid is free for anyone.
	free := newCID()
	cs.PutContact(ctx, free, owner, raw(`{}`), 100, 200, lim)
	if _, err := cs.PruneContacts(ctx, 1300, 0, hold); err != nil {
		t.Fatal(err)
	}
	if created, err := cs.PutContact(ctx, free, stranger, raw(`{}`), 1301, 5000, lim); err != nil || !created {
		t.Fatalf("claim after the hold: %v %v", created, err)
	}
	// Unpruned but past the hold: free too.
	late := newCID()
	cs.PutContact(ctx, late, owner, raw(`{}`), 100, 200, lim)
	if created, err := cs.PutContact(ctx, late, stranger, raw(`{}`), 1201, 5000, lim); err != nil || !created {
		t.Fatalf("claim past the hold, unpruned: %v %v", created, err)
	}
}

func TestContactReclaimHoldMemory(t *testing.T) { contactReclaimHoldConformance(t, newMemoryStore()) }

func TestPG_ContactReclaimHold(t *testing.T) { contactReclaimHoldConformance(t, pgStore(t)) }

// contactDropEvictionConformance (R6): a full box evicts drops already served
// to the owner first, then the heaviest sender's; an unread invite from a
// light sender survives a flood, and on a tie a verified sender is kept.
func contactDropEvictionConformance(t *testing.T, cs ContactStore) {
	ctx := context.Background()
	kh := sha256hex(newWriteKey())
	cid := newCID()
	lim := ContactLimits{DropMaxRows: 4, DropMaxBoxBytes: 1000}
	if _, err := cs.PutContact(ctx, cid, kh, raw(`{}`), 10, 1000, lim); err != nil {
		t.Fatal(err)
	}
	from := func(tag string, verified bool) context.Context {
		return WithDropSender(ctx, DropSender{Tag: tag, Verified: verified})
	}
	blobs := func(now int64) []string {
		items, _, err := cs.ContactDropsAfter(ctx, cid, kh, 0, 0, 0, now)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range items {
			out = append(out, string(d.Blob))
		}
		return out
	}
	has := func(got []string, want string) bool {
		for _, g := range got {
			if g == want {
				return true
			}
		}
		return false
	}
	// Already served: the owner listed it, so it goes first.
	if _, err := cs.AppendContactDrop(from("ip:192.0.2.1", false), cid, raw(`"read"`), 11, lim); err != nil {
		t.Fatal(err)
	}
	blobs(12)
	if _, err := cs.AppendContactDrop(from("ip:192.0.2.2", false), cid, raw(`"invite"`), 13, lim); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppendContactDrop(from("sub:alice", true), cid, raw(`"signed-in"`), 14, lim); err != nil {
		t.Fatal(err)
	}
	// A flood from two senders: each over-cap append evicts the read drop
	// first, then the flood's own drops.
	for i := 0; i < 6; i++ {
		tag := "ip:203.0.113.1"
		if i%2 == 1 {
			tag = "ip:203.0.113.2"
		}
		if _, err := cs.AppendContactDrop(from(tag, false), cid, raw(`"flood-`+strconv.Itoa(i)+`"`), int64(15+i), lim); err != nil {
			t.Fatal(err)
		}
	}
	got := blobs(30)
	if len(got) != 4 || !has(got, `"invite"`) || !has(got, `"signed-in"`) || has(got, `"read"`) {
		t.Fatalf("flood eviction kept %v", got)
	}
	// Everything is now served; the byte cap evicts oldest first again.
	if _, err := cs.AppendContactDrop(from("ip:192.0.2.9", false), cid, raw(`"`+strings.Repeat("z", 990)+`"`), 31, lim); err != nil {
		t.Fatal(err)
	}
	got = blobs(32)
	if len(got) != 1 || got[0] != `"`+strings.Repeat("z", 990)+`"` {
		t.Fatalf("byte cap after delivery kept %d drops", len(got))
	}

	// A tie between an unverified and a verified sender evicts the unverified.
	cid2 := newCID()
	lim2 := ContactLimits{DropMaxRows: 1}
	if _, err := cs.PutContact(ctx, cid2, kh, raw(`{}`), 40, 1000, lim2); err != nil {
		t.Fatal(err)
	}
	cs.AppendContactDrop(from("sub:bob", true), cid2, raw(`"v"`), 41, lim2)
	cs.AppendContactDrop(from("ip:198.51.100.3", false), cid2, raw(`"u"`), 42, lim2)
	items, _, _ := cs.ContactDropsAfter(ctx, cid2, kh, 0, 0, 0, 43)
	if len(items) != 1 || string(items[0].Blob) != `"v"` {
		t.Fatalf("tie kept %v", items)
	}
}

func TestContactDropEvictionMemory(t *testing.T) {
	contactDropEvictionConformance(t, newMemoryStore())
}

func TestPG_ContactDropEviction(t *testing.T) {
	s := pgStore(t)
	if _, err := s.pool.Exec(bg, `TRUNCATE relay_contacts, relay_contact_drop`); err != nil {
		t.Fatal(err)
	}
	contactDropEvictionConformance(t, s)
}
