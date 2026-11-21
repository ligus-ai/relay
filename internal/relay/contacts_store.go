package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Contacts (relay v0.3): an opaque, signed contact record per random contact id
// (cid) plus a sealed drop box for that cid. The relay does no cryptography on
// either: the record is client-signed and verified only by clients, drops are
// sealed client-side. The relay keeps SHA-256 of the owner's write key (a
// 32-byte random capability chosen on first write) and compares hashes.
//
// ContactStore is an optional interface, like TunnelStore, so a downstream
// Store that predates contacts keeps compiling; the relay then answers 404 on
// /v1/contacts/ (the same answer a v0.2 relay gives, which clients handle).

// ContactRecord is one stored contact record.
type ContactRecord struct {
	CID          string
	WriteKeyHash string          // hex SHA-256 of the owner's write key
	Record       json.RawMessage // opaque, stored and returned byte for byte
	UpdatedAt    int64
	ExpiresAt    int64
}

// ContactDrop is one sealed message in a contact's drop box (wire shape).
// The unexported fields are relay-side eviction metadata and never reach the
// wire.
type ContactDrop struct {
	Seq       uint64          `json:"seq"`
	Blob      json.RawMessage `json:"blob"`
	CreatedAt int64           `json:"createdAt"`

	sender    string // salted hash of the sender tag (dropSenderHash)
	verified  bool   // the sender carried a relay-token subject
	delivered bool   // served to the owner at least once
}

// DropSender is who the relay attributes a drop to: the relay-token subject
// when the request carries one (Verified), else the client address (an IPv6
// /64 or an IPv4 address). Drops are sealed, so this is the only sender
// identity the relay has; it is used for eviction only.
type DropSender struct {
	Tag      string
	Verified bool
}

type dropSenderKey struct{}

// WithDropSender attaches the drop's sender to ctx for AppendContactDrop.
// (Carried in the context so the ContactStore signature stays stable for
// downstream stores.)
func WithDropSender(ctx context.Context, s DropSender) context.Context {
	return context.WithValue(ctx, dropSenderKey{}, s)
}

func dropSenderFrom(ctx context.Context) DropSender {
	s, _ := ctx.Value(dropSenderKey{}).(DropSender)
	return s
}

// dropSenderSalt keys the stored sender hashes, so a snapshot or database dump
// doesn't list who dropped into which box (an IPv4 tag hashed without a
// secret is brute-forced in seconds). It changes on restart: senders of drops
// stored before the restart then count as different senders, which only
// weakens the ranking for boxes that were mid-flood across a restart.
var dropSenderSalt = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}()

// dropSenderHash is the stored, per-box sender key.
func dropSenderHash(cid string, s DropSender) string {
	if s.Tag == "" {
		return ""
	}
	h := sha256.New()
	h.Write(dropSenderSalt)
	h.Write([]byte(cid))
	h.Write([]byte{0})
	h.Write([]byte(s.Tag))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// dropEvictions picks the drops to evict so a box (drops in seq order) fits
// lim's row and byte caps; at least one drop always stays.
//
// A drop box is open to anyone who knows the cid, and a few addresses within
// the rate limits can fill it. Plain oldest-first eviction then lets a flood
// push out an invite nobody has read yet. Instead, in order:
//
//  1. drops already served to the owner go first, oldest first;
//  2. then unread drops of the heaviest sender (most bytes in the box, then
//     most rows; on a tie an unverified sender before a verified one, then
//     the sender whose oldest unread drop is oldest), its oldest first.
//
// So a flood evicts the flood, and a sender with one small invite keeps it
// unless it is itself the heaviest sender.
func dropEvictions(drops []ContactDrop, lim ContactLimits) []int {
	rows, bytes := len(drops), 0
	for _, d := range drops {
		bytes += len(d.Blob)
	}
	over := func() bool {
		return rows > 1 && ((lim.DropMaxRows > 0 && rows > lim.DropMaxRows) ||
			(lim.DropMaxBoxBytes > 0 && bytes > lim.DropMaxBoxBytes))
	}
	if !over() {
		return nil
	}
	type senderLoad struct {
		bytes, rows int
		verified    bool
		idx         []int // unread drops, seq order
	}
	senders := map[string]*senderLoad{}
	var order []string // first-seen order (oldest unread drop first)
	var delivered []int
	for i, d := range drops {
		if d.delivered {
			delivered = append(delivered, i)
			continue
		}
		l := senders[d.sender]
		if l == nil {
			l = &senderLoad{}
			senders[d.sender] = l
			order = append(order, d.sender)
		}
		l.bytes += len(d.Blob)
		l.rows++
		l.verified = l.verified || d.verified
		l.idx = append(l.idx, i)
	}
	var out []int
	evict := func(i int) {
		out = append(out, i)
		rows--
		bytes -= len(drops[i].Blob)
	}
	for over() && len(delivered) > 0 {
		evict(delivered[0])
		delivered = delivered[1:]
	}
	for over() {
		var best *senderLoad
		for _, k := range order {
			l := senders[k]
			if len(l.idx) == 0 {
				continue
			}
			if best == nil || l.bytes > best.bytes ||
				(l.bytes == best.bytes && (l.rows > best.rows ||
					(l.rows == best.rows && best.verified && !l.verified))) {
				best = l
			}
		}
		if best == nil {
			break
		}
		i := best.idx[0]
		best.idx = best.idx[1:]
		best.bytes -= len(drops[i].Blob)
		best.rows--
		evict(i)
	}
	sort.Ints(out)
	return out
}

var (
	// ErrContactNotFound: no live (unexpired) record for the cid.
	ErrContactNotFound = errors.New("contact not found")
	// ErrContactKey: the presented write key doesn't match the record's.
	ErrContactKey = errors.New("contact key does not match")
	// ErrContactsFull: the store holds its maximum number of contact records.
	ErrContactsFull = errors.New("relay contact capacity reached")
)

// ContactLimits are the storage bounds the handlers pass to the store, so the
// store stays free of policy (like friendCap).
type ContactLimits struct {
	MaxContacts     int // live records per store (memory store only; 0 = unbounded)
	DropMaxRows     int // rows per drop box, oldest evicted (0 = unbounded)
	DropMaxBoxBytes int // blob bytes per drop box, oldest evicted (0 = unbounded)
	// ReclaimHold is how long after a record expires only its old write key
	// may create the cid again (0 = anyone at once). A cid travels to
	// co-members, invitees and anyone a link was forwarded to; without a hold,
	// any of them could claim the cid of an owner who was offline past the TTL
	// and receive the drops meant for them.
	ReclaimHold time.Duration
	// MaxBytes bounds record plus drop bytes across the relay (Postgres
	// only; the memory store has MaxContacts and its store budget). New
	// records and drops past it get ErrContactsFull; an existing record can
	// still be refreshed. 0 = unbounded.
	MaxBytes int64
}

// ContactStore is the contacts' durable state.
type ContactStore interface {
	// PutContact creates the record when the cid has no live record, storing
	// keyHash as its write key. An expired record's drop box is discarded; for
	// lim.ReclaimHold after its expiry only its old key may create it again
	// (ErrContactKey otherwise). For a live record keyHash must equal the
	// stored hash (ErrContactKey) and the record is replaced. created reports
	// whether a record was created.
	PutContact(ctx context.Context, cid, keyHash string, record json.RawMessage, now, expiresAt int64, lim ContactLimits) (created bool, err error)
	// GetContact returns the live record, or nil.
	GetContact(ctx context.Context, cid string, now int64) (*ContactRecord, error)
	// DeleteContact removes the record and its drop box (key-checked).
	DeleteContact(ctx context.Context, cid, keyHash string, now int64) error
	// AppendContactDrop appends a blob to a live record's drop box (the sender
	// comes from WithDropSender on ctx), evicting per dropEvictions past
	// lim.DropMaxRows / lim.DropMaxBoxBytes: drops already served to the owner
	// first, then the heaviest sender's.
	AppendContactDrop(ctx context.Context, cid string, blob json.RawMessage, now int64, lim ContactLimits) (uint64, error)
	// ContactDropsAfter returns up to limit drops with seq > after (and at most
	// about maxBytes of blobs, always at least one row); more reports a
	// truncated page. Key-checked. The returned drops count as delivered for
	// eviction.
	ContactDropsAfter(ctx context.Context, cid, keyHash string, after uint64, limit, maxBytes int, now int64) (items []ContactDrop, more bool, err error)
	// AckContactDrops deletes the drops with seq <= through (key-checked).
	AckContactDrops(ctx context.Context, cid, keyHash string, through uint64, now int64) (int64, error)
	// PruneContacts empties expired records (record and drop box; the write
	// key hash is kept until reclaimHold after expiry, then the row goes) and
	// deletes drops older than dropMaxAge (0 = no age bound). Returns rows
	// removed.
	PruneContacts(ctx context.Context, now int64, dropMaxAge, reclaimHold time.Duration) (int64, error)
}

// ── Memory (and snapshot) implementation ─────────────────────────────────────

// memContacts is the in-process ContactStore. memoryStore embeds it (its state
// rides the JSON snapshot); the server uses a standalone one only in tests.
type memContacts struct {
	cmu      sync.Mutex
	contacts map[string]*memContact
	held     int // stripped (reclaim hold) entries in contacts
	// reserve charges bytes against the owning store's byte budget (nil = no
	// budget). Called with cmu held; must not take cmu.
	reserve func(n int64) bool
}

type memContact struct {
	keyHash   string
	record    json.RawMessage
	updatedAt int64
	expiresAt int64
	drops     []ContactDrop
	dropBytes int
	nextSeq   uint64
	stripped  bool // expired and emptied: a reclaim hold tombstone
}

// contactSeqBase is the drop-box seq a box created at now starts after. A box
// that is deleted, or expires, and is created again for the same cid must not
// reuse seqs: each device of the account keeps its own after= cursor and acks
// with through=, so a restart at 1 would hide new drops from a device whose
// cursor is past them and let its stale ack delete drops nobody has read. The
// creation second times 2^20 grows faster than any box can be filled (drops are
// rate-limited per cid), stays below 2^53 until the year 2242 so JavaScript
// clients read it exactly, and needs no per-cid state after a delete.
func contactSeqBase(now int64) uint64 {
	if now <= 0 {
		return 0
	}
	return uint64(now) << 20
}

// contactOverheadBytes is what the byte budget charges per record beyond its
// payload (map entry, cid, key hash).
const contactOverheadBytes = 256

func newMemContacts() *memContacts {
	return &memContacts{contacts: map[string]*memContact{}}
}

func (m *memContacts) charge(n int64) bool {
	if m.reserve == nil {
		return true
	}
	return m.reserve(n)
}

func (c *memContact) bytes() int64 {
	return int64(contactOverheadBytes + len(c.record) + c.dropBytes)
}

func (m *memContacts) liveLocked(cid string, now int64) *memContact {
	c := m.contacts[cid]
	if c == nil {
		return nil
	}
	if c.expiresAt <= now {
		m.stripLocked(c)
		return nil
	}
	return c
}

// stripLocked empties an expired record down to its key hash and seq counter
// (a reclaim hold tombstone; PruneContacts removes it after the hold).
func (m *memContacts) stripLocked(c *memContact) {
	if c.stripped {
		return
	}
	freed := len(c.record) + c.dropBytes
	c.record, c.drops, c.dropBytes, c.stripped = nil, nil, 0, true
	m.held++
	m.charge(-int64(freed))
}

func (m *memContacts) removeLocked(cid string) {
	if c := m.contacts[cid]; c != nil {
		m.charge(-c.bytes())
		if c.stripped {
			m.held--
		}
		delete(m.contacts, cid)
	}
}

func (m *memContacts) PutContact(_ context.Context, cid, keyHash string, record json.RawMessage, now, expiresAt int64, lim ContactLimits) (bool, error) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	rec := append(json.RawMessage(nil), record...)
	if c := m.liveLocked(cid, now); c != nil {
		if !constantTimeEq(c.keyHash, keyHash) {
			return false, ErrContactKey
		}
		if !m.charge(int64(len(rec) - len(c.record))) {
			return false, ErrStoreFull
		}
		c.record, c.updatedAt, c.expiresAt = rec, now, expiresAt
		return false, nil
	}
	if old := m.contacts[cid]; old != nil { // expired (stripped by liveLocked)
		held := now < old.expiresAt+int64(lim.ReclaimHold/time.Second)
		if !constantTimeEq(old.keyHash, keyHash) {
			if held {
				return false, ErrContactKey
			}
			m.removeLocked(cid)
		} else {
			if !m.charge(int64(len(rec))) {
				return false, ErrStoreFull
			}
			old.record, old.updatedAt, old.expiresAt, old.stripped = rec, now, expiresAt, false
			m.held--
			old.nextSeq = max(old.nextSeq, contactSeqBase(now))
			return true, nil
		}
	}
	// Tombstones hold no record or drops (their bytes still count toward the
	// store budget), so the cap counts the other entries only.
	if lim.MaxContacts > 0 && len(m.contacts)-m.held >= lim.MaxContacts {
		return false, ErrContactsFull
	}
	c := &memContact{keyHash: keyHash, record: rec, updatedAt: now, expiresAt: expiresAt, nextSeq: contactSeqBase(now)}
	if !m.charge(c.bytes()) {
		return false, ErrStoreFull
	}
	m.contacts[cid] = c
	return true, nil
}

func (m *memContacts) GetContact(_ context.Context, cid string, now int64) (*ContactRecord, error) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	c := m.liveLocked(cid, now)
	if c == nil {
		return nil, nil
	}
	return &ContactRecord{CID: cid, WriteKeyHash: c.keyHash, Record: c.record, UpdatedAt: c.updatedAt, ExpiresAt: c.expiresAt}, nil
}

// ownedLocked returns the live record if keyHash matches.
func (m *memContacts) ownedLocked(cid, keyHash string, now int64) (*memContact, error) {
	c := m.liveLocked(cid, now)
	if c == nil {
		return nil, ErrContactNotFound
	}
	if !constantTimeEq(c.keyHash, keyHash) {
		return nil, ErrContactKey
	}
	return c, nil
}

func (m *memContacts) DeleteContact(_ context.Context, cid, keyHash string, now int64) error {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	if _, err := m.ownedLocked(cid, keyHash, now); err != nil {
		return err
	}
	m.removeLocked(cid)
	return nil
}

func (m *memContacts) AppendContactDrop(ctx context.Context, cid string, blob json.RawMessage, now int64, lim ContactLimits) (uint64, error) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	c := m.liveLocked(cid, now)
	if c == nil {
		return 0, ErrContactNotFound
	}
	if !m.charge(int64(len(blob))) {
		return 0, ErrStoreFull
	}
	snd := dropSenderFrom(ctx)
	c.nextSeq++
	c.drops = append(c.drops, ContactDrop{Seq: c.nextSeq, Blob: append(json.RawMessage(nil), blob...), CreatedAt: now,
		sender: dropSenderHash(cid, snd), verified: snd.Verified})
	c.dropBytes += len(blob)
	// Past the row and byte caps, evict per dropEvictions (one drop always
	// stays).
	if ev := dropEvictions(c.drops, lim); len(ev) > 0 {
		gone := make(map[int]bool, len(ev))
		freed := 0
		for _, i := range ev {
			gone[i] = true
			freed += len(c.drops[i].Blob)
		}
		kept := make([]ContactDrop, 0, len(c.drops)-len(ev))
		for i, d := range c.drops {
			if !gone[i] {
				kept = append(kept, d)
			}
		}
		m.charge(-int64(freed))
		c.dropBytes -= freed
		c.drops = kept
	}
	return c.nextSeq, nil
}

func (m *memContacts) ContactDropsAfter(_ context.Context, cid, keyHash string, after uint64, limit, maxBytes int, now int64) ([]ContactDrop, bool, error) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	c, err := m.ownedLocked(cid, keyHash, now)
	if err != nil {
		return nil, false, err
	}
	i := sort.Search(len(c.drops), func(i int) bool { return c.drops[i].Seq > after })
	out := []ContactDrop{}
	size := 0
	for ; i < len(c.drops); i++ {
		d := c.drops[i]
		if len(out) > 0 && ((limit > 0 && len(out) >= limit) || (maxBytes > 0 && size+len(d.Blob) > maxBytes)) {
			return out, true, nil
		}
		c.drops[i].delivered = true
		out = append(out, d)
		size += len(d.Blob)
	}
	return out, false, nil
}

func (m *memContacts) AckContactDrops(_ context.Context, cid, keyHash string, through uint64, now int64) (int64, error) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	c, err := m.ownedLocked(cid, keyHash, now)
	if err != nil {
		return 0, err
	}
	i := sort.Search(len(c.drops), func(i int) bool { return c.drops[i].Seq > through })
	if i == 0 {
		return 0, nil
	}
	freed := 0
	for _, d := range c.drops[:i] {
		freed += len(d.Blob)
	}
	c.drops = append([]ContactDrop(nil), c.drops[i:]...)
	c.dropBytes -= freed
	m.charge(-int64(freed))
	return int64(i), nil
}

func (m *memContacts) PruneContacts(_ context.Context, now int64, dropMaxAge, reclaimHold time.Duration) (int64, error) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	var n int64
	cutoff := now - int64(dropMaxAge/time.Second)
	for cid, c := range m.contacts {
		if c.expiresAt <= now {
			n += int64(len(c.drops))
			if now >= c.expiresAt+int64(reclaimHold/time.Second) {
				n++
				m.removeLocked(cid)
			} else {
				m.stripLocked(c)
			}
			continue
		}
		if dropMaxAge <= 0 {
			continue
		}
		i := 0
		freed := 0
		for i < len(c.drops) && c.drops[i].CreatedAt < cutoff {
			freed += len(c.drops[i].Blob)
			i++
		}
		if i > 0 {
			c.drops = append([]ContactDrop(nil), c.drops[i:]...)
			c.dropBytes -= freed
			m.charge(-int64(freed))
			n += int64(i)
		}
	}
	return n, nil
}

// contactCount reports live and expired-unswept records (tests).
func (m *memContacts) contactCount() int {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	return len(m.contacts)
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

// Records and blobs are snapshotted as JSON strings, not raw JSON, so the
// exact bytes survive a restart (encoding/json compacts raw values).
type contactSnap struct {
	KeyHash   string            `json:"keyHash"`
	Record    string            `json:"record"`
	UpdatedAt int64             `json:"updatedAt"`
	ExpiresAt int64             `json:"expiresAt"`
	Drops     []contactDropSnap `json:"drops,omitempty"`
	NextSeq   uint64            `json:"nextSeq"`
	Stripped  bool              `json:"stripped,omitempty"`
}

type contactDropSnap struct {
	Seq       uint64 `json:"seq"`
	Blob      string `json:"blob"`
	CreatedAt int64  `json:"createdAt"`
	Sender    string `json:"sender,omitempty"`
	Verified  bool   `json:"verified,omitempty"`
	Delivered bool   `json:"delivered,omitempty"`
}

func (m *memContacts) toContactSnap() map[string]contactSnap {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	if len(m.contacts) == 0 {
		return nil
	}
	out := make(map[string]contactSnap, len(m.contacts))
	for cid, c := range m.contacts {
		cs := contactSnap{KeyHash: c.keyHash, Record: string(c.record), UpdatedAt: c.updatedAt,
			ExpiresAt: c.expiresAt, NextSeq: c.nextSeq, Stripped: c.stripped}
		for _, d := range c.drops {
			cs.Drops = append(cs.Drops, contactDropSnap{Seq: d.Seq, Blob: string(d.Blob), CreatedAt: d.CreatedAt,
				Sender: d.sender, Verified: d.verified, Delivered: d.delivered})
		}
		out[cid] = cs
	}
	return out
}

// restoreContacts replaces the contacts from a snapshot and returns the bytes
// they hold (the caller adds them to the store budget).
func (m *memContacts) restoreContacts(snap map[string]contactSnap) int64 {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	m.contacts = map[string]*memContact{}
	m.held = 0
	var total int64
	for cid, s := range snap {
		c := &memContact{keyHash: s.KeyHash, record: json.RawMessage(s.Record), updatedAt: s.UpdatedAt,
			expiresAt: s.ExpiresAt, nextSeq: s.NextSeq}
		for _, d := range s.Drops {
			c.drops = append(c.drops, ContactDrop{Seq: d.Seq, Blob: json.RawMessage(d.Blob), CreatedAt: d.CreatedAt,
				sender: d.Sender, verified: d.Verified, delivered: d.Delivered})
			c.dropBytes += len(d.Blob)
		}
		if s.Stripped {
			c.stripped = true
			m.held++
		}
		m.contacts[cid] = c
		total += c.bytes()
	}
	return total
}
