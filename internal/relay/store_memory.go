package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// A room's envelope log is never trimmed from the front: a client folds it
// from seq 1 (the founder's seed), so rooms are bounded by refusal (room
// quotas, the store byte budget) and expired only whole (eviction.go,
// docs/tenancy.md).

// memoryStore is the in-process Store: RWMutex-guarded maps plus an optional
// JSON snapshot (set persistPath). Zero external dependencies; the self-host
// default and what the tests run against. It does not share state across
// processes — that's postgresStore's job (selected by DATABASE_URL), which the
// Store seam lets drop in with no data migration.
type memoryStore struct {
	mu          sync.RWMutex
	workspaces  map[string]*memWorkspace
	directory   map[string]*DirAccount // keyed by lowercased login
	accounts    map[string]*memAccount
	loginIndex  map[string]string // lowercased login → account key
	friendReqs  map[string]*FriendRequest
	friendEdges map[[2]string]struct{}

	users     map[string]*UserRecord // user id → record
	tokens    map[string]*memToken   // token id → record
	tokenHash map[string]string      // token hash → token id
	nextIDSeq uint64                 // monotonic id source for users/tokens

	persistPath string // "" = in-memory only

	// Structural caps that bound unauthenticated growth (0 = unbounded):
	//   inboxMaxRows      — per-account inbox rows (oldest evicted past the cap).
	//   maxKeyringPerWS   — key-rotation rows per workspace.
	//   maxDeviceBlobsPerWS — candidate/presence device entries per workspace.
	inboxMaxRows        int
	maxKeyringPerWS     int
	maxDeviceBlobsPerWS int
	// maxKeyringBytesPerWS caps the stored bytes of one workspace's keyring
	// (0 = unbounded).
	maxKeyringBytesPerWS int

	// maxStoreBytes caps the bytes of workspace blobs held (envelope bodies,
	// keyring rows, candidate and presence blobs) across all workspaces
	// (LANGSTROTH_RELAY_MAX_STORE_BYTES; 0 = unbounded, the default). storeBytes is
	// the running total. A write past the cap fails with ErrStoreFull (507).
	maxStoreBytes int64
	storeBytes    int64

	// Room accounting (quota.go): live rooms and their bytes, per tenant and
	// per creator. Recomputed on restore.
	liveRooms    int64
	roomBytes    int64
	tenantUse    map[string]*memTenantUse
	creatorRooms map[string]int64

	// Attachment blobs (blobs_memory.go): room → id → blob, with per-tenant
	// and relay-wide totals. Lazily built.
	blobs      map[string]map[string]*memBlob
	blobTenant map[string]*memBlobUse
	blobTotal  memBlobUse

	// notify wakes SSE subscribers of this workspace on a genuinely new append
	// (in-process; see wsNotifier).
	notify *wsNotifier

	// Relay tunnel state (hosts, revocations, push tokens); see tunnel_store.go.
	*memTunnel

	// Contact records and drop boxes; see contacts_store.go. Lock order: its
	// cmu may be taken before s.mu (to charge the byte budget), never after.
	*memContacts
}

type memToken struct {
	rec  TokenRecord
	hash string
}

type memWorkspace struct {
	envelopes []Envelope
	// envAt[i] is the wall-clock unix time envelopes[i] was appended, kept
	// aligned with envelopes for age-based retention. It never rides the wire
	// (the relay is content-blind); it is persisted only so retention survives a
	// restart.
	envAt []int64
	// envKey[i] is the idempotency key envelopes[i] was stored under ("" = none),
	// kept aligned with envelopes so pruning can forget a dropped envelope's key.
	envKey []string
	// dedup maps a non-empty idempotency key → the seq stored under it, so a
	// re-push returns the existing seq instead of appending a duplicate. Rebuilt
	// from envKey on snapshot restore; an entry is dropped when its envelope is
	// pruned (forgetting a pruned key is acceptable — a later re-push re-appends).
	dedup      map[string]uint64
	nextSeq    uint64
	candidates map[string]json.RawMessage
	presence   map[string]json.RawMessage
	keyring    []json.RawMessage
	// Relay-managed team roster, keyed by account. Empty = unclaimed (open,
	// content-blind); non-empty = the membership guard enforces this workspace.
	members map[string]*MemberRow
	// Relay-issued invites, keyed by invite id (revocable/expiring self-enroll).
	invites map[string]*memInvite

	// Room accounting (quota.go). live: the room holds data and counts as a
	// room (set by its first write, cleared by retention or a purge). The
	// struct outlives that so nextSeq never restarts.
	live      bool
	tenant    string
	creator   string
	roomBytes int64 // envelope bodies + key rotations
	lastWrite int64 // unix seconds of the room's creation or its last envelope or key-rotation write
	// charged: the store budget holds this workspace's overhead
	// (wsOverheadBytes + id), to give back if the struct is dropped.
	charged bool
}

type memTenantUse struct {
	bytes, rooms int64
}

type memDeviceReg struct {
	nodeID   *string
	label    *string
	lastSeen int64
}

type memAccount struct {
	login         string
	appearOffline bool
	inbox         []InboxRow
	nextSeq       uint64
	devices       map[string]memDeviceReg
}

func newMemoryStore() *memoryStore {
	s := &memoryStore{
		workspaces:           map[string]*memWorkspace{},
		directory:            map[string]*DirAccount{},
		accounts:             map[string]*memAccount{},
		loginIndex:           map[string]string{},
		friendReqs:           map[string]*FriendRequest{},
		friendEdges:          map[[2]string]struct{}{},
		users:                map[string]*UserRecord{},
		tokens:               map[string]*memToken{},
		tokenHash:            map[string]string{},
		inboxMaxRows:         int(envInt64("LANGSTROTH_RELAY_INBOX_MAX_ROWS", defaultInboxMaxRows)),
		maxKeyringPerWS:      int(envInt64("LANGSTROTH_RELAY_MAX_KEYRING_PER_WS", defaultMaxKeyringPerWS)),
		maxKeyringBytesPerWS: int(envInt64("LANGSTROTH_RELAY_MAX_KEYRING_BYTES_PER_WS", defaultMaxKeyringBytesPerWS)),
		maxDeviceBlobsPerWS:  int(envInt64("LANGSTROTH_RELAY_MAX_DEVICE_BLOBS_PER_WS", defaultMaxDeviceBlobsPerWS)),
		maxStoreBytes:        max(envInt64("LANGSTROTH_RELAY_MAX_STORE_BYTES", 0), 0),
		notify:               newWSNotifier(),
		memTunnel:            newMemTunnel(),
		memContacts:          newMemContacts(),
		tenantUse:            map[string]*memTenantUse{},
		creatorRooms:         map[string]int64{},
	}
	s.memContacts.reserve = func(n int64) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.reserveLocked(n)
	}
	return s
}

// subscribeWorkspace / latestSeq satisfy notifyStore, letting the SSE handler
// wake on appends and greet a new subscriber with the current head seq.
func (s *memoryStore) subscribeWorkspace(workspace string) (<-chan uint64, func()) {
	return s.notify.subscribe(workspace)
}

func (s *memoryStore) latestSeq(_ context.Context, workspace string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if w := s.workspaces[workspace]; w != nil {
		return w.nextSeq, nil
	}
	return 0, nil
}

func (s *memoryStore) workspace(id string) *memWorkspace {
	w := s.workspaces[id]
	if w == nil {
		w = &memWorkspace{
			candidates: map[string]json.RawMessage{},
			presence:   map[string]json.RawMessage{},
			members:    map[string]*MemberRow{},
			invites:    map[string]*memInvite{},
		}
		s.workspaces[id] = w
	}
	return w
}

// wsOverheadBytes is what the byte budget charges for each workspace it holds
// (its maps and slices), plus the id itself, so fresh workspace ids with tiny
// writes can't grow the heap past the budget.
const wsOverheadBytes = 1024

// workspaceForWrite returns the workspace for a write of addBytes room bytes
// and addEnv envelopes, after the quotas in ctx (quota.go) and the store byte
// budget admit it. It charges a new workspace's overhead to the budget,
// accounts the room bytes and, when the write creates the room, counts the
// room for its tenant and creator. Device-blob writes pass 0/0 (they only
// create the room). Caller holds s.mu.
func (s *memoryStore) workspaceForWrite(ctx context.Context, id string, addBytes, addEnv int64) (*memWorkspace, error) {
	q := quotaFrom(ctx)
	w := s.workspaces[id]
	creating := w == nil || !w.live
	tenant := ""
	if w != nil && w.live {
		tenant = w.tenant
	} else if q != nil {
		tenant = q.Tenant
	}
	if q != nil {
		var rb, re int64
		if w != nil {
			rb, re = w.roomBytes, int64(len(w.envelopes))
		}
		tu := s.tenantUse[tenant]
		if tu == nil {
			tu = &memTenantUse{}
		}
		switch {
		case addBytes > 0 && q.RoomMaxBytes > 0 && rb+addBytes > q.RoomMaxBytes:
			return nil, errQuota(limRoomBytes, tenant)
		case addEnv > 0 && q.RoomMaxEnvelopes > 0 && re+addEnv > q.RoomMaxEnvelopes:
			return nil, errQuota(limRoomEnvelopes, tenant)
		case addBytes > 0 && q.TotalMaxBytes > 0 && s.roomBytes+addBytes > q.TotalMaxBytes:
			return nil, errQuota(limTotalBytes, tenant)
		case addBytes > 0 && q.TenantMaxBytes > 0 && tu.bytes+addBytes > q.TenantMaxBytes:
			return nil, errQuota(limTenantBytes, tenant)
		case creating && q.TotalMaxRooms > 0 && s.liveRooms >= q.TotalMaxRooms:
			return nil, errQuota(limTotalRooms, tenant)
		case creating && q.TenantMaxRooms > 0 && tu.rooms >= q.TenantMaxRooms:
			return nil, errQuota(limTenantRooms, tenant)
		case creating && q.CreatorMaxRooms > 0 && q.Creator != "" && s.creatorRooms[q.Creator] >= q.CreatorMaxRooms:
			return nil, errQuota(limClientRooms, tenant)
		}
	}
	reserve := addBytes
	if w == nil {
		reserve += int64(wsOverheadBytes + len(id))
	}
	if !s.reserveLocked(reserve) {
		return nil, ErrStoreFull
	}
	if w == nil {
		w = s.workspace(id)
		w.charged = true
	}
	if creating {
		w.live, w.tenant, w.creator = true, tenant, ""
		if q != nil {
			w.creator = q.Creator
		}
		s.liveRooms++
		s.tenantUseFor(tenant).rooms++
		if w.creator != "" {
			s.creatorRooms[w.creator]++
		}
	}
	// A new room starts its idle clock now, whatever created it (a presence
	// write too), so retention can't expire a room created a minute ago.
	if creating || addBytes > 0 || addEnv > 0 {
		w.lastWrite = time.Now().Unix()
	}
	s.addRoomBytesLocked(w, addBytes)
	return w, nil
}

func (s *memoryStore) tenantUseFor(t string) *memTenantUse {
	tu := s.tenantUse[t]
	if tu == nil {
		tu = &memTenantUse{}
		s.tenantUse[t] = tu
	}
	return tu
}

// addRoomBytesLocked moves w's room bytes by n (negative frees) in every
// total that counts them. It does not touch the store budget. Caller holds
// s.mu.
func (s *memoryStore) addRoomBytesLocked(w *memWorkspace, n int64) {
	if n == 0 {
		return
	}
	w.roomBytes += n
	s.roomBytes += n
	s.tenantUseFor(w.tenant).bytes += n
}

func (s *memoryStore) account(key string) *memAccount {
	a := s.accounts[key]
	if a == nil {
		a = &memAccount{devices: map[string]memDeviceReg{}}
		s.accounts[key] = a
	}
	return a
}

// ── Workspace sync ───────────────────────────────────────────────────────────

func (s *memoryStore) AppendEnvelope(ctx context.Context, workspace string, body json.RawMessage, dedupKey string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w := s.workspaces[workspace]; w != nil && dedupKey != "" {
		if seq, ok := w.dedup[dedupKey]; ok {
			return seq, nil // already stored — idempotent no-op, even when full
		}
	}
	w, err := s.workspaceForWrite(ctx, workspace, int64(len(body)), 1)
	if err != nil {
		return 0, err
	}
	// Realign envKey with envelopes in case envelopes were populated directly
	// (older snapshots without keys, or tests): pad the older prefix with empty
	// keys so the append below stays index-aligned.
	if len(w.envKey) < len(w.envelopes) {
		w.envKey = append(make([]string, len(w.envelopes)-len(w.envKey)), w.envKey...)
	}
	w.nextSeq++
	seq := w.nextSeq
	w.envelopes = append(w.envelopes, Envelope{Seq: seq, Body: body})
	w.envAt = append(w.envAt, time.Now().Unix())
	w.envKey = append(w.envKey, dedupKey)
	if dedupKey != "" {
		if w.dedup == nil {
			w.dedup = map[string]uint64{}
		}
		w.dedup[dedupKey] = seq
	}
	// Wake SSE subscribers — only reached on a genuinely new seq (the dedup
	// branch above returns first), so a re-push never spams. publish is
	// non-blocking and takes a separate mutex, so holding s.mu here is safe.
	s.notify.publish(workspace, seq)
	return seq, nil
}

func (s *memoryStore) EnvelopesAfter(_ context.Context, workspace string, after uint64) ([]Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Envelope{}
	if w := s.workspaces[workspace]; w != nil {
		for _, e := range w.envelopes {
			if e.Seq > after {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// EnvelopesPage satisfies envelopePager: one bounded page past after, without
// copying the rest of the log.
func (s *memoryStore) EnvelopesPage(_ context.Context, workspace string, after uint64, limit, maxBytes int) ([]Envelope, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pb := newPageBuilder(limit, maxBytes)
	w := s.workspaces[workspace]
	if w == nil {
		return pb.rows, false, nil
	}
	// Seqs are appended in increasing order (pruning drops a prefix), so the
	// first envelope past the cursor is found by binary search.
	start := sort.Search(len(w.envelopes), func(i int) bool { return w.envelopes[i].Seq > after })
	for _, e := range w.envelopes[start:] {
		if !pb.add(e) {
			return pb.rows, true, nil
		}
	}
	return pb.rows, false, nil
}

func (s *memoryStore) PutCandidate(ctx context.Context, workspace, deviceID string, candidate json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := s.workspaceForWrite(ctx, workspace, 0, 0)
	if err != nil {
		return err
	}
	return s.putDeviceBlobLocked(w.candidates, deviceID, candidate)
}

// putDeviceBlobLocked stores a candidate/presence blob under the per-workspace
// device cap and the store byte budget. Caller holds s.mu.
func (s *memoryStore) putDeviceBlobLocked(m map[string]json.RawMessage, deviceID string, blob json.RawMessage) error {
	old, exists := m[deviceID]
	if !s.reserveLocked(int64(len(blob)) - int64(len(old))) {
		return ErrStoreFull
	}
	if !exists {
		if evicted, ok := capDeviceBlobs(m, deviceID, s.maxDeviceBlobsPerWS); ok {
			s.storeBytes -= int64(len(evicted))
		}
	}
	m[deviceID] = blob
	return nil
}

// reserveLocked accounts n more bytes (negative frees) against the store
// budget; false (and nothing accounted) when that would exceed it. Caller
// holds s.mu.
func (s *memoryStore) reserveLocked(n int64) bool {
	if n > 0 && s.maxStoreBytes > 0 && s.storeBytes+n > s.maxStoreBytes {
		return false
	}
	s.storeBytes += n
	return true
}

// capDeviceBlobs bounds a per-workspace device-blob map so an attacker can't grow
// it without limit by spraying distinct device ids (P2-12). If the map is at the
// cap and deviceID is new, it evicts one existing entry first (blobs are
// ephemeral rendezvous state — a live device simply re-publishes).
func capDeviceBlobs(m map[string]json.RawMessage, deviceID string, limit int) (evicted json.RawMessage, ok bool) {
	if limit <= 0 {
		return nil, false
	}
	if _, exists := m[deviceID]; exists || len(m) < limit {
		return nil, false
	}
	for k, v := range m { // drop one arbitrary entry to make room
		delete(m, k)
		return v, true
	}
	return nil, false
}

func (s *memoryStore) Candidates(_ context.Context, workspace string) (map[string]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]json.RawMessage{}
	if w := s.workspaces[workspace]; w != nil {
		for k, v := range w.candidates {
			out[k] = v
		}
	}
	return out, nil
}

func (s *memoryStore) PutPresence(ctx context.Context, workspace, deviceID string, presence json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := s.workspaceForWrite(ctx, workspace, 0, 0)
	if err != nil {
		return err
	}
	return s.putDeviceBlobLocked(w.presence, deviceID, presence)
}

func (s *memoryStore) PresenceBlobs(_ context.Context, workspace string) (map[string]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]json.RawMessage{}
	if w := s.workspaces[workspace]; w != nil {
		for k, v := range w.presence {
			out[k] = v
		}
	}
	return out, nil
}

func (s *memoryStore) AppendKeyRotation(ctx context.Context, workspace string, blob json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.workspaces[workspace]
	if w == nil {
		w = &memWorkspace{} // for the cap checks only; nothing is stored
	}
	// Bound key-rotation growth per workspace (P2-12) by refusing past the
	// caps, never by evicting: the oldest rows are the real rotations a junk
	// flood would otherwise push out.
	if s.maxKeyringPerWS > 0 && len(w.keyring) >= s.maxKeyringPerWS {
		return ErrKeyringFull
	}
	if s.maxKeyringBytesPerWS > 0 {
		total := len(blob)
		for _, k := range w.keyring {
			total += len(k)
		}
		if total > s.maxKeyringBytesPerWS {
			return ErrKeyringFull
		}
	}
	w, err := s.workspaceForWrite(ctx, workspace, int64(len(blob)), 0)
	if err != nil {
		return err
	}
	w.keyring = append(w.keyring, blob)
	return nil
}

func (s *memoryStore) KeyRotations(_ context.Context, workspace string) ([]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []json.RawMessage{}
	if w := s.workspaces[workspace]; w != nil {
		out = append(out, w.keyring...)
	}
	return out, nil
}

// ── Identity directory ────────────────────────────────────────────────────────

func (s *memoryStore) UpsertDirDevice(_ context.Context, githubID uint64, login string, name *string, deviceID, kaPub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := lower(login)
	e := s.directory[key]
	if e == nil {
		e = &DirAccount{Devices: map[string]string{}}
		s.directory[key] = e
	}
	e.GitHubID = githubID
	e.Login = login
	e.Name = name
	if kaPub != "" && deviceID != "" {
		e.Devices[deviceID] = kaPub
	}
	return nil
}

func (s *memoryStore) DirAccountByHandle(_ context.Context, handle string) (*DirAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.directory[normHandle(handle)]
	if e == nil {
		return nil, nil
	}
	devices := make(map[string]string, len(e.Devices))
	for k, v := range e.Devices {
		devices[k] = v
	}
	return &DirAccount{GitHubID: e.GitHubID, Login: e.Login, Name: e.Name, Devices: devices}, nil
}

// ── Account registry + inbox ──────────────────────────────────────────────────

func (s *memoryStore) RegisterAccountDevice(_ context.Context, githubID uint64, login, deviceID string, nodeID, label *string, now int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := accountKey(githubID)
	s.loginIndex[lower(login)] = key
	a := s.account(key)
	a.login = login
	a.devices[deviceID] = memDeviceReg{nodeID: nodeID, label: label, lastSeen: now}
	return key, nil
}

func (s *memoryStore) HeartbeatDevice(_ context.Context, githubID uint64, deviceID string, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.accounts[accountKey(githubID)]
	if a == nil {
		return false, nil
	}
	d, ok := a.devices[deviceID]
	if !ok {
		return false, nil
	}
	d.lastSeen = now
	a.devices[deviceID] = d
	return true, nil
}

func (s *memoryStore) PushAccountEvent(_ context.Context, key string, body json.RawMessage) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.account(key)
	a.nextSeq++
	a.inbox = append(a.inbox, InboxRow{Seq: a.nextSeq, Body: body})
	// Bound inbox growth: past the cap, drop the oldest rows so inbox spam can't
	// grow an account without limit (P1-7). The relay is a recent-traffic cache;
	// clients that fell far behind re-sync from a peer.
	if s.inboxMaxRows > 0 && len(a.inbox) > s.inboxMaxRows {
		a.inbox = append([]InboxRow(nil), a.inbox[len(a.inbox)-s.inboxMaxRows:]...)
	}
	return a.nextSeq, nil
}

func (s *memoryStore) AccountInboxAfter(_ context.Context, key string, after uint64) ([]InboxRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []InboxRow{}
	if a := s.accounts[key]; a != nil {
		for _, e := range a.inbox {
			if e.Seq > after {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (s *memoryStore) AccountDevices(_ context.Context, key string) ([]DeviceRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accountDevicesLocked(key), nil
}

func (s *memoryStore) accountDevicesLocked(key string) []DeviceRow {
	out := []DeviceRow{}
	if a := s.accounts[key]; a != nil {
		for id, d := range a.devices {
			out = append(out, DeviceRow{DeviceID: id, NodeID: d.nodeID, Label: d.label, LastSeen: d.lastSeen})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

func (s *memoryStore) AccountKeyForLogin(_ context.Context, login string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.loginIndex[normHandle(login)]
	return k, ok, nil
}

func (s *memoryStore) SetVisibility(_ context.Context, githubID uint64, appearOffline bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.accounts[accountKey(githubID)]; a != nil {
		a.appearOffline = appearOffline
	}
	return nil
}

func (s *memoryStore) PresenceOf(_ context.Context, key string, now int64) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.presenceOfLocked(key, now), nil
}

func (s *memoryStore) presenceOfLocked(key string, now int64) string {
	a := s.accounts[key]
	if a == nil {
		return "offline"
	}
	if a.appearOffline {
		return "offline"
	}
	var latest int64
	for _, d := range a.devices {
		if d.lastSeen > latest {
			latest = d.lastSeen
		}
	}
	return presenceStr(latest, now)
}

// ── Friend graph ───────────────────────────────────────────────────────────────

func (s *memoryStore) AreFriends(_ context.Context, a, b string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.friendEdges[canonicalPair(a, b)]
	return ok, nil
}

func (s *memoryStore) friendCountLocked(account string) int {
	n := 0
	for pair := range s.friendEdges {
		if pair[0] == account || pair[1] == account {
			n++
		}
	}
	return n
}

func (s *memoryStore) capBlocksLocked(account string, friendCap *int) bool {
	return friendCap != nil && s.friendCountLocked(account) >= *friendCap
}

func (s *memoryStore) expirePendingLocked(now int64) {
	for _, r := range s.friendReqs {
		if r.State == StatePending && now-r.CreatedAt > requestTTLSecs {
			r.State = StateCancelled
		}
	}
}

func (s *memoryStore) CreateFriendRequest(_ context.Context, fromAccount, fromLogin, toAccount, toLogin string, now int64, friendCap *int) (FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fromAccount == toAccount {
		return FriendRequest{}, ErrSelfRequest
	}
	if _, ok := s.friendEdges[canonicalPair(fromAccount, toAccount)]; ok {
		return FriendRequest{}, ErrAlreadyFriends
	}
	if s.capBlocksLocked(fromAccount, friendCap) {
		return FriendRequest{}, ErrCapReached
	}
	s.expirePendingLocked(now)
	// Idempotent: a duplicate pending request returns the existing one.
	for _, r := range s.friendReqs {
		if r.State == StatePending && r.FromAccount == fromAccount && r.ToAccount == toAccount {
			return *r, nil
		}
	}
	// Abuse control: bound how many requests one account can have in flight.
	pendingOut := 0
	for _, r := range s.friendReqs {
		if r.State == StatePending && r.FromAccount == fromAccount {
			pendingOut++
		}
	}
	if pendingOut >= maxPendingOutbound {
		return FriendRequest{}, ErrTooManyPending
	}
	req := &FriendRequest{
		ID:          newRequestID(),
		FromAccount: fromAccount,
		FromLogin:   fromLogin,
		ToAccount:   toAccount,
		ToLogin:     toLogin,
		CreatedAt:   now,
		State:       StatePending,
	}
	s.friendReqs[req.ID] = req
	return *req, nil
}

func (s *memoryStore) AcceptFriendRequest(_ context.Context, requestID, acceptor string, friendCap *int) (FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.friendReqs[requestID]
	if r == nil {
		return FriendRequest{}, ErrNotFound
	}
	if r.ToAccount != acceptor {
		return FriendRequest{}, ErrNotYours
	}
	if r.State != StatePending {
		return FriendRequest{}, ErrNotPending
	}
	if s.capBlocksLocked(r.FromAccount, friendCap) || s.capBlocksLocked(r.ToAccount, friendCap) {
		return FriendRequest{}, ErrCapReached
	}
	s.friendEdges[canonicalPair(r.FromAccount, r.ToAccount)] = struct{}{}
	r.State = StateAccepted
	return *r, nil
}

func (s *memoryStore) CloseFriendRequest(_ context.Context, requestID, actor string) (FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.friendReqs[requestID]
	if r == nil {
		return FriendRequest{}, ErrNotFound
	}
	if r.State != StatePending {
		return FriendRequest{}, ErrNotPending
	}
	switch actor {
	case r.ToAccount:
		r.State = StateRejected
	case r.FromAccount:
		r.State = StateCancelled
	default:
		return FriendRequest{}, ErrNotYours
	}
	return *r, nil
}

func (s *memoryStore) RemoveFriend(_ context.Context, account, other string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pair := canonicalPair(account, other)
	if _, ok := s.friendEdges[pair]; !ok {
		return false, nil
	}
	delete(s.friendEdges, pair)
	return true, nil
}

func (s *memoryStore) listFriendsLocked(account string) []Friend {
	others := []string{}
	for pair := range s.friendEdges {
		switch account {
		case pair[0]:
			others = append(others, pair[1])
		case pair[1]:
			others = append(others, pair[0])
		}
	}
	sort.Strings(others)
	out := make([]Friend, 0, len(others))
	for _, k := range others {
		login := ""
		if a := s.accounts[k]; a != nil {
			login = a.login
		}
		out = append(out, Friend{AccountKey: k, Login: login})
	}
	return out
}

func (s *memoryStore) ListFriends(_ context.Context, account string) ([]Friend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listFriendsLocked(account), nil
}

func (s *memoryStore) IncomingRequests(_ context.Context, account string, now int64) ([]FriendRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expirePendingLocked(now)
	out := []FriendRequest{}
	for _, r := range s.friendReqs {
		if r.State == StatePending && r.ToAccount == account {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *memoryStore) FriendDevices(_ context.Context, caller, friend string) ([]DeviceRow, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.friendEdges[canonicalPair(caller, friend)]; !ok {
		return nil, false, nil
	}
	return s.accountDevicesLocked(friend), true, nil
}

func (s *memoryStore) FriendCount(_ context.Context, account string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.friendCountLocked(account), nil
}

func (s *memoryStore) FriendPresence(_ context.Context, account string, now int64) ([]FriendPresence, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	friends := s.listFriendsLocked(account)
	out := make([]FriendPresence, 0, len(friends))
	for _, f := range friends {
		out = append(out, FriendPresence{
			AccountKey: f.AccountKey,
			Login:      f.Login,
			Presence:   s.presenceOfLocked(f.AccountKey, now),
		})
	}
	return out, nil
}

// Ping always succeeds: the in-process store is reachable whenever the process
// is. It still takes the lock so the probe fails fast if the store is wedged.
func (s *memoryStore) Ping(_ context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return nil
}

func (s *memoryStore) PersistenceEnabled() bool { return s.persistPath != "" }

func (s *memoryStore) Flush(_ context.Context) error { return s.flushSnapshot() }

func (s *memoryStore) Close() error { return nil }

// ── helpers ──────────────────────────────────────────────────────────────────

func lower(s string) string { return strings.ToLower(s) }

// normHandle strips a leading '@' and surrounding space, then lowercases — used
// for login-index and directory lookups.
func normHandle(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "@"))
}

// ── Users + access tokens ────────────────────────────────────────────────────

func (s *memoryStore) nextID(prefix string) string {
	s.nextIDSeq++
	return fmt.Sprintf("%s_%d", prefix, s.nextIDSeq)
}

func (s *memoryStore) CreateUser(_ context.Context, name, login string, now int64) (UserRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := UserRecord{ID: s.nextID("usr"), Name: name, Login: login, CreatedAt: now}
	s.users[u.ID] = &u
	return u, nil
}

func (s *memoryStore) ListUsers(_ context.Context) ([]UserRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserRecord, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *memoryStore) SetUserDisabled(_ context.Context, userID string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return ErrUserNotFound
	}
	u.Disabled = disabled
	return nil
}

func (s *memoryStore) IssueToken(_ context.Context, userID, label, tokenHash string, now int64) (TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return TokenRecord{}, ErrUserNotFound
	}
	rec := TokenRecord{ID: s.nextID("tok"), UserID: userID, Label: label, CreatedAt: now}
	s.tokens[rec.ID] = &memToken{rec: rec, hash: tokenHash}
	s.tokenHash[tokenHash] = rec.ID
	return rec, nil
}

func (s *memoryStore) ListTokens(_ context.Context) ([]TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TokenRecord, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t.rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (s *memoryStore) RevokeToken(_ context.Context, tokenID string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return ErrTokenNotFound
	}
	if t.rec.RevokedAt == nil {
		n := now
		t.rec.RevokedAt = &n
	}
	delete(s.tokenHash, t.hash) // no longer resolvable
	return nil
}

func (s *memoryStore) ResolveToken(_ context.Context, tokenHash string, now int64) (*TokenClaims, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.tokenHash[tokenHash]
	if !ok {
		return nil, false, nil
	}
	t := s.tokens[id]
	if t == nil || t.rec.RevokedAt != nil {
		return nil, false, nil
	}
	u := s.users[t.rec.UserID]
	if u == nil || u.Disabled {
		return nil, false, nil
	}
	t.rec.LastUsed = now
	sub := u.Login
	if sub == "" {
		sub = u.ID
	}
	return &TokenClaims{Sub: sub, Plan: "team"}, true, nil
}
