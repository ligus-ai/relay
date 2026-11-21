package relay

import (
	"context"
	"errors"
	"net/http"
)

// Room quotas (docs/tenancy.md, "Community limits" and "Per-tenant limits").
//
// A room is a workspace's stored state. Its bytes are its envelope bodies plus
// its key rotations; device blobs (candidates, presence) are bounded by their
// own per-room count cap and the memory store budget. Quotas are refusals,
// never eviction, so a flood can't push a room's founder seed out (the client
// folds the whole log from it). The handler puts a writeQuota in the request
// context; a store that sees none enforces nothing, so direct store callers
// (tests, downstream builds) keep the old behavior.

// writeQuota carries the limits for one write. Zero fields are unlimited.
type writeQuota struct {
	// Tenant owns the room ("" without tenancy). Set at room creation.
	Tenant string
	// Creator is the hashed identity of the writer (roomCreatorTag), counted
	// against CreatorMaxRooms when the write creates the room.
	Creator string

	RoomMaxBytes     int64
	RoomMaxEnvelopes int64
	TotalMaxBytes    int64
	TotalMaxRooms    int64 // live rooms across the relay (LANGSTROTH_RELAY_MAX_ROOMS)
	TenantMaxBytes   int64
	TenantMaxRooms   int64
	CreatorMaxRooms  int64
}

type quotaCtxKey struct{}

func withQuota(ctx context.Context, q *writeQuota) context.Context {
	return context.WithValue(ctx, quotaCtxKey{}, q)
}

func quotaFrom(ctx context.Context) *writeQuota {
	q, _ := ctx.Value(quotaCtxKey{}).(*writeQuota)
	return q
}

// Limit names: the label values of hive_relay_limit_rejections_total.
const (
	limRoomBytes      = "room_bytes"
	limRoomEnvelopes  = "room_envelopes"
	limTotalBytes     = "total_bytes"
	limTotalRooms     = "total_rooms"
	limStoreBytes     = "store_bytes"
	limKeyring        = "keyring"
	limTenantBytes    = "tenant_bytes"
	limTenantRooms    = "tenant_rooms"
	limClientRooms    = "client_rooms"
	limIPRate         = "ip_rate"
	limRoomRate       = "room_rate"
	limTenantRate     = "tenant_rate"
	limPairings       = "pairings"
	limPush           = "push"
	limTenantHosts    = "tenant_hosts"
	limClientInflight = "client_inflight"
)

// allLimitNames fixes the label set (and its order on /metrics).
var allLimitNames = []string{
	limRoomBytes, limRoomEnvelopes, limTotalBytes, limTotalRooms, limStoreBytes, limKeyring,
	limTenantBytes, limTenantRooms, limClientRooms, limIPRate, limRoomRate,
	limTenantRate, limPairings, limPush, limTenantHosts, limClientInflight,
}

// quotaError is a refused write. Storage quotas (storage=true) match
// ErrStoreFull, so every existing caller maps them to 507; a room-count limit
// per client is a 429.
type quotaError struct {
	limit   string
	tenant  string
	storage bool
}

func (e *quotaError) Error() string { return "relay quota reached: " + e.limit }

func (e *quotaError) Is(target error) bool { return e.storage && target == ErrStoreFull }

func errQuota(limit, tenant string) error {
	return &quotaError{limit: limit, tenant: tenant, storage: limit != limClientRooms}
}

// quotaMessages are the response bodies, so a client (or a human with curl)
// can tell which limit it hit.
var quotaMessages = map[string]string{
	limRoomBytes:     "room storage quota reached",
	limRoomEnvelopes: "room envelope quota reached",
	limTotalBytes:    "relay storage is full",
	limTotalRooms:    "relay room capacity reached",
	limStoreBytes:    "relay storage is full",
	limTenantBytes:   "tenant storage quota reached",
	limTenantRooms:   "tenant room quota reached",
	limClientRooms:   "too many rooms created by this client",
}

// quotaStatus maps a store error to a refusal (its status and stable code,
// refusal.go), recording it. ok=false when err is not a quota refusal.
func quotaStatus(err error) (status int, code, msg string, ok bool) {
	var qe *quotaError
	switch {
	case errors.As(err, &qe):
		countLimit(qe.limit, qe.tenant)
		if qe.storage {
			return http.StatusInsufficientStorage, qe.limit, quotaMessages[qe.limit], true
		}
		return http.StatusTooManyRequests, qe.limit, quotaMessages[qe.limit], true
	case errors.Is(err, ErrKeyringFull):
		countLimit(limKeyring, "")
		return http.StatusInsufficientStorage, limKeyring, "workspace keyring is full", true
	case errors.Is(err, ErrStoreFull):
		countLimit(limStoreBytes, "")
		return http.StatusInsufficientStorage, limStoreBytes, "relay storage is full", true
	}
	return 0, "", "", false
}

// roomCreatorTag is the stored identity of a room's creator: a hash, never
// the raw address or token subject.
func roomCreatorTag(key string) string {
	if key == "" {
		return ""
	}
	return sha256hex("relay-room-creator\x00" + key)
}

// RoomUsage is one room's accounted state.
type RoomUsage struct {
	Room      string // storage key (<tenant>/<id> with tenancy)
	Tenant    string
	Bytes     int64
	Envelopes int64
	LastWrite int64 // unix seconds of the last envelope or key-rotation write
}

// roomStore is implemented by both built-in stores: room accounting for the
// quotas, idle-room retention, the tenant admin routes and metrics. A
// downstream Store without it keeps compiling; quotas, retention and the
// tenant routes are then off for it.
type roomStore interface {
	// RoomTotals returns the number of live rooms and their bytes.
	RoomTotals(ctx context.Context) (rooms, bytes int64, err error)
	// TenantUsage returns one tenant's bytes and live rooms.
	TenantUsage(ctx context.Context, tenant string) (bytes, rooms int64, err error)
	// ListRooms returns up to limit live rooms of tenant whose key sorts
	// after `after` (a full storage key), in key order.
	ListRooms(ctx context.Context, tenant, after string, limit int) ([]RoomUsage, error)
	// PurgeRoom deletes a room's envelopes, key rotations, device blobs,
	// roster and invites. Its sequence counter is kept. ok=false if the room
	// held nothing.
	PurgeRoom(ctx context.Context, room string) (bool, error)
	// PruneIdleRooms deletes the envelopes, key rotations and device blobs
	// of every room with no envelope or key-rotation write since cutoff
	// (unix seconds), keeping its sequence counter, roster and invites.
	// Returns the number of rooms expired.
	PruneIdleRooms(ctx context.Context, cutoff int64) (int64, error)
}

// tenantRoomPrefix is the storage-key prefix of a tenant's rooms.
func tenantRoomPrefix(tenant string) string {
	if tenant == "" {
		return ""
	}
	return tenant + "/"
}
