package relay

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Community limits (docs/tenancy.md). Every one is off (0) by default.
type communityLimits struct {
	roomMaxBytes      int64 // LANGSTROTH_RELAY_ROOM_MAX_BYTES
	roomMaxEnvelopes  int64 // LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES
	totalMaxBytes     int64 // LANGSTROTH_RELAY_MAX_TOTAL_ROOM_BYTES
	totalMaxRooms     int64 // LANGSTROTH_RELAY_MAX_ROOMS
	maxRoomsPerClient int64 // LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT
	roomRetention     time.Duration

	ip   *ipRateLimiter // LANGSTROTH_RELAY_IP_RATE / _BURST: every request per client
	room *ipRateLimiter // LANGSTROTH_RELAY_ROOM_RATE / _BURST: every request per room

	// LANGSTROTH_RELAY_MAX_INFLIGHT_PER_CLIENT: ordinary requests one client
	// may hold open at once (inflight), and an IPv6 /48 in total
	// (inflight48, inflightSlash48Factor times as many).
	inflight   *keyedConcurrencyLimiter
	inflight48 *keyedConcurrencyLimiter
}

// One IPv6 /48 holds 65536 client /64s; together they may hold this many
// times the per-client in-flight cap.
const inflightSlash48Factor = 16

// inflightPath reports whether the per-client in-flight cap applies to path:
// every limited route but the ones with their own concurrency caps (event
// streams, the tunnel's WebSockets, blob transfers).
func inflightPath(path string) bool {
	return limitedPath(path) && !strings.HasPrefix(path, "/v1/tunnel/") &&
		!strings.HasSuffix(path, "/events") && !strings.Contains(path, "/blobs")
}

// acquireInflight takes an in-flight slot for r's client (and its /48);
// ok=false means the client is at its cap.
func (l communityLimits) acquireInflight(r *http.Request) (release func(), ok bool) {
	rel, ok := l.inflight.acquire(clientKey(r))
	if !ok {
		return rel, false
	}
	if k := slash48Key(r); k != "" {
		rel48, ok := l.inflight48.acquire(k)
		if !ok {
			rel()
			return rel48, false
		}
		return func() { rel48(); rel() }, true
	}
	return rel, true
}

func communityLimitsFromEnv() communityLimits {
	pos := func(name string) int64 { return max(envInt64(name, 0), 0) }
	l := communityLimits{
		roomMaxBytes:      pos("LANGSTROTH_RELAY_ROOM_MAX_BYTES"),
		roomMaxEnvelopes:  pos("LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES"),
		totalMaxBytes:     pos("LANGSTROTH_RELAY_MAX_TOTAL_ROOM_BYTES"),
		totalMaxRooms:     pos("LANGSTROTH_RELAY_MAX_ROOMS"),
		maxRoomsPerClient: pos("LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT"),
		roomRetention:     daysEnv("LANGSTROTH_RELAY_ROOM_RETENTION_DAYS", 0),
	}
	if r := envFloat("LANGSTROTH_RELAY_IP_RATE", 0); r > 0 {
		l.ip = newIPRateLimiter(r, max(envFloat("LANGSTROTH_RELAY_IP_BURST", r*2), 1))
	}
	if n := pos("LANGSTROTH_RELAY_MAX_INFLIGHT_PER_CLIENT"); n > 0 {
		l.inflight = newKeyedConcurrencyLimiter(n)
		l.inflight48 = newKeyedConcurrencyLimiter(n * inflightSlash48Factor)
	}
	if r := envFloat("LANGSTROTH_RELAY_ROOM_RATE", 0); r > 0 {
		l.room = newIPRateLimiter(r, max(envFloat("LANGSTROTH_RELAY_ROOM_BURST", r*2), 1))
	}
	return l
}

// tooMany writes a 429 refusal for limit (refusal.go) and counts it.
func tooMany(w http.ResponseWriter, limit, tenant string, wait time.Duration, msg string) {
	countLimit(limit, tenant)
	refuse(w, http.StatusTooManyRequests, limit, msg, wait)
}

// limitedPath reports whether the per-client request rate applies to path:
// everything but the status page, health and metrics.
func limitedPath(path string) bool {
	return path != "/" && path != "/v1/health" && path != "/metrics"
}

// quotaFor builds the write quotas for a request (relay-wide limits, then
// the caller's tenant's).
func (s *Server) quotaFor(r *http.Request) *writeQuota {
	ctx := r.Context()
	q := &writeQuota{
		Creator:          roomCreatorTag(writerTag(ctx, clientKey(r))),
		RoomMaxBytes:     s.lim.roomMaxBytes,
		RoomMaxEnvelopes: s.lim.roomMaxEnvelopes,
		TotalMaxBytes:    s.lim.totalMaxBytes,
		TotalMaxRooms:    s.lim.totalMaxRooms,
		CreatorMaxRooms:  s.lim.maxRoomsPerClient,
	}
	if t := tenantFrom(ctx); t != nil {
		q.Tenant = t.id
		q.TenantMaxBytes = t.limits.MaxBytes
		q.TenantMaxRooms = t.limits.MaxRooms
		if t.limits.RoomMaxBytes > 0 {
			q.RoomMaxBytes = t.limits.RoomMaxBytes
		}
		if t.limits.RoomMaxEnvelopes > 0 {
			q.RoomMaxEnvelopes = t.limits.RoomMaxEnvelopes
		}
	}
	return q
}

// roomRetentionLoop expires idle rooms hourly (LANGSTROTH_RELAY_ROOM_RETENTION_DAYS).
func roomRetentionLoop(rs roomStore, idle time.Duration, stop <-chan struct{}) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			runPrune("idle_rooms", func() (int64, error) {
				return rs.PruneIdleRooms(context.Background(), time.Now().Add(-idle).Unix())
			})
		}
	}
}

// logLimits says at startup which community limits are on.
func (l communityLimits) log() {
	if l.roomMaxBytes == 0 && l.roomMaxEnvelopes == 0 && l.totalMaxBytes == 0 && l.totalMaxRooms == 0 && l.maxRoomsPerClient == 0 &&
		l.roomRetention == 0 && l.ip == nil && l.room == nil && l.inflight == nil {
		return
	}
	attrs := []any{
		"room_max_bytes", l.roomMaxBytes, "room_max_envelopes", l.roomMaxEnvelopes,
		"total_max_bytes", l.totalMaxBytes, "max_rooms", l.totalMaxRooms, "max_rooms_per_client", l.maxRoomsPerClient,
		"room_retention_days", int(l.roomRetention / (24 * time.Hour)),
	}
	if l.ip != nil {
		attrs = append(attrs, "ip_rate", l.ip.rate, "ip_burst", l.ip.burst)
	}
	if l.room != nil {
		attrs = append(attrs, "room_rate", l.room.rate, "room_burst", l.room.burst)
	}
	if l.inflight != nil {
		attrs = append(attrs, "max_inflight_per_client", l.inflight.max)
	}
	slog.Info("community limits", attrs...)
}
