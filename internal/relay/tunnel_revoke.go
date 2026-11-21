package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// POST /v1/tunnel/revoke: a host revokes one of its phones over plain HTTPS,
// signed with its registered host key (the key its control connection
// authenticates with). It does what the control connection's `revoke` does
// (record the revocation until exp, drop the phone's push token, close its
// live sessions with 4003), but it doesn't need the control connection to
// be up, and it answers with what it did, so the host can show per-step
// status. Additive: the control `revoke` is unchanged.
//
// Request (JSON):
//
//	{"v":1, "hostId", "pid", "exp", "ts", "nonce": b64u(16 bytes), "sig": b64u(64 bytes)}
//
// sig = Ed25519(host key, hostRevokeMessage(hostId, pid, exp, ts, nonce)).
// ts must be within ±tunnelSkewSecs of the relay's clock, and each
// (hostId, nonce) is accepted once. Only the host the pairing belongs to can
// sign for its host id; a host revoking a pid under its own id touches only
// its own state.
//
// Answers: 200 {"ok":true,"pid","revokedUntil","sessionsClosed","pushTokenRemoved"};
// 400 malformed; 401 unknown host or bad signature ({"error":"unauthorized"},
// counted against the address) or ts outside the window ({"error":
// "clock_skew","now":<relay unix time>}, not counted); 409 replayed;
// 429 too many failed attempts from this address; 503 store unavailable.

// hostRevokeLabel is the ctx label of the signed preimage (new; additive to
// the frozen hive-tunnel/1 labels, none of which change).
const hostRevokeLabel = "host-revoke"

const hostRevokeMaxBody = 2048

// hostRevokeMessage is the signed preimage: ctx("host-revoke", hostId, pid,
// u64be(exp), u64be(ts), nonce). hostId and pid are 22 characters and the
// nonce 16 bytes, so the concatenation is unambiguous.
func hostRevokeMessage(hostID, pid string, exp, ts int64, nonce []byte) []byte {
	var nums [16]byte
	binary.BigEndian.PutUint64(nums[:8], uint64(exp))
	binary.BigEndian.PutUint64(nums[8:], uint64(ts))
	return tunnelCtx(hostRevokeLabel, []byte(hostID), []byte(pid), nums[:8], nums[8:], nonce)
}

type hostRevokeReq struct {
	V      *int   `json:"v"`
	HostID string `json:"hostId"`
	PID    string `json:"pid"`
	Exp    *int64 `json:"exp"`
	TS     *int64 `json:"ts"`
	Nonce  string `json:"nonce"`
	Sig    string `json:"sig"`
}

// replayCache remembers accepted (hostId, nonce) pairs until their ts falls
// out of the skew window, after which the ts check alone refuses them. Each
// host may hold at most perHost live entries, so one host (every host on an
// open relay can sign for itself) can't fill it and lock the others out.
type replayCache struct {
	mu      sync.Mutex
	seen    map[string]int64 // key -> forget after (unix)
	perHost map[string]int   // host -> live entries
	max     int
	hostMax int
}

func newReplayCache(max int) *replayCache {
	hostMax := max / 8
	if hostMax < 1 {
		hostMax = 1
	}
	return &replayCache{seen: map[string]int64{}, perHost: map[string]int{}, max: max, hostMax: hostMax}
}

// claim records host|nonce. ok=false when it was already seen (a replay);
// hostFull when this host has too many live entries; full when the whole
// cache is full of live entries (the caller may still apply the request:
// a host revocation is idempotent, so a replay of it changes nothing).
func (c *replayCache) claim(host, nonce string, until, now int64) (ok, hostFull, full bool) {
	key := host + "|" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, dup := c.seen[key]; dup && exp > now {
		return false, false, false
	}
	if c.perHost[host] >= c.hostMax || len(c.seen) >= c.max {
		c.pruneLocked(now)
	}
	if c.perHost[host] >= c.hostMax {
		return false, true, false
	}
	if len(c.seen) >= c.max {
		return true, false, true
	}
	if _, dup := c.seen[key]; !dup {
		c.perHost[host]++
	}
	c.seen[key] = until
	return true, false, false
}

func (c *replayCache) prune(now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
}

func (c *replayCache) pruneLocked(now int64) {
	for k, exp := range c.seen {
		if exp <= now {
			delete(c.seen, k)
			host, _, _ := strings.Cut(k, "|")
			if c.perHost[host]--; c.perHost[host] <= 0 {
				delete(c.perHost, host)
			}
		}
	}
}

func (h *tunnelHub) handleRevokeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientKey(r)
	now := h.now()
	if h.authFail.blocked(ip, now) {
		refuse(w, http.StatusTooManyRequests, refRateLimited, "too many failed revocations from this client", h.authFail.wait(ip, now))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, hostRevokeMaxBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol"})
		return
	}
	var m hostRevokeReq
	if json.NewDecoder(bytes.NewReader(raw)).Decode(&m) != nil || m.V == nil || *m.V != 1 || m.Exp == nil || m.TS == nil ||
		!validTunnelID(m.HostID) || !validTunnelID(m.PID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol"})
		return
	}
	nonce, ok1 := b64uFixed(m.Nonce, 16)
	sig, ok2 := b64uFixed(m.Sig, ed25519.SignatureSize)
	if !ok1 || !ok2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "protocol"})
		return
	}
	unauthorized := func(why string) {
		h.authFail.note(ip, now)
		slog.Warn("tunnel revoke refused", "host", m.HostID, "reason", why)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rec, err := h.store.TunnelHost(ctx, m.HostID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "internal"})
		return
	}
	if rec == nil || len(rec.Pub) != ed25519.PublicKeySize {
		unauthorized("unknown host")
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(rec.Pub), hostRevokeMessage(m.HostID, m.PID, *m.Exp, *m.TS, nonce), sig) {
		unauthorized("bad signature")
		return
	}
	t := now.Unix()
	if *m.TS < t-tunnelSkewSecs || *m.TS > t+tunnelSkewSecs {
		// The host's own valid signature: a skewed clock (or a stale
		// replay), not a guess. Not counted against the address (a real
		// host retrying would block itself from the tunnel); the relay's
		// time lets the host correct.
		slog.Warn("tunnel revoke refused", "host", m.HostID, "reason", "timestamp outside the skew window")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "clock_skew", "now": t})
		return
	}
	// Single use: kept until the ts can no longer pass the window above.
	ok, hostFull, full := h.revokeSeen.claim(m.HostID, m.Nonce, *m.TS+tunnelSkewSecs+1, t)
	if hostFull {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
		return
	}
	if full {
		// Every host's quota together filled the cache: apply it unrecorded
		// rather than refuse a revocation (it is idempotent).
		slog.Warn("tunnel revoke replay cache full; applying unrecorded", "host", m.HostID)
	}
	if !ok {
		slog.Warn("tunnel revoke replayed", "host", m.HostID)
		writeJSON(w, http.StatusConflict, map[string]string{"error": "replayed"})
		return
	}

	closed, removed, until, err := h.revokePhone(ctx, m.HostID, m.PID, *m.Exp)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "internal"})
		return
	}
	slog.Info("tunnel phone revoked", "host", m.HostID, "pid", m.PID, "via", "http", "sessions_closed", closed, "push_token_removed", removed)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "pid": m.PID, "revokedUntil": until, "sessionsClosed": closed, "pushTokenRemoved": removed,
	})
}

// revokePhone records (hostID, pid) as revoked until exp (capped at the
// longest credential lifetime), drops its push token and closes its live
// sessions. Idempotent. Returns the sessions closed, whether a push token
// was removed, and the recorded expiry (0: nothing left to refuse).
func (h *tunnelHub) revokePhone(ctx context.Context, hostID, pid string, exp int64) (int, bool, int64, error) {
	now := h.nowUnix()
	if cap := now + credMaxLifetimeSecs + tunnelSkewSecs; exp > cap {
		exp = cap
	}
	tok, err := h.store.TunnelPushToken(ctx, hostID, pid)
	if err != nil {
		return 0, false, 0, err
	}
	if exp > now {
		if err := h.store.RevokeTunnelPhone(ctx, hostID, pid, exp); err != nil {
			return 0, false, 0, err
		}
	} else {
		// Every credential it held has expired: nothing to keep, but drop
		// the push token all the same.
		if err := h.store.SetTunnelPushToken(ctx, hostID, pid, nil, now); err != nil {
			return 0, false, 0, err
		}
		exp = 0
	}
	closed := h.killSessions(hostID, pid, tcRevoked, "phone revoked by its host")
	return closed, tok != nil, exp, nil
}
