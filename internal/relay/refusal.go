package relay

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Refusals (docs/reference.md, "Refusals: 429 and 507"). Every 429 and 507 the relay
// sends carries a Retry-After header (whole seconds, at least 1) and a JSON
// body with a stable machine-readable code:
//
//	{"error": "<code>", "message": "<for humans>", "retryAfter": <seconds>}
//
// The code says what to do: a rate code clears by itself after retryAfter; a
// room or tenant quota code (507) won't clear until the room is emptied or
// the operator raises the limit, so retryAfter there is long and a client
// should surface it instead of retrying in a loop.

// Codes that are not quota-limit names (quota.go holds the others).
const (
	refWriteRate      = "write_rate"       // per-client write rate (LANGSTROTH_RELAY_PUSH_RATE)
	refReadRate       = "read_rate"        // per-client read rate (LANGSTROTH_RELAY_READ_RATE)
	refRoomWriterRate = "room_writer_rate" // one writer's appends to one room
	refSSEStreams     = "sse_streams"      // concurrent event streams per client
	refPairLockout    = "pair_lockout"     // too many failed pairing-code guesses
	refPairCodes      = "pair_codes"       // too many live pairing codes from one client
	refClientInflight = "client_inflight"  // too many requests in progress from one client
	refContactsFull   = "contacts_full"    // the relay's contact capacity
	refContactCreate  = "contact_create_rate"
	refContactWrite   = "contact_write_rate"
	refContactDrop    = "contact_drop_rate"
	refRateLimited    = "rate_limited" // other per-client rates (GitHub routes, tunnel revoke)
	refTooManyPending = "too_many_pending"
)

// Retry-After for refusals that no token bucket times.
const (
	retryQuota     = time.Hour        // a room or tenant quota: needs a purge or a higher limit
	retryStoreFull = 10 * time.Minute // relay-wide storage: retention or the operator frees it
	retrySSE       = 5 * time.Second  // a stream of this client's closes
	retryPairCodes = time.Minute      // one of this client's codes is resolved or expires
	retryInflight  = time.Second      // one of this client's requests finishes

)

// quotaRetry is the Retry-After for a storage refusal code.
func quotaRetry(code string) time.Duration {
	switch code {
	case limTotalBytes, limTotalRooms, limStoreBytes, refContactsFull, limBlobTotalBytes:
		return retryStoreFull
	}
	return retryQuota
}

type refusalBody struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	RetryAfter int64  `json:"retryAfter"`
}

// refuse writes a 429 or 507 refusal with Retry-After and the JSON code.
func refuse(w http.ResponseWriter, status int, code, msg string, wait time.Duration) {
	secs := int64(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	b, _ := json.Marshal(refusalBody{Error: code, Message: msg, RetryAfter: secs})
	h := w.Header()
	h.Set("Retry-After", strconv.FormatInt(secs, 10))
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

// rateRefused answers a token-bucket refusal of key by l with 429 and the
// bucket's wait. ok=true means the request may go on.
func rateRefused(w http.ResponseWriter, l *ipRateLimiter, key, code, msg string) bool {
	ok, wait := l.allowWait(key)
	if ok {
		return false
	}
	refuse(w, http.StatusTooManyRequests, code, msg, wait)
	return true
}
