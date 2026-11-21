package relay

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// /v1/contacts/ (relay v0.3): opaque contact records and sealed drop boxes.
// See contacts_store.go for the storage model and docs/reference.md "Contacts" for the
// wire contract. The routes go through the access gate like every other
// /v1 route. They never read, verify or forward a forge token: a request that
// carries one is refused (400), so a misbehaving client finds out at once.

const (
	contactKeyHeader = "X-Ligus-Contact-Key"

	cidRawBytes      = 16 // cid = 16 random bytes, base64url (22 chars, no padding)
	writeKeyRawBytes = 32 // write key = 32 random bytes, base64url (43 chars, no padding)

	defaultContactMaxRecordBytes = 64 << 10
	defaultContactMaxDropBytes   = 64 << 10
	defaultContactTTLDays        = 30
	defaultContactMaxContacts    = 100000 // memory store only
	// Drop box: the same row cap as the account inbox, plus a byte cap so a
	// box can't hold rows x 64 KiB.
	defaultContactDropMaxRows      = defaultInboxMaxRows
	defaultContactDropMaxBoxBytes  = 4 << 20
	defaultContactDropRetentionDay = 30
	// An expired cid stays reserved for its old write key this long.
	defaultContactReclaimHoldDays = 180
	defaultContactDropPage        = 100
	maxContactDropPage            = 1000

	// Drops reuse the account-invite limits per (sender, box): ~3/min
	// sustained, burst 10. Per box (all senders) and per record writes are
	// bounded too.
	defaultContactDropRate     = defaultInviteRate
	defaultContactDropBurst    = defaultInviteBurst
	defaultContactDropCIDRate  = 1.0
	defaultContactDropCIDBurst = 60.0
	defaultContactWriteRate    = 0.2 // record updates per cid
	defaultContactWriteBurst   = 10.0
	defaultContactCreateRate   = 0.01 // new records per client (~36/hour)
	defaultContactCreateBurst  = 20.0
)

type contactConfig struct {
	enabled        bool
	maxRecordBytes int
	maxDropBytes   int
	ttl            time.Duration
	dropMaxAge     time.Duration
	limits         ContactLimits
}

func contactConfigFromEnv() contactConfig {
	enabled := true
	switch strings.ToLower(strings.TrimSpace(getenv("LANGSTROTH_RELAY_CONTACTS"))) {
	case "0", "false", "no", "off":
		enabled = false
	}
	pos := func(name string, def int64) int {
		if n := envInt64(name, def); n > 0 {
			return int(n)
		}
		return int(def)
	}
	nonNeg := func(name string, def int64) int {
		if n := envInt64(name, def); n >= 0 {
			return int(n)
		}
		return int(def)
	}
	return contactConfig{
		enabled:        enabled,
		maxRecordBytes: pos("LANGSTROTH_RELAY_CONTACT_MAX_RECORD_BYTES", defaultContactMaxRecordBytes),
		maxDropBytes:   pos("LANGSTROTH_RELAY_CONTACT_MAX_DROP_BYTES", defaultContactMaxDropBytes),
		ttl:            time.Duration(pos("LANGSTROTH_RELAY_CONTACT_TTL_DAYS", defaultContactTTLDays)) * 24 * time.Hour,
		dropMaxAge:     daysEnv("LANGSTROTH_RELAY_CONTACT_DROP_RETENTION_DAYS", defaultContactDropRetentionDay),
		limits: ContactLimits{
			MaxContacts:     nonNeg("LANGSTROTH_RELAY_MAX_CONTACTS", defaultContactMaxContacts),
			DropMaxRows:     pos("LANGSTROTH_RELAY_CONTACT_DROP_MAX_ROWS", defaultContactDropMaxRows),
			DropMaxBoxBytes: pos("LANGSTROTH_RELAY_CONTACT_DROP_MAX_BOX_BYTES", defaultContactDropMaxBoxBytes),
			ReclaimHold:     time.Duration(nonNeg("LANGSTROTH_RELAY_CONTACT_RECLAIM_HOLD_DAYS", defaultContactReclaimHoldDays)) * 24 * time.Hour,
			MaxBytes:        max(envInt64("LANGSTROTH_RELAY_MAX_CONTACT_BYTES", 0), 0),
		},
	}
}

// contactLimiters are the per-instance rate limits of the contacts routes.
type contactLimiters struct {
	drop    *ipRateLimiter // per (sender, cid)
	dropCID *ipRateLimiter // per cid, all senders
	write   *ipRateLimiter // record updates per cid (owner only)
	create  *ipRateLimiter // new records per client
	// create48 bounds new records per IPv6 /48 (a client is keyed by its /64,
	// and one /48 holds 65536 of them): createSlash48Factor times create's
	// rate and burst. Not applied to token subjects or IPv4.
	create48 *ipRateLimiter
}

const createSlash48Factor = 16

// slash48Key returns the IPv6 /48 of the client address, or "" for IPv4.
func slash48Key(r *http.Request) string {
	a, err := netip.ParseAddr(clientIP(r))
	if err != nil || !a.Is6() || a.Is4In6() {
		return ""
	}
	return netip.PrefixFrom(a, 48).Masked().String()
}

// allowCreate spends one create token for the client (and its /48).
func (l contactLimiters) allowCreate(r *http.Request) (bool, time.Duration) {
	tag := writerTag(r.Context(), clientKey(r))
	if ok, wait := l.create.allowWait(tag); !ok {
		return false, wait
	}
	if strings.HasPrefix(tag, "ip:") {
		if k := slash48Key(r); k != "" {
			if ok, wait := l.create48.allowWait(k); !ok {
				return false, wait
			}
		}
	}
	return true, 0
}

func contactLimitersFromEnv() contactLimiters {
	return contactLimiters{
		drop:    newIPRateLimiter(envFloat("LANGSTROTH_RELAY_CONTACT_DROP_RATE", defaultContactDropRate), envFloat("LANGSTROTH_RELAY_CONTACT_DROP_BURST", defaultContactDropBurst)),
		dropCID: newIPRateLimiter(envFloat("LANGSTROTH_RELAY_CONTACT_DROP_CID_RATE", defaultContactDropCIDRate), envFloat("LANGSTROTH_RELAY_CONTACT_DROP_CID_BURST", defaultContactDropCIDBurst)),
		write:   newIPRateLimiter(envFloat("LANGSTROTH_RELAY_CONTACT_WRITE_RATE", defaultContactWriteRate), envFloat("LANGSTROTH_RELAY_CONTACT_WRITE_BURST", defaultContactWriteBurst)),
		create:  newIPRateLimiter(envFloat("LANGSTROTH_RELAY_CONTACT_CREATE_RATE", defaultContactCreateRate), envFloat("LANGSTROTH_RELAY_CONTACT_CREATE_BURST", defaultContactCreateBurst)),
		create48: newIPRateLimiter(createSlash48Factor*envFloat("LANGSTROTH_RELAY_CONTACT_CREATE_RATE", defaultContactCreateRate),
			createSlash48Factor*envFloat("LANGSTROTH_RELAY_CONTACT_CREATE_BURST", defaultContactCreateBurst)),
	}
}

func (s *Server) registerContacts(mux *http.ServeMux) {
	if s.contacts == nil {
		return // off, or the Store doesn't implement ContactStore → 404
	}
	mux.HandleFunc("PUT /v1/contacts/{cid}", s.contactPut)
	mux.HandleFunc("GET /v1/contacts/{cid}", s.contactGet)
	mux.HandleFunc("DELETE /v1/contacts/{cid}", s.contactDelete)
	mux.HandleFunc("POST /v1/contacts/{cid}/drop", s.contactDropPost)
	mux.HandleFunc("GET /v1/contacts/{cid}/drop", s.contactDropList)
	mux.HandleFunc("DELETE /v1/contacts/{cid}/drop", s.contactDropAck)
}

// validCID reports whether c is base64url (no padding) of exactly 16 bytes,
// so a cid always carries 128 random bits and is safe as a path and key.
func validCID(c string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(c)
	return err == nil && len(b) == cidRawBytes
}

// contactKeyHash validates a write key (base64url, no padding, 32 bytes) and
// returns its hex SHA-256 ("" when malformed).
func contactKeyHash(k string) string {
	b, err := base64.RawURLEncoding.Strict().DecodeString(k)
	if err != nil || len(b) != writeKeyRawBytes {
		return ""
	}
	return sha256hex(k)
}

// forgeTokenHeaderSuffixes name request headers that carry a forge credential.
var forgeTokenHeaderSuffixes = []string{
	"-github-token", "-gitlab-token", "-gitea-token", "-forgejo-token", "-forge-token",
}

// forgeTokenPrefixes are well-known forge token formats; one sent as the
// bearer on a contacts route is refused, never used.
var forgeTokenPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-"}

// carriesForgeToken reports whether the request carries a forge token in any
// header. It never logs or returns the value.
func carriesForgeToken(r *http.Request) bool {
	for name, vals := range r.Header {
		n := strings.ToLower(name)
		for _, suf := range forgeTokenHeaderSuffixes {
			if strings.HasSuffix(n, suf) {
				for _, v := range vals {
					if strings.TrimSpace(v) != "" {
						return true
					}
				}
			}
		}
	}
	bt := bearerToken(r)
	for _, p := range forgeTokenPrefixes {
		if strings.HasPrefix(bt, p) {
			return true
		}
	}
	return false
}

// contactPreamble runs the checks shared by every contacts route. It writes
// the error response and returns ("", false) on failure.
func (s *Server) contactPreamble(w http.ResponseWriter, r *http.Request) (string, bool) {
	if carriesForgeToken(r) {
		http.Error(w, "forge tokens are not accepted by the relay", http.StatusBadRequest)
		return "", false
	}
	cid := r.PathValue("cid")
	if !validCID(cid) {
		http.Error(w, "invalid contact id", http.StatusBadRequest)
		return "", false
	}
	// Tenancy: a contact and its drop box live in the caller's tenant.
	return tenantKey(r.Context(), cid), true
}

// ownerKey reads the owner's capability from X-Ligus-Contact-Key.
func ownerKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	k := strings.TrimSpace(r.Header.Get(contactKeyHeader))
	if k == "" {
		http.Error(w, "contact key required", http.StatusUnauthorized)
		return "", false
	}
	h := contactKeyHash(k)
	if h == "" {
		http.Error(w, "invalid contact key", http.StatusBadRequest)
		return "", false
	}
	return h, true
}

// contactErr maps a ContactStore error to a status. Returns true if handled.
func contactErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrContactNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, ErrContactKey):
		http.Error(w, "contact key does not match", http.StatusForbidden)
	case errors.Is(err, ErrContactsFull):
		refuse(w, http.StatusInsufficientStorage, refContactsFull, "relay contact capacity reached", quotaRetry(refContactsFull))
	default:
		if !errors.Is(err, ErrStoreFull) {
			slog.Error("contact store error", "error", err)
		}
		return storeErr(w, err)
	}
	return true
}

// capBody bounds a contacts request body below the relay-wide cap.
func capBody(w http.ResponseWriter, r *http.Request, payload int) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(payload)+4096)
}

func isNullJSON(b json.RawMessage) bool {
	t := strings.TrimSpace(string(b))
	return t == "" || t == "null"
}

type contactPutReq struct {
	Record   json.RawMessage `json:"record"`
	WriteKey string          `json:"writeKey"`
}

// contactPut: PUT /v1/contacts/{cid} {record, writeKey?}. The first write
// sets the write key (body writeKey, or the header); every later write must
// present the same key (header, or the body's writeKey).
func (s *Server) contactPut(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.contactPreamble(w, r)
	if !ok || !s.limitWrite(w, r) {
		return
	}
	capBody(w, r, s.contactCfg.maxRecordBytes)
	var req contactPutReq
	if !readJSON(w, r, &req) {
		return
	}
	if isNullJSON(req.Record) {
		http.Error(w, "record required", http.StatusBadRequest)
		return
	}
	if len(req.Record) > s.contactCfg.maxRecordBytes {
		http.Error(w, "record too large", http.StatusRequestEntityTooLarge)
		return
	}
	// Byte-exact storage needs valid UTF-8: the snapshot would rewrite it and
	// Postgres TEXT refuses it.
	if !utf8.Valid(req.Record) {
		http.Error(w, "record is not valid UTF-8", http.StatusBadRequest)
		return
	}
	hdr := strings.TrimSpace(r.Header.Get(contactKeyHeader))
	body := strings.TrimSpace(req.WriteKey)
	if hdr != "" && body != "" && hdr != body {
		http.Error(w, "header and body write keys differ", http.StatusBadRequest)
		return
	}
	key := hdr
	if key == "" {
		key = body
	}
	if key == "" {
		http.Error(w, "contact key required", http.StatusUnauthorized)
		return
	}
	keyHash := contactKeyHash(key)
	if keyHash == "" {
		http.Error(w, "invalid contact key", http.StatusBadRequest)
		return
	}
	now := nowUnix()
	existing, err := s.contacts.GetContact(r.Context(), cid, now)
	if contactErr(w, err) {
		return
	}
	switch {
	case existing != nil && !constantTimeEq(existing.WriteKeyHash, keyHash):
		// Refused before any limiter, so a stranger who knows the cid can't
		// spend the owner's write budget. The store re-checks atomically.
		contactErr(w, ErrContactKey)
		return
	case existing == nil:
		if ok, wait := s.contactLim.allowCreate(r); !ok {
			refuse(w, http.StatusTooManyRequests, refContactCreate, "too many new contacts from this client", wait)
			return
		}
	case rateRefused(w, s.contactLim.write, cid, refContactWrite, "too many writes to this contact"):
		return
	}
	exp := now + int64(s.contactCfg.ttl/time.Second)
	created, err := s.contacts.PutContact(r.Context(), cid, keyHash, req.Record, now, exp, s.contactCfg.limits)
	if contactErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": created, "updatedAt": now, "expiresAt": exp})
}

// contactGet: GET /v1/contacts/{cid} → {record, updatedAt}.
func (s *Server) contactGet(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.contactPreamble(w, r)
	if !ok {
		return
	}
	if rateRefused(w, s.readLimiter, clientKey(r), refReadRate, "rate limit exceeded") {
		return
	}
	rec, err := s.contacts.GetContact(r.Context(), cid, nowUnix())
	if contactErr(w, err) {
		return
	}
	if rec == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeRawJSON(w, []byte(`{"record":`), rec.Record, []byte(`,"updatedAt":`+strconv.FormatInt(rec.UpdatedAt, 10)+`}`))
}

// writeRawJSON writes a 200 JSON body assembled from parts. Opaque client
// JSON (records, blobs) is spliced in verbatim: encoding/json would compact
// it, and clients verify signatures over what they published. Every spliced
// value was syntax-checked by readJSON when it was stored.
func writeRawJSON(w http.ResponseWriter, parts ...[]byte) {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	buf := make([]byte, 0, n)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

// contactDelete: DELETE /v1/contacts/{cid} (contact key) → record + drop box gone.
func (s *Server) contactDelete(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.contactPreamble(w, r)
	if !ok || !s.limitWrite(w, r) {
		return
	}
	keyHash, ok := ownerKey(w, r)
	if !ok {
		return
	}
	if contactErr(w, s.contacts.DeleteContact(r.Context(), cid, keyHash, nowUnix())) {
		return
	}
	writeJSON(w, http.StatusOK, okResp())
}

type contactDropReq struct {
	Blob json.RawMessage `json:"blob"`
}

// contactDropPost: POST /v1/contacts/{cid}/drop {blob}. Anyone who knows the
// cid may drop (gate only); the blob is sealed client-side and opaque here.
// The answer doesn't reveal the box's sequence (other senders' volume).
func (s *Server) contactDropPost(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.contactPreamble(w, r)
	if !ok || !s.limitWrite(w, r) {
		return
	}
	if rateRefused(w, s.contactLim.drop, writerTag(r.Context(), clientKey(r))+"->"+cid, refContactDrop, "too many drops to this contact") ||
		rateRefused(w, s.contactLim.dropCID, cid, refContactDrop, "too many drops to this contact") {
		return
	}
	capBody(w, r, s.contactCfg.maxDropBytes)
	var req contactDropReq
	if !readJSON(w, r, &req) {
		return
	}
	if isNullJSON(req.Blob) {
		http.Error(w, "blob required", http.StatusBadRequest)
		return
	}
	if len(req.Blob) > s.contactCfg.maxDropBytes {
		http.Error(w, "blob too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !utf8.Valid(req.Blob) {
		http.Error(w, "blob is not valid UTF-8", http.StatusBadRequest)
		return
	}
	c := claimsFrom(r.Context())
	sender := DropSender{Tag: writerTag(r.Context(), clientKey(r)), Verified: c != nil && c.Sub != ""}
	if _, err := s.contacts.AppendContactDrop(WithDropSender(r.Context(), sender), cid, req.Blob, nowUnix(), s.contactCfg.limits); contactErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, okResp())
}

// contactDropList: GET /v1/contacts/{cid}/drop?after=<seq>[&limit=n] (contact
// key) → {items:[{seq, blob, createdAt}], more}. Non-destructive, so several
// devices of one account can read the box with their own cursors; the owner
// deletes what it has processed with DELETE …/drop?through=<seq>.
func (s *Server) contactDropList(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.contactPreamble(w, r)
	if !ok {
		return
	}
	if rateRefused(w, s.readLimiter, clientKey(r), refReadRate, "rate limit exceeded") {
		return
	}
	keyHash, ok := ownerKey(w, r)
	if !ok {
		return
	}
	limit := defaultContactDropPage
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, maxContactDropPage)
		}
	}
	items, more, err := s.contacts.ContactDropsAfter(r.Context(), cid, keyHash, afterParam(r), limit, s.maxListBytes, nowUnix())
	if contactErr(w, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	parts := make([][]byte, 0, 2+5*len(items))
	parts = append(parts, []byte(`{"items":[`))
	for i, d := range items {
		sep := `{"seq":`
		if i > 0 {
			sep = `,{"seq":`
		}
		parts = append(parts, []byte(sep+strconv.FormatUint(d.Seq, 10)+`,"blob":`), d.Blob,
			[]byte(`,"createdAt":`+strconv.FormatInt(d.CreatedAt, 10)+`}`))
	}
	parts = append(parts, []byte(`],"more":`+strconv.FormatBool(more)+`}`))
	writeRawJSON(w, parts...)
}

// contactDropAck: DELETE /v1/contacts/{cid}/drop?through=<seq> (contact key)
// deletes every drop with seq <= through → {ok, deleted}.
func (s *Server) contactDropAck(w http.ResponseWriter, r *http.Request) {
	cid, ok := s.contactPreamble(w, r)
	if !ok || !s.limitWrite(w, r) {
		return
	}
	keyHash, ok := ownerKey(w, r)
	if !ok {
		return
	}
	through, err := strconv.ParseUint(r.URL.Query().Get("through"), 10, 64)
	if err != nil {
		http.Error(w, "through=<seq> required", http.StatusBadRequest)
		return
	}
	n, err := s.contacts.AckContactDrops(r.Context(), cid, keyHash, through, nowUnix())
	if contactErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": n})
}
