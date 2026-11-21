package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Blob channel (docs/blobs.md): opaque, end-to-end encrypted file
// attachments. A client seals a file with its workspace key and uploads the
// ciphertext; the relay stores the bytes it got and hands them back to anyone
// with read access to the workspace who knows the blob's id. The relay never
// sees plaintext, file names or types: the signed event that references a
// blob (its id, content hash, size, author) lives inside the sealed envelope
// log, and clients check a downloaded blob against it.
//
//	POST   /v1/workspaces/{id}/blobs          body = ciphertext → 201 {"id","size","sha256","expiresAt"}
//	GET    /v1/workspaces/{id}/blobs/{blob}   → 200 application/octet-stream
//	DELETE /v1/workspaces/{id}/blobs/{blob}   → 204 (whether or not it existed)
//
// Ids are minted by the relay (32 random bytes, base64url without padding)
// and there is no route that lists them, so a blob can't be found by
// enumeration. Deleting needs write access to the workspace and the id, and
// a blob uploaded with an identified token (a token subject) is bound to
// it: only that subject, or a workspace Admin or Owner on the relay roster
// (relay membership), may delete it. A blob uploaded without an identity is
// a capability (anyone with write access and the id). Clients delete only
// after a signed deletion event in the workspace log.

// Blob refusal codes (refusal.go). The storage ones answer 507 and are also
// label values of hive_relay_limit_rejections_total; blob_rate answers 429.
const (
	limBlobRoomBytes    = "blob_room_bytes"
	limBlobRoomCount    = "blob_room_count"
	limBlobWriterBytes  = "blob_writer_bytes"
	limBlobWriterCount  = "blob_writer_count"
	limBlobTenantBytes  = "blob_tenant_bytes"
	limBlobTenantCount  = "blob_tenant_count"
	limBlobTotalBytes   = "blob_total_bytes"
	limBlobRate         = "blob_rate"
	limBlobInflight     = "blob_inflight"
	limBlobDownloadRate = "blob_download_rate"
)

func init() {
	allLimitNames = append(allLimitNames, limBlobRoomBytes, limBlobRoomCount, limBlobWriterBytes,
		limBlobWriterCount, limBlobTenantBytes, limBlobTenantCount, limBlobTotalBytes, limBlobRate, limBlobInflight, limBlobDownloadRate)
	for k, v := range map[string]string{
		limBlobRoomBytes:   "workspace attachment storage quota reached",
		limBlobRoomCount:   "workspace attachment count quota reached",
		limBlobWriterBytes: "your attachment storage quota in this workspace is reached",
		limBlobWriterCount: "your attachment count quota in this workspace is reached",
		limBlobTenantBytes: "tenant attachment storage quota reached",
		limBlobTenantCount: "tenant attachment count quota reached",
		limBlobTotalBytes:  "relay attachment storage is full",
	} {
		quotaMessages[k] = v
	}
}

// Defaults (docs/reference.md "Blobs"; details in docs/blobs.md).
const (
	defaultBlobMaxBytes      = 25 << 20  // one blob
	defaultBlobRoomMaxBytes  = 512 << 20 // one workspace
	defaultBlobRoomMaxCount  = 2000
	defaultBlobRetentionDays = 30
	defaultBlobRate          = 1.0 // uploads per second per writer per workspace
	defaultBlobBurst         = 20

	// Uploads being received at once, relay-wide and per uploader. Each
	// holds up to the blob size cap in memory for up to blobTransferWindow.
	defaultBlobMaxInflight    = 16
	defaultBlobWriterInflight = 4
	blobInflightRetry         = 5 * time.Second

	// Downloads being written at once, relay-wide and per downloader. Each
	// holds the whole blob in memory until the client has read it.
	defaultBlobDownloadInflight       = 8
	defaultBlobClientDownloadInflight = 2

	// Downloads per blob (enough for a large team's devices to fetch a new
	// attachment at once, then a steady trickle) and per downloader.
	defaultBlobDownloadRate        = 0.5
	defaultBlobDownloadBurst       = 100
	defaultBlobClientDownloadRate  = 2.0
	defaultBlobClientDownloadBurst = 60

	// blobIDBytes is the entropy of a blob id; its base64url form is
	// blobIDLen characters.
	blobIDBytes = 32
	blobIDLen   = 43

	// blobTransferWindow is how long one upload or download may take: the
	// server's 30 s read and write timeouts are for JSON, not 25 MiB.
	blobTransferWindow = 5 * time.Minute
)

// Upload pacing (package variables so tests can shorten them).
var (
	blobIdleTimeout = 15 * time.Second
	blobRateGrace   = 15 * time.Second
	blobMinRate     = 8 << 10 // bytes per second, averaged after blobRateGrace
)

// Per-uploader defaults (a quarter of the per-workspace ones).
const (
	defaultBlobWriterMaxBytes = 128 << 20
	defaultBlobWriterMaxCount = 500
)

// blobConfig is the blob channel's relay-wide configuration.
type blobConfig struct {
	enabled        bool
	maxBytes       int64 // LANGSTROTH_RELAY_BLOB_MAX_BYTES
	roomMaxBytes   int64 // LANGSTROTH_RELAY_BLOB_ROOM_MAX_BYTES (0 = off)
	roomMaxCount   int64 // LANGSTROTH_RELAY_BLOB_ROOM_MAX_COUNT (0 = off)
	writerMaxBytes int64 // LANGSTROTH_RELAY_BLOB_WRITER_MAX_BYTES (default 128 MiB; 0 = off)
	writerMaxCount int64 // LANGSTROTH_RELAY_BLOB_WRITER_MAX_COUNT (default 500; 0 = off)
	totalMaxBytes  int64 // LANGSTROTH_RELAY_BLOB_TOTAL_MAX_BYTES (0 = off)
	retention      time.Duration
	rate           *ipRateLimiter // LANGSTROTH_RELAY_BLOB_RATE / _BURST (nil = off)
	inflight       *blobInflight  // LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT / _WRITER_INFLIGHT (nil = off)
	download       *ipRateLimiter // LANGSTROTH_RELAY_BLOB_DOWNLOAD_RATE / _BURST, per blob (nil = off)
	clientDownload *ipRateLimiter // LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_RATE / _BURST, per downloader (nil = off)
	downloads      *blobInflight  // LANGSTROTH_RELAY_BLOB_DOWNLOAD_INFLIGHT / _CLIENT_DOWNLOAD_INFLIGHT (nil = off)
}

func blobConfigFromEnv() blobConfig {
	pos := func(name string, def int64) int64 { return max(envInt64(name, def), 0) }
	c := blobConfig{
		enabled:      blobsEnabled(getenv("LANGSTROTH_RELAY_BLOBS")),
		maxBytes:     pos("LANGSTROTH_RELAY_BLOB_MAX_BYTES", defaultBlobMaxBytes),
		roomMaxBytes: pos("LANGSTROTH_RELAY_BLOB_ROOM_MAX_BYTES", defaultBlobRoomMaxBytes),
		roomMaxCount: pos("LANGSTROTH_RELAY_BLOB_ROOM_MAX_COUNT", defaultBlobRoomMaxCount),
		// Per-uploader quotas are on by default: one member (or, on an open
		// relay, one address) can't fill a workspace's whole blob quota.
		writerMaxBytes: pos("LANGSTROTH_RELAY_BLOB_WRITER_MAX_BYTES", defaultBlobWriterMaxBytes),
		writerMaxCount: pos("LANGSTROTH_RELAY_BLOB_WRITER_MAX_COUNT", defaultBlobWriterMaxCount),
		totalMaxBytes:  pos("LANGSTROTH_RELAY_BLOB_TOTAL_MAX_BYTES", 0),
		retention:      daysEnv("LANGSTROTH_RELAY_BLOB_RETENTION_DAYS", defaultBlobRetentionDays),
	}
	if c.maxBytes == 0 {
		c.maxBytes = defaultBlobMaxBytes // a blob size cap is never off
	}
	if n, w := pos("LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT", defaultBlobMaxInflight),
		pos("LANGSTROTH_RELAY_BLOB_WRITER_INFLIGHT", defaultBlobWriterInflight); n > 0 || w > 0 {
		c.inflight = &blobInflight{max: n, perWriter: w, byWriter: map[string]int64{}}
	}
	if n, w := pos("LANGSTROTH_RELAY_BLOB_DOWNLOAD_INFLIGHT", defaultBlobDownloadInflight),
		pos("LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_INFLIGHT", defaultBlobClientDownloadInflight); n > 0 || w > 0 {
		c.downloads = &blobInflight{max: n, perWriter: w, byWriter: map[string]int64{}}
	}
	if r := envFloat("LANGSTROTH_RELAY_BLOB_DOWNLOAD_RATE", defaultBlobDownloadRate); r > 0 {
		c.download = newIPRateLimiter(r, max(envFloat("LANGSTROTH_RELAY_BLOB_DOWNLOAD_BURST", defaultBlobDownloadBurst), 1))
	}
	if r := envFloat("LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_RATE", defaultBlobClientDownloadRate); r > 0 {
		c.clientDownload = newIPRateLimiter(r, max(envFloat("LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_BURST", defaultBlobClientDownloadBurst), 1))
	}
	if r := envFloat("LANGSTROTH_RELAY_BLOB_RATE", defaultBlobRate); r > 0 {
		c.rate = newIPRateLimiter(r, max(envFloat("LANGSTROTH_RELAY_BLOB_BURST", defaultBlobBurst), 1))
	}
	return c
}

// blobsEnabled reads LANGSTROTH_RELAY_BLOBS: on unless it says off.
func blobsEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

func (c blobConfig) log() {
	if !c.enabled {
		slog.Info("blob channel off (LANGSTROTH_RELAY_BLOBS=off)")
		return
	}
	attrs := []any{"max_bytes", c.maxBytes, "room_max_bytes", c.roomMaxBytes, "room_max_count", c.roomMaxCount,
		"writer_max_bytes", c.writerMaxBytes, "writer_max_count", c.writerMaxCount, "total_max_bytes", c.totalMaxBytes,
		"retention_days", int(c.retention / (24 * time.Hour))}
	if c.rate != nil {
		attrs = append(attrs, "rate", c.rate.rate, "burst", c.rate.burst)
	}
	if c.inflight != nil {
		attrs = append(attrs, "max_inflight", c.inflight.max, "writer_inflight", c.inflight.perWriter)
	}
	if c.downloads != nil {
		attrs = append(attrs, "download_inflight", c.downloads.max, "client_download_inflight", c.downloads.perWriter)
	}
	if c.download != nil {
		attrs = append(attrs, "download_rate", c.download.rate, "download_burst", c.download.burst)
	}
	if c.clientDownload != nil {
		attrs = append(attrs, "client_download_rate", c.clientDownload.rate, "client_download_burst", c.clientDownload.burst)
	}
	slog.Info("blob channel", attrs...)
}

// blobInflight counts the uploads being received, relay-wide and per
// uploader (zero limits are off). A client that opens uploads and never
// finishes them holds at most these many buffers.
type blobInflight struct {
	mu             sync.Mutex
	max, perWriter int64
	total          int64
	byWriter       map[string]int64
}

func (l *blobInflight) acquire(writer string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if (l.max > 0 && l.total >= l.max) || (l.perWriter > 0 && l.byWriter[writer] >= l.perWriter) {
		return false
	}
	l.total++
	l.byWriter[writer]++
	return true
}

func (l *blobInflight) release(writer string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.byWriter[writer]--; l.byWriter[writer] <= 0 {
		delete(l.byWriter, writer)
	}
}

// BlobMeta describes one stored blob. Uploader is a hash of the writing
// identity (blobUploaderTag), never the raw token subject or address.
type BlobMeta struct {
	Room      string // storage key (<tenant>/<id> with tenancy)
	ID        string
	Tenant    string
	Uploader  string
	Size      int64
	SHA256    string // hex of the stored bytes
	CreatedAt int64
	ExpiresAt int64 // unix seconds; 0 = kept until deleted
	// Bound: the uploader was an identified token subject, so only it (or
	// a workspace Admin) may delete the blob. False for an upload tagged
	// by client address, which any writer with the id may delete.
	Bound bool
}

// blobDeleter is who asks to delete a blob: its uploader tag, and Any when
// it may delete any blob of the workspace (an Admin on the roster).
type blobDeleter struct {
	Uploader string
	Any      bool
}

// blobDeleteResult is the outcome of DeleteBlobAs.
type blobDeleteResult int

const (
	blobDeleteAbsent  blobDeleteResult = iota // no such blob
	blobDeleteDone                            // deleted
	blobDeleteRefused                         // bound to another uploader
)

// mayDelete reports whether by may delete a blob described by m.
func (by blobDeleter) mayDelete(m BlobMeta) bool {
	return by.Any || !m.Bound || m.Uploader == by.Uploader
}

// blobQuota carries the limits for one upload. Zero fields are unlimited.
type blobQuota struct {
	RoomMaxBytes, RoomMaxCount     int64
	WriterMaxBytes, WriterMaxCount int64
	TenantMaxBytes, TenantMaxCount int64
	TotalMaxBytes                  int64
}

// errNoRoom is a blob upload to a workspace that holds nothing yet. Blobs
// ride a workspace's log, so they never create a room (which would get round
// the room limits).
var errNoRoom = errors.New("no such workspace")

// blobStore is implemented by both built-in stores. A downstream Store
// without it keeps compiling; the blob routes then answer 404.
type blobStore interface {
	// PutBlob stores data under meta if the room is live and every quota in
	// q admits it, atomically with the quota checks. Returns errNoRoom or a
	// quota error (quota.go) otherwise.
	PutBlob(ctx context.Context, meta BlobMeta, data []byte, q blobQuota) error
	// GetBlob returns a live (unexpired at now) blob of room.
	GetBlob(ctx context.Context, room, id string, now int64) (BlobMeta, []byte, bool, error)
	// DeleteBlob removes one blob of room; false if there was none.
	DeleteBlob(ctx context.Context, room, id string) (bool, error)
	// DeleteBlobAs removes one blob of room if by may delete it
	// (blobDeleter.mayDelete), atomically with that check.
	DeleteBlobAs(ctx context.Context, room, id string, by blobDeleter) (blobDeleteResult, error)
	// DeleteBlobsByUploader removes every blob uploader put in room.
	DeleteBlobsByUploader(ctx context.Context, room, uploader string) (int64, error)
	// PruneExpiredBlobs removes every blob that expired at or before now.
	PruneExpiredBlobs(ctx context.Context, now int64) (int64, error)
}

// newBlobID mints a blob id: 32 random bytes, base64url without padding.
func newBlobID() string {
	var b [blobIDBytes]byte
	randRead(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// validBlobID is the shape newBlobID produces; anything else is unknown.
func validBlobID(id string) bool {
	if len(id) != blobIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// blobUploaderTag is the stored identity of an uploader: a hash of its
// writerTag (token subject, else client address).
func blobUploaderTag(writer string) string {
	return sha256hex("relay-blob-uploader\x00" + writer)
}

// blobUploaderForAccount is the uploader tag of a token subject in the
// tenant of ctx: what writerTag yields for that member's uploads.
func blobUploaderForAccount(ctx context.Context, account string) string {
	if t := tenantID(ctx); t != "" {
		return blobUploaderTag("sub:t:" + t + "\x00" + account)
	}
	return blobUploaderTag("sub:" + account)
}

// blobQuotaFor builds the upload quotas for a request: relay-wide limits,
// then the caller's tenant's.
func (s *Server) blobQuotaFor(ctx context.Context) blobQuota {
	q := blobQuota{
		RoomMaxBytes:   s.blobs.roomMaxBytes,
		RoomMaxCount:   s.blobs.roomMaxCount,
		WriterMaxBytes: s.blobs.writerMaxBytes,
		WriterMaxCount: s.blobs.writerMaxCount,
		TotalMaxBytes:  s.blobs.totalMaxBytes,
	}
	if t := tenantFrom(ctx); t != nil {
		q.TenantMaxBytes = t.limits.BlobMaxBytes
		q.TenantMaxCount = t.limits.BlobMaxCount
		if t.limits.BlobRoomMaxBytes > 0 {
			q.RoomMaxBytes = t.limits.BlobRoomMaxBytes
		}
		if t.limits.BlobRoomMaxCount > 0 {
			q.RoomMaxCount = t.limits.BlobRoomMaxCount
		}
	}
	return q
}

func (s *Server) registerBlobs(mux *http.ServeMux) {
	if !s.blobs.enabled || s.blobStore == nil {
		return
	}
	mux.HandleFunc("POST /v1/workspaces/{id}/blobs", s.scoped(s.postBlob))
	mux.HandleFunc("GET /v1/workspaces/{id}/blobs/{blob}", s.scoped(s.getBlob))
	mux.HandleFunc("DELETE /v1/workspaces/{id}/blobs/{blob}", s.scoped(s.deleteBlob))
}

type blobError struct {
	Error    string `json:"error"`
	Message  string `json:"message"`
	MaxBytes int64  `json:"maxBytes,omitempty"`
}

func blobNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, blobError{Error: "blob_not_found", Message: "no such blob"})
}

// postBlob stores one sealed blob and answers its relay-minted id.
func (s *Server) postBlob(w http.ResponseWriter, r *http.Request) {
	if !s.limitWrite(w, r) {
		return
	}
	room := r.PathValue("id")
	if !s.enforceWrite(w, r, room) {
		return
	}
	writer := writerTag(r.Context(), clientKey(r))
	if s.blobs.rate != nil {
		if ok, wait := s.blobs.rate.allowWait(room + "|" + writer); !ok {
			tooMany(w, limBlobRate, tenantID(r.Context()), wait, "attachment upload rate exceeded")
			return
		}
	}
	tooLarge := func() {
		writeJSON(w, http.StatusRequestEntityTooLarge, blobError{Error: "blob_too_large",
			Message: "attachment is larger than this relay accepts", MaxBytes: s.blobs.maxBytes})
	}
	if r.ContentLength > s.blobs.maxBytes {
		tooLarge()
		return
	}
	if l := s.blobs.inflight; l != nil {
		if !l.acquire(writer) {
			tooMany(w, limBlobInflight, tenantID(r.Context()), blobInflightRetry, "too many attachment uploads in progress")
			return
		}
		defer l.release(writer)
	}
	// Both deadlines: the server's write timeout runs from the end of the
	// request headers, so a long upload would otherwise be stored and its
	// answer (the id) lost, and the client's retry would store it again.
	deadline := time.Now().Add(blobTransferWindow)
	_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(30 * time.Second))
	data, err := readBlobBody(w, r, s.blobs.maxBytes, deadline)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			tooLarge()
			return
		}
		var ne net.Error
		if errors.Is(err, errBlobTooSlow) || (errors.As(err, &ne) && ne.Timeout()) {
			writeJSON(w, http.StatusRequestTimeout, blobError{Error: "blob_too_slow",
				Message: "the upload stalled or arrived too slowly"})
			return
		}
		writeJSON(w, http.StatusBadRequest, blobError{Error: "bad_body", Message: "could not read the request body"})
		return
	}
	if len(data) == 0 {
		writeJSON(w, http.StatusBadRequest, blobError{Error: "empty_blob", Message: "an attachment needs a body"})
		return
	}
	sum := sha256.Sum256(data)
	now := time.Now().Unix()
	meta := BlobMeta{
		Room:      room,
		ID:        newBlobID(),
		Tenant:    tenantID(r.Context()),
		Uploader:  blobUploaderTag(writer),
		Bound:     strings.HasPrefix(writer, "sub:"),
		Size:      int64(len(data)),
		SHA256:    hex.EncodeToString(sum[:]),
		CreatedAt: now,
	}
	if s.blobs.retention > 0 {
		meta.ExpiresAt = now + int64(s.blobs.retention/time.Second)
	}
	if err := s.blobStore.PutBlob(r.Context(), meta, data, s.blobQuotaFor(r.Context())); err != nil {
		if errors.Is(err, errNoRoom) {
			writeJSON(w, http.StatusNotFound, blobError{Error: "no_workspace",
				Message: "this workspace holds nothing yet; attachments ride an existing workspace"})
			return
		}
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": meta.ID, "size": meta.Size, "sha256": meta.SHA256, "expiresAt": meta.ExpiresAt,
	})
}

// errBlobTooSlow is an upload arriving slower than blobMinRate.
var errBlobTooSlow = errors.New("upload too slow")

// readBlobBody reads an upload of at most limit bytes, by end at the latest.
// The buffer grows as bytes arrive (never sized from a declared length, so
// headers alone allocate nothing). A client that sends nothing for
// blobIdleTimeout, or averages under blobMinRate after blobRateGrace, is
// cut off, so it can't hold an upload slot for the whole window.
func readBlobBody(w http.ResponseWriter, r *http.Request, limit int64, end time.Time) ([]byte, error) {
	return io.ReadAll(&pacedReader{r: http.MaxBytesReader(w, r.Body, limit),
		rc: http.NewResponseController(w), start: time.Now(), end: end})
}

type pacedReader struct {
	r          io.Reader
	rc         *http.ResponseController
	start, end time.Time
	n          int64
}

func (p *pacedReader) Read(b []byte) (int, error) {
	now := time.Now()
	if el := now.Sub(p.start); el > blobRateGrace && float64(p.n) < el.Seconds()*float64(blobMinRate) {
		return 0, errBlobTooSlow
	}
	d := now.Add(blobIdleTimeout)
	if d.After(p.end) {
		d = p.end
	}
	_ = p.rc.SetReadDeadline(d)
	n, err := p.r.Read(b)
	p.n += int64(n)
	return n, err
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("id")
	if !s.enforceRead(w, r, room) {
		return
	}
	id := r.PathValue("blob")
	if !validBlobID(id) {
		blobNotFound(w)
		return
	}
	// A slot before the blob is loaded: it stays in memory until the
	// client has read all of it.
	if l := s.blobs.downloads; l != nil {
		who := writerTag(r.Context(), clientKey(r))
		if !l.acquire(who) {
			tooMany(w, limBlobInflight, tenantID(r.Context()), blobInflightRetry, "too many attachment downloads in progress")
			return
		}
		defer l.release(who)
	}
	_, data, ok, err := s.blobStore.GetBlob(r.Context(), room, id, time.Now().Unix())
	if storeErr(w, err) {
		return
	}
	if !ok {
		blobNotFound(w)
		return
	}
	// Download rates, checked only for a blob that exists (unknown ids are
	// under the read rate and mint no buckets): per blob, so a blob URL
	// can't serve as a public download link, then per downloader.
	if ok, wait := s.blobs.download.allowWait(room + "|" + id); !ok {
		tooMany(w, limBlobDownloadRate, tenantID(r.Context()), wait, "this attachment is being downloaded too often")
		return
	}
	if ok, wait := s.blobs.clientDownload.allowWait(writerTag(r.Context(), clientKey(r))); !ok {
		tooMany(w, limBlobDownloadRate, tenantID(r.Context()), wait, "attachment download rate exceeded")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", "attachment")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	writeBlobPaced(w, data, time.Now().Add(blobTransferWindow))
}

// blobWriteChunk is how much of a download is written per write deadline.
const blobWriteChunk = 64 << 10

// writeBlobPaced writes a download by end at the latest, paced like an
// upload (pacedReader): a client that reads nothing for blobIdleTimeout, or
// averages under blobMinRate after blobRateGrace, is cut off, so it can't
// hold a download slot and the blob's memory for the whole window.
func writeBlobPaced(w http.ResponseWriter, data []byte, end time.Time) {
	rc := http.NewResponseController(w)
	start := time.Now()
	for off := 0; off < len(data); {
		now := time.Now()
		if el := now.Sub(start); el > blobRateGrace && float64(off) < el.Seconds()*float64(blobMinRate) {
			return
		}
		d := now.Add(blobIdleTimeout)
		if d.After(end) {
			d = end
		}
		_ = rc.SetWriteDeadline(d)
		n := min(len(data)-off, blobWriteChunk)
		if _, err := w.Write(data[off : off+n]); err != nil {
			return
		}
		off += n
	}
}

func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request) {
	if !s.limitWrite(w, r) {
		return
	}
	room := r.PathValue("id")
	if !s.enforceWrite(w, r, room) {
		return
	}
	id := r.PathValue("blob")
	if !validBlobID(id) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	by := blobDeleter{Uploader: blobUploaderTag(writerTag(r.Context(), clientKey(r)))}
	res, err := s.blobStore.DeleteBlobAs(r.Context(), room, id, by)
	if storeErr(w, err) {
		return
	}
	if res == blobDeleteRefused && s.isRosterAdmin(r.Context(), room) {
		by.Any = true
		if res, err = s.blobStore.DeleteBlobAs(r.Context(), room, id, by); storeErr(w, err) {
			return
		}
	}
	if res == blobDeleteRefused {
		writeJSON(w, http.StatusForbidden, blobError{Error: "blob_not_yours",
			Message: "only its uploader or a workspace admin may delete this attachment"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// isRosterAdmin reports whether the caller is an Admin or Owner of room on
// the relay roster (relay membership only; the open relay has no Admins).
func (s *Server) isRosterAdmin(ctx context.Context, room string) bool {
	if !s.membership {
		return false
	}
	caller := callerAccount(claimsFrom(ctx))
	return caller != "" && s.requireRole(ctx, room, caller, rankAdmin) == nil
}

// removeMemberBlobs deletes the blobs a removed member uploaded to room
// (best effort: logged, never fails the removal).
func (s *Server) removeMemberBlobs(ctx context.Context, room, account string) {
	if s.blobStore == nil || account == "" {
		return
	}
	n, err := s.blobStore.DeleteBlobsByUploader(ctx, room, blobUploaderForAccount(ctx, account))
	if err != nil {
		slog.Warn("removing a member's blobs failed", "error", err)
		return
	}
	if n > 0 {
		slog.Info("removed member's blobs", "count", n)
	}
}

// blobRetentionLoop deletes expired blobs hourly.
func blobRetentionLoop(bs blobStore, stop <-chan struct{}) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			runPrune("expired_blobs", func() (int64, error) {
				return bs.PruneExpiredBlobs(context.Background(), time.Now().Unix())
			})
		}
	}
}
