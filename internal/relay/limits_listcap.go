package relay

import (
	"context"
	"encoding/json"
	"sort"
)

// Bounded keyring / candidate / presence listings.
//
// These routes return every retained row in one response. With up to
// defaultMaxKeyringPerWS keyring rows and defaultMaxDeviceBlobsPerWS device
// blobs per workspace, each up to the request body cap, one unbounded GET could
// make the relay load and encode gigabytes. LANGSTROTH_RELAY_MAX_LIST_BYTES bounds
// each response by stored blob bytes (default 16 MiB; 0 = unbounded). Real
// rows are small (a rotation sealed per device, a presence or candidate
// blob), so the bound only bites on abuse. The keyring itself is capped at
// LANGSTROTH_RELAY_MAX_KEYRING_BYTES_PER_WS (default: this same 16 MiB), so with the
// defaults its listing is never cut; if an operator lowers the list bound below
// it, the keyring keeps its newest rows, in order. A device-blob map keeps a
// subset (by device id). At least one row is always returned.
const defaultMaxListBytes = 16 << 20

func listCapFromEnv() int {
	n := envInt64("LANGSTROTH_RELAY_MAX_LIST_BYTES", defaultMaxListBytes)
	if n < 0 {
		return defaultMaxListBytes
	}
	return int(n)
}

// boundedLister is implemented by stores that can bound these listings in the
// backend (both built-in stores). Others are bounded after the fact.
type boundedLister interface {
	KeyRotationsBounded(ctx context.Context, workspace string, maxBytes int) ([]json.RawMessage, error)
	CandidatesBounded(ctx context.Context, workspace string, maxBytes int) (map[string]json.RawMessage, error)
	PresenceBounded(ctx context.Context, workspace string, maxBytes int) (map[string]json.RawMessage, error)
}

// newestWithin keeps the newest rows of an oldest-first slice whose total size
// fits maxBytes (always at least the newest one), preserving order.
func newestWithin(rows []json.RawMessage, maxBytes int) []json.RawMessage {
	if maxBytes <= 0 || len(rows) == 0 {
		return rows
	}
	total, start := 0, len(rows)
	for start > 0 {
		n := len(rows[start-1])
		if start < len(rows) && total+n > maxBytes {
			break
		}
		total += n
		start--
	}
	return rows[start:]
}

// blobsWithin keeps device blobs in device-id order while they fit maxBytes
// (always at least one).
func blobsWithin(m map[string]json.RawMessage, maxBytes int) map[string]json.RawMessage {
	if maxBytes <= 0 {
		return m
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := map[string]json.RawMessage{}
	total := 0
	for _, id := range ids {
		n := len(m[id])
		if len(out) > 0 && total+n > maxBytes {
			break
		}
		out[id] = m[id]
		total += n
	}
	return out
}

func (s *Server) keyRotations(ctx context.Context, workspace string) ([]json.RawMessage, error) {
	if b, ok := s.store.(boundedLister); ok && s.maxListBytes > 0 {
		return b.KeyRotationsBounded(ctx, workspace, s.maxListBytes)
	}
	rows, err := s.store.KeyRotations(ctx, workspace)
	return newestWithin(rows, s.maxListBytes), err
}

func (s *Server) candidates(ctx context.Context, workspace string) (map[string]json.RawMessage, error) {
	if b, ok := s.store.(boundedLister); ok && s.maxListBytes > 0 {
		return b.CandidatesBounded(ctx, workspace, s.maxListBytes)
	}
	m, err := s.store.Candidates(ctx, workspace)
	return blobsWithin(m, s.maxListBytes), err
}

func (s *Server) presenceBlobs(ctx context.Context, workspace string) (map[string]json.RawMessage, error) {
	if b, ok := s.store.(boundedLister); ok && s.maxListBytes > 0 {
		return b.PresenceBounded(ctx, workspace, s.maxListBytes)
	}
	m, err := s.store.PresenceBlobs(ctx, workspace)
	return blobsWithin(m, s.maxListBytes), err
}

// ── memoryStore ──────────────────────────────────────────────────────────────

func (s *memoryStore) KeyRotationsBounded(_ context.Context, workspace string, maxBytes int) ([]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []json.RawMessage{}
	if w := s.workspaces[workspace]; w != nil {
		out = append(out, newestWithin(w.keyring, maxBytes)...)
	}
	return out, nil
}

func (s *memoryStore) CandidatesBounded(_ context.Context, workspace string, maxBytes int) (map[string]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if w := s.workspaces[workspace]; w != nil {
		return blobsWithin(w.candidates, maxBytes), nil
	}
	return map[string]json.RawMessage{}, nil
}

func (s *memoryStore) PresenceBounded(_ context.Context, workspace string, maxBytes int) (map[string]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if w := s.workspaces[workspace]; w != nil {
		return blobsWithin(w.presence, maxBytes), nil
	}
	return map[string]json.RawMessage{}, nil
}

// ── postgresStore ────────────────────────────────────────────────────────────
//
// The size windows use octet_length, which reads the stored length without
// fetching the value, so only the rows returned are read in full.

func (s *postgresStore) KeyRotationsBounded(ctx context.Context, workspace string, maxBytes int) ([]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT blob FROM (
		   SELECT id, blob,
		          row_number() OVER (ORDER BY id DESC) AS rn,
		          sum(octet_length(blob)) OVER (ORDER BY id DESC) AS cum
		   FROM relay_keyring WHERE workspace = $1
		 ) k
		 WHERE rn = 1 OR cum <= $2
		 ORDER BY id`, workspace, maxBytes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(blob))
	}
	return out, rows.Err()
}

func (s *postgresStore) CandidatesBounded(ctx context.Context, workspace string, maxBytes int) (map[string]json.RawMessage, error) {
	return s.deviceBlobsBounded(ctx, "relay_candidates", workspace, maxBytes)
}

func (s *postgresStore) PresenceBounded(ctx context.Context, workspace string, maxBytes int) (map[string]json.RawMessage, error) {
	return s.deviceBlobsBounded(ctx, "relay_presence", workspace, maxBytes)
}

// deviceBlobsBounded: table is one of the two constant table names above.
func (s *postgresStore) deviceBlobsBounded(ctx context.Context, table, workspace string, maxBytes int) (map[string]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT device_id, blob FROM (
		   SELECT device_id, blob,
		          row_number() OVER (ORDER BY device_id) AS rn,
		          sum(octet_length(blob)) OVER (ORDER BY device_id) AS cum
		   FROM `+table+` WHERE workspace = $1
		 ) d
		 WHERE rn = 1 OR cum <= $2`, workspace, maxBytes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, err
		}
		out[id] = json.RawMessage(blob)
	}
	return out, rows.Err()
}
