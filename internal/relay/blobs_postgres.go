package relay

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"
)

// blobStore for Postgres (blobs.go). relay_blob_usage holds running totals
// per scope (a room, one uploader in a room, a tenant, the relay), updated
// in the same transaction as every insert and delete. An upload takes the
// row locks of its scopes in one fixed (sorted) order and checks the quotas
// against the locked totals, so concurrent uploads can't overshoot a quota
// and two transactions never wait on each other's scopes in a cycle.
//
// Lock order: relay_rooms row, then relay_blobs rows, then relay_blob_usage
// rows (sorted by scope).
const blobsSchemaSQL = `
CREATE TABLE IF NOT EXISTS relay_blobs (
  workspace  TEXT   NOT NULL,
  id         TEXT   NOT NULL,
  tenant     TEXT   NOT NULL DEFAULT '',
  uploader   TEXT   NOT NULL,
  size       BIGINT NOT NULL,
  sha256     TEXT   NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL DEFAULT 0,
  data       BYTEA  NOT NULL,
  bound      BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (workspace, id)
);
-- bound (only its uploader or an Admin may delete): added after the table
-- first shipped in development builds. Only when missing, so a boot never
-- queues an exclusive lock behind an upload.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'relay_blobs'::regclass
                 AND attname = 'bound' AND NOT attisdropped) THEN
    ALTER TABLE relay_blobs ADD COLUMN bound BOOLEAN NOT NULL DEFAULT false;
  END IF;
END $$;
-- Ciphertext doesn't compress: store it out of line, uncompressed. Only
-- when not yet set, so a later boot never queues an exclusive lock behind
-- an upload in flight.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'relay_blobs'::regclass
             AND attname = 'data' AND attstorage <> 'e') THEN
    ALTER TABLE relay_blobs ALTER COLUMN data SET STORAGE EXTERNAL;
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS relay_blobs_uploader ON relay_blobs (workspace, uploader);
CREATE INDEX IF NOT EXISTS relay_blobs_expiry ON relay_blobs (expires_at) WHERE expires_at > 0;
CREATE TABLE IF NOT EXISTS relay_blob_usage (
  scope TEXT   PRIMARY KEY,
  bytes BIGINT NOT NULL DEFAULT 0,
  count BIGINT NOT NULL DEFAULT 0
);
`

// Usage scopes. An uploader tag is 64 hex characters, so a writer scope is
// unambiguous whatever the room id holds.
const blobScopeTotal = "total"

func blobScopeRoom(room string) string             { return "r|" + room }
func blobScopeWriter(room, uploader string) string { return "w|" + room + "|" + uploader }
func blobScopeTenant(tenant string) string         { return "t|" + tenant }

// blobScopes lists the scopes a blob counts in.
func blobScopes(room, tenant, uploader string) []string {
	out := []string{blobScopeRoom(room), blobScopeWriter(room, uploader), blobScopeTotal}
	if tenant != "" {
		out = append(out, blobScopeTenant(tenant))
	}
	return out
}

func (s *postgresStore) PutBlob(ctx context.Context, meta BlobMeta, data []byte, q blobQuota) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	// The room must exist; FOR SHARE holds off a purge or an idle expiry
	// until this upload commits (they then delete it with the room).
	var tenant string
	if err := tx.QueryRow(ctx, `SELECT tenant FROM relay_rooms WHERE workspace = $1 FOR SHARE`, meta.Room).Scan(&tenant); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errNoRoom
		}
		return err
	}
	size := int64(len(data))
	scopes := blobScopes(meta.Room, tenant, meta.Uploader)
	sort.Strings(scopes)
	for _, sc := range scopes {
		var bytes, count int64
		if err := tx.QueryRow(ctx, `
INSERT INTO relay_blob_usage (scope, bytes, count) VALUES ($1, $2, 1)
ON CONFLICT (scope) DO UPDATE SET bytes = relay_blob_usage.bytes + EXCLUDED.bytes, count = relay_blob_usage.count + 1
RETURNING bytes, count`, sc, size).Scan(&bytes, &count); err != nil {
			return err
		}
		if lim := blobScopeRefusal(sc, tenant, bytes, count, q); lim != "" {
			return errQuota(lim, tenant)
		}
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO relay_blobs (workspace, id, tenant, uploader, size, sha256, created_at, expires_at, data, bound)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		meta.Room, meta.ID, tenant, meta.Uploader, size, meta.SHA256, meta.CreatedAt, meta.ExpiresAt, data, meta.Bound); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// blobScopeRefusal names the quota a scope's new totals break, or "".
// Count limits are checked before byte limits, as the memory store does.
func blobScopeRefusal(scope, tenant string, bytes, count int64, q blobQuota) string {
	over := func(v, limit int64) bool { return limit > 0 && v > limit }
	switch {
	case scope == blobScopeTotal:
		if over(bytes, q.TotalMaxBytes) {
			return limBlobTotalBytes
		}
	case tenant != "" && scope == blobScopeTenant(tenant):
		if over(count, q.TenantMaxCount) {
			return limBlobTenantCount
		}
		if over(bytes, q.TenantMaxBytes) {
			return limBlobTenantBytes
		}
	case len(scope) > 2 && scope[:2] == "w|":
		if over(count, q.WriterMaxCount) {
			return limBlobWriterCount
		}
		if over(bytes, q.WriterMaxBytes) {
			return limBlobWriterBytes
		}
	case len(scope) > 2 && scope[:2] == "r|":
		if over(count, q.RoomMaxCount) {
			return limBlobRoomCount
		}
		if over(bytes, q.RoomMaxBytes) {
			return limBlobRoomBytes
		}
	}
	return ""
}

func (s *postgresStore) GetBlob(ctx context.Context, room, id string, now int64) (BlobMeta, []byte, bool, error) {
	m := BlobMeta{Room: room, ID: id}
	var data []byte
	err := s.pool.QueryRow(ctx, `
SELECT tenant, uploader, size, sha256, created_at, expires_at, bound, data FROM relay_blobs
WHERE workspace = $1 AND id = $2 AND (expires_at = 0 OR expires_at > $3)`, room, id, now).
		Scan(&m.Tenant, &m.Uploader, &m.Size, &m.SHA256, &m.CreatedAt, &m.ExpiresAt, &m.Bound, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return BlobMeta{}, nil, false, nil
	}
	if err != nil {
		return BlobMeta{}, nil, false, err
	}
	return m, data, true, nil
}

// deleteBlobsTx runs a DELETE ... RETURNING workspace, tenant, uploader,
// size on relay_blobs and takes the deleted blobs off their scopes' totals.
func deleteBlobsTx(ctx context.Context, tx pgx.Tx, sql string, args ...any) (int64, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	type use struct{ bytes, count int64 }
	dec := map[string]*use{}
	var n int64
	for rows.Next() {
		var room, tenant, uploader string
		var size int64
		if err := rows.Scan(&room, &tenant, &uploader, &size); err != nil {
			rows.Close()
			return 0, err
		}
		n++
		for _, sc := range blobScopes(room, tenant, uploader) {
			u := dec[sc]
			if u == nil {
				u = &use{}
				dec[sc] = u
			}
			u.bytes += size
			u.count++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	scopes := make([]string, 0, len(dec))
	for sc := range dec {
		scopes = append(scopes, sc)
	}
	sort.Strings(scopes)
	for _, sc := range scopes {
		u := dec[sc]
		if _, err := tx.Exec(ctx, `UPDATE relay_blob_usage SET bytes = bytes - $2, count = count - $3 WHERE scope = $1`,
			sc, u.bytes, u.count); err != nil {
			return 0, err
		}
	}
	if len(scopes) > 0 {
		// Drop emptied scopes (writer and room scopes would otherwise pile up).
		if _, err := tx.Exec(ctx, `DELETE FROM relay_blob_usage WHERE scope = ANY($1) AND count <= 0 AND scope <> $2`,
			scopes, blobScopeTotal); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// pgDeleteBlobs runs deleteBlobsTx in its own transaction.
func (s *postgresStore) pgDeleteBlobs(ctx context.Context, sql string, args ...any) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	n, err := deleteBlobsTx(ctx, tx, sql, args...)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit(ctx)
}

const blobReturning = ` RETURNING workspace, tenant, uploader, size`

func (s *postgresStore) DeleteBlob(ctx context.Context, room, id string) (bool, error) {
	n, err := s.pgDeleteBlobs(ctx, `DELETE FROM relay_blobs WHERE workspace = $1 AND id = $2`+blobReturning, room, id)
	return n > 0, err
}

func (s *postgresStore) DeleteBlobAs(ctx context.Context, room, id string, by blobDeleter) (blobDeleteResult, error) {
	n, err := s.pgDeleteBlobs(ctx, `DELETE FROM relay_blobs WHERE workspace = $1 AND id = $2
AND (NOT bound OR uploader = $3 OR $4)`+blobReturning, room, id, by.Uploader, by.Any)
	if err != nil || n > 0 {
		return blobDeleteDone, err
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM relay_blobs WHERE workspace = $1 AND id = $2)`,
		room, id).Scan(&exists); err != nil {
		return blobDeleteAbsent, err
	}
	if exists {
		return blobDeleteRefused, nil
	}
	return blobDeleteAbsent, nil
}

func (s *postgresStore) DeleteBlobsByUploader(ctx context.Context, room, uploader string) (int64, error) {
	return s.pgDeleteBlobs(ctx, `DELETE FROM relay_blobs WHERE workspace = $1 AND uploader = $2`+blobReturning, room, uploader)
}

// PruneExpiredBlobs deletes expired blobs in batches.
func (s *postgresStore) PruneExpiredBlobs(ctx context.Context, now int64) (int64, error) {
	const batch = 200
	var total int64
	for {
		n, err := s.pgDeleteBlobs(ctx, `
DELETE FROM relay_blobs WHERE (workspace, id) IN (
  SELECT workspace, id FROM relay_blobs WHERE expires_at > 0 AND expires_at <= $1
  ORDER BY workspace, id LIMIT $2 FOR UPDATE SKIP LOCKED)`+blobReturning, now, batch)
		total += n
		if err != nil || n < batch {
			return total, err
		}
	}
}

// expireRoomBlobsTx deletes the blobs of rooms inside a room purge or an
// idle expiry (rooms_postgres.go), whose room rows tx already locked.
func expireRoomBlobsTx(ctx context.Context, tx pgx.Tx, rooms []string) error {
	_, err := deleteBlobsTx(ctx, tx, `DELETE FROM relay_blobs WHERE workspace = ANY($1)`+blobReturning, rooms)
	return err
}
