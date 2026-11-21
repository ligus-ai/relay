package relay

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Room accounting for Postgres (quota.go). relay_rooms holds one row per live
// room, updated in the same transaction as every write; relay_tenant_usage
// holds per-tenant totals (tenancy only: the "" tenant isn't kept there, so a
// relay without tenancy doesn't serialize every write on one row).
const roomsSchemaSQL = `
CREATE TABLE IF NOT EXISTS relay_rooms (
  workspace  TEXT   PRIMARY KEY,
  tenant     TEXT   NOT NULL DEFAULT '',
  creator    TEXT   NOT NULL DEFAULT '',
  bytes      BIGINT NOT NULL DEFAULT 0,
  envelopes  BIGINT NOT NULL DEFAULT 0,
  last_write BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS relay_rooms_tenant ON relay_rooms (tenant, workspace);
CREATE INDEX IF NOT EXISTS relay_rooms_creator ON relay_rooms (creator) WHERE creator <> '';
CREATE INDEX IF NOT EXISTS relay_rooms_idle ON relay_rooms (last_write);
CREATE TABLE IF NOT EXISTS relay_tenant_usage (
  tenant TEXT   PRIMARY KEY,
  bytes  BIGINT NOT NULL DEFAULT 0,
  rooms  BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS relay_migrations (
  name       TEXT   PRIMARY KEY,
  applied_at BIGINT NOT NULL
);
-- One-time backfill of relay_rooms from rooms written before it existed.
-- Keyring-only rooms count as written now, so retention never expires a room
-- early because of the backfill.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM relay_migrations WHERE name = 'rooms_backfill_v1') THEN
    INSERT INTO relay_rooms (workspace, bytes, envelopes, last_write)
    SELECT workspace, sum(b), sum(n), max(lw) FROM (
      SELECT workspace, sum(octet_length(body))::bigint AS b, count(*)::bigint AS n,
             coalesce(max(created_at), extract(epoch FROM now())::bigint) AS lw
        FROM relay_envelopes GROUP BY workspace
      UNION ALL
      SELECT workspace, sum(octet_length(blob))::bigint, 0, extract(epoch FROM now())::bigint
        FROM relay_keyring GROUP BY workspace
    ) x GROUP BY workspace
    ON CONFLICT (workspace) DO NOTHING;
    INSERT INTO relay_migrations (name, applied_at) VALUES ('rooms_backfill_v1', extract(epoch FROM now())::bigint);
  END IF;
END $$;
`

// pgTotal caches the sum of room bytes (LANGSTROTH_RELAY_MAX_TOTAL_ROOM_BYTES)
// and the room count (LANGSTROTH_RELAY_MAX_ROOMS).
type pgTotal struct {
	mu    sync.Mutex
	bytes int64
	rooms int64
	at    time.Time
}

const pgTotalTTL = 10 * time.Second

func (s *postgresStore) totalRoomBytes(ctx context.Context) (int64, error) {
	s.total.mu.Lock()
	defer s.total.mu.Unlock()
	if !s.total.at.IsZero() && time.Since(s.total.at) < pgTotalTTL {
		return s.total.bytes, nil
	}
	if err := s.refreshTotalLocked(ctx); err != nil {
		return 0, err
	}
	return s.total.bytes, nil
}

// refreshTotalLocked re-reads the cached totals. Caller holds s.total.mu.
func (s *postgresStore) refreshTotalLocked(ctx context.Context) error {
	var b, r int64
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(sum(bytes), 0)::bigint, count(*) FROM relay_rooms`).Scan(&b, &r); err != nil {
		return err
	}
	s.total.bytes, s.total.rooms, s.total.at = b, r, time.Now()
	return nil
}

// reserveRoom admits one more room under max (re-reading the count at most
// every pgTotalTTL, like the byte total) and counts it.
func (s *postgresStore) reserveRoom(ctx context.Context, max int64) (bool, error) {
	s.total.mu.Lock()
	defer s.total.mu.Unlock()
	if s.total.at.IsZero() || time.Since(s.total.at) >= pgTotalTTL {
		if err := s.refreshTotalLocked(ctx); err != nil {
			return false, err
		}
	}
	if s.total.rooms >= max {
		return false, nil
	}
	s.total.rooms++
	return true, nil
}

func (s *postgresStore) addTotal(n int64) {
	s.total.mu.Lock()
	s.total.bytes += n
	s.total.mu.Unlock()
}

// touchRoomTx accounts a write of addBytes room bytes and addEnv envelopes
// to room inside tx, creating the room on its first write, and enforces the
// quotas in ctx. The caller rolls tx back on an error, which undoes the
// accounting with the write.
func (s *postgresStore) touchRoomTx(ctx context.Context, tx pgx.Tx, room string, addBytes, addEnv int64) error {
	q := quotaFrom(ctx)
	tenant, creator := "", ""
	if q != nil {
		tenant, creator = q.Tenant, q.Creator
	}
	if q != nil && q.TotalMaxBytes > 0 && addBytes > 0 {
		total, err := s.totalRoomBytes(ctx)
		if err != nil {
			return err
		}
		if total+addBytes > q.TotalMaxBytes {
			return errQuota(limTotalBytes, tenant)
		}
	}
	var bytes, envs int64
	var rowTenant string
	var inserted bool
	if err := tx.QueryRow(ctx, `
INSERT INTO relay_rooms (workspace, tenant, creator, bytes, envelopes, last_write) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (workspace) DO UPDATE SET
  bytes = relay_rooms.bytes + EXCLUDED.bytes,
  envelopes = relay_rooms.envelopes + EXCLUDED.envelopes,
  last_write = CASE WHEN EXCLUDED.bytes > 0 OR EXCLUDED.envelopes > 0 THEN EXCLUDED.last_write ELSE relay_rooms.last_write END
RETURNING bytes, envelopes, tenant, (xmax = 0)`,
		room, tenant, creator, addBytes, addEnv, time.Now().Unix()).Scan(&bytes, &envs, &rowTenant, &inserted); err != nil {
		return err
	}
	if q != nil {
		switch {
		case addBytes > 0 && q.RoomMaxBytes > 0 && bytes > q.RoomMaxBytes:
			return errQuota(limRoomBytes, rowTenant)
		case addEnv > 0 && q.RoomMaxEnvelopes > 0 && envs > q.RoomMaxEnvelopes:
			return errQuota(limRoomEnvelopes, rowTenant)
		}
		if inserted && q.TotalMaxRooms > 0 {
			// The cached count includes this room (counted by reserveRoom;
			// a rollback is corrected at the next re-read).
			ok, err := s.reserveRoom(ctx, q.TotalMaxRooms)
			if err != nil {
				return err
			}
			if !ok {
				return errQuota(limTotalRooms, rowTenant)
			}
		}
		if inserted && q.CreatorMaxRooms > 0 && creator != "" {
			// Serialize this creator's room creations, then count (the
			// count sees our own row and every committed one).
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('relay_room_creator:' || $1, 0))`, creator); err != nil {
				return err
			}
			var n int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM relay_rooms WHERE creator = $1`, creator).Scan(&n); err != nil {
				return err
			}
			if n > q.CreatorMaxRooms {
				return errQuota(limClientRooms, rowTenant)
			}
		}
	}
	if rowTenant != "" && (addBytes != 0 || inserted) {
		var tb, tr int64
		var newRoom int64
		if inserted {
			newRoom = 1
		}
		if err := tx.QueryRow(ctx, `
INSERT INTO relay_tenant_usage (tenant, bytes, rooms) VALUES ($1, $2, $3)
ON CONFLICT (tenant) DO UPDATE SET bytes = relay_tenant_usage.bytes + EXCLUDED.bytes, rooms = relay_tenant_usage.rooms + EXCLUDED.rooms
RETURNING bytes, rooms`, rowTenant, addBytes, newRoom).Scan(&tb, &tr); err != nil {
			return err
		}
		if q != nil {
			switch {
			case addBytes > 0 && q.TenantMaxBytes > 0 && tb > q.TenantMaxBytes:
				return errQuota(limTenantBytes, rowTenant)
			case inserted && q.TenantMaxRooms > 0 && tr > q.TenantMaxRooms:
				return errQuota(limTenantRooms, rowTenant)
			}
		}
	}
	return nil
}

func (s *postgresStore) RoomTotals(ctx context.Context) (int64, int64, error) {
	var rooms, bytes int64
	err := s.pool.QueryRow(ctx, `SELECT count(*), coalesce(sum(bytes), 0)::bigint FROM relay_rooms`).Scan(&rooms, &bytes)
	return rooms, bytes, err
}

func (s *postgresStore) TenantUsage(ctx context.Context, tenant string) (int64, int64, error) {
	var bytes, rooms int64
	var err error
	if tenant == "" {
		err = s.pool.QueryRow(ctx, `SELECT coalesce(sum(bytes), 0)::bigint, count(*) FROM relay_rooms WHERE tenant = ''`).Scan(&bytes, &rooms)
	} else {
		err = s.pool.QueryRow(ctx, `SELECT bytes, rooms FROM relay_tenant_usage WHERE tenant = $1`, tenant).Scan(&bytes, &rooms)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, nil
		}
	}
	return bytes, rooms, err
}

func (s *postgresStore) ListRooms(ctx context.Context, tenant, after string, limit int) ([]RoomUsage, error) {
	if limit <= 0 {
		limit = maxTenantRoomPage
	}
	rows, err := s.pool.Query(ctx,
		`SELECT workspace, tenant, bytes, envelopes, last_write FROM relay_rooms
		 WHERE tenant = $1 AND workspace > $2 ORDER BY workspace LIMIT $3`, tenant, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RoomUsage{}
	for rows.Next() {
		var r RoomUsage
		if err := rows.Scan(&r.Room, &r.Tenant, &r.Bytes, &r.Envelopes, &r.LastWrite); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// expireRoomsTx deletes the stored data of rooms (and, with roster, their
// roster and invites) and their accounting rows. relay_seq is kept, so a
// room written again continues its sequence.
func (s *postgresStore) expireRoomsTx(ctx context.Context, tx pgx.Tx, rooms []string, roster bool) error {
	tables := []string{"relay_envelopes", "relay_keyring", "relay_candidates", "relay_presence"}
	if roster {
		tables = append(tables, "relay_workspace_members", "relay_workspace_invites")
	}
	for _, t := range tables {
		if _, err := tx.Exec(ctx, `DELETE FROM `+t+` WHERE workspace = ANY($1)`, rooms); err != nil {
			return err
		}
	}
	if err := expireRoomBlobsTx(ctx, tx, rooms); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
WITH r AS (DELETE FROM relay_rooms WHERE workspace = ANY($1) RETURNING tenant, bytes),
x AS (SELECT tenant, sum(bytes)::bigint AS b, count(*)::bigint AS c FROM r WHERE tenant <> '' GROUP BY tenant)
UPDATE relay_tenant_usage tu SET bytes = tu.bytes - x.b, rooms = tu.rooms - x.c FROM x WHERE tu.tenant = x.tenant`, rooms)
	return err
}

func (s *postgresStore) PurgeRoom(ctx context.Context, room string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	// Lock the room's row first, as retention does: an append in flight
	// (row updated, envelope not yet committed) then finishes before the
	// deletes run, instead of leaving an envelope behind with no row
	// counting it.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM relay_rooms WHERE workspace = $1 FOR UPDATE`, room); err != nil {
		return false, err
	}
	var existed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM relay_rooms WHERE workspace = $1)
		OR EXISTS (SELECT 1 FROM relay_workspace_members WHERE workspace = $1)`, room).Scan(&existed); err != nil {
		return false, err
	}
	if err := s.expireRoomsTx(ctx, tx, []string{room}, true); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	s.total.mu.Lock()
	s.total.at = time.Time{}
	s.total.mu.Unlock()
	return existed, nil
}

// PruneIdleRooms expires rooms in batches; each batch locks its rooms' rows,
// so a write racing the expiry either lands first (and the room is no longer
// idle when its row is re-checked) or after (and starts the room again).
func (s *postgresStore) PruneIdleRooms(ctx context.Context, cutoff int64) (int64, error) {
	var total int64
	for {
		n, err := s.pruneIdleBatch(ctx, cutoff, 500)
		total += n
		if err != nil || n < 500 {
			if total > 0 {
				s.total.mu.Lock()
				s.total.at = time.Time{}
				s.total.mu.Unlock()
			}
			return total, err
		}
	}
}

func (s *postgresStore) pruneIdleBatch(ctx context.Context, cutoff int64, batch int) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx,
		`SELECT workspace FROM relay_rooms WHERE last_write < $1 ORDER BY workspace LIMIT $2 FOR UPDATE SKIP LOCKED`, cutoff, batch)
	if err != nil {
		return 0, err
	}
	var rooms []string
	for rows.Next() {
		var w string
		if err := rows.Scan(&w); err != nil {
			rows.Close()
			return 0, err
		}
		rooms = append(rooms, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(rooms) == 0 {
		return 0, nil
	}
	if err := s.expireRoomsTx(ctx, tx, rooms, false); err != nil {
		return 0, err
	}
	return int64(len(rooms)), tx.Commit(ctx)
}
