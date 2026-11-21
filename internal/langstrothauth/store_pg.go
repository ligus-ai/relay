package langstrothauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgStore is the Postgres store, for more than one langstroth-auth replica. The
// short-lived flow state stays per process, so replicas behind a load
// balancer need session affinity for the browser and device-code steps (see
// the deployment docs); tokens, users and grants are shared.
type pgStore struct{ pool *pgxpool.Pool }

const pgSchema = `
CREATE TABLE IF NOT EXISTS ligus_auth_users (
  tenant text NOT NULL, id text NOT NULL,
  user_name text NOT NULL, user_name_lc text NOT NULL,
  external_id text NOT NULL DEFAULT '', display_name text NOT NULL DEFAULT '',
  active boolean NOT NULL, subject text NOT NULL DEFAULT '',
  created bigint NOT NULL, modified bigint NOT NULL,
  PRIMARY KEY (tenant, id));
CREATE UNIQUE INDEX IF NOT EXISTS ligus_auth_users_uname ON ligus_auth_users (tenant, user_name_lc);
CREATE UNIQUE INDEX IF NOT EXISTS ligus_auth_users_ext ON ligus_auth_users (tenant, external_id) WHERE external_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS ligus_auth_users_sub ON ligus_auth_users (tenant, subject) WHERE subject <> '';
CREATE TABLE IF NOT EXISTS ligus_auth_groups (
  tenant text NOT NULL, id text NOT NULL,
  display_name text NOT NULL, display_name_lc text NOT NULL,
  external_id text NOT NULL DEFAULT '',
  created bigint NOT NULL, modified bigint NOT NULL,
  PRIMARY KEY (tenant, id));
CREATE UNIQUE INDEX IF NOT EXISTS ligus_auth_groups_name ON ligus_auth_groups (tenant, display_name_lc);
CREATE TABLE IF NOT EXISTS ligus_auth_group_members (
  tenant text NOT NULL, group_id text NOT NULL, user_id text NOT NULL,
  PRIMARY KEY (tenant, group_id, user_id),
  FOREIGN KEY (tenant, group_id) REFERENCES ligus_auth_groups (tenant, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant, user_id) REFERENCES ligus_auth_users (tenant, id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS ligus_auth_group_members_user ON ligus_auth_group_members (tenant, user_id);
CREATE TABLE IF NOT EXISTS ligus_auth_grants (
  tenant text NOT NULL, grp text NOT NULL, workspaces text[] NOT NULL,
  PRIMARY KEY (tenant, grp));
CREATE TABLE IF NOT EXISTS ligus_auth_refresh (
  hash text PRIMARY KEY, tenant text NOT NULL, family_id text NOT NULL,
  user_id text NOT NULL, client_id text NOT NULL, device_id text NOT NULL,
  device_key text NOT NULL, idp_groups text[] NOT NULL DEFAULT '{}',
  session_start bigint NOT NULL, expires_at bigint NOT NULL, created_at bigint NOT NULL,
  used boolean NOT NULL DEFAULT false, revoked boolean NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS ligus_auth_refresh_family ON ligus_auth_refresh (tenant, family_id);
CREATE INDEX IF NOT EXISTS ligus_auth_refresh_user ON ligus_auth_refresh (tenant, user_id);
CREATE INDEX IF NOT EXISTS ligus_auth_refresh_exp ON ligus_auth_refresh (expires_at);
`

// migrationLockKey is the pg_advisory_lock key langstroth-auth takes while
// creating its schema ("ligusath" in ASCII; the relay uses "ligusrly").
const migrationLockKey int64 = 0x6c69677573617468

// migrate creates the schema in one transaction under a transaction-scoped
// advisory lock, so pods starting together don't race in the catalog. Not a
// session lock: behind a transaction-pooling PgBouncer its unlock can land on
// another server connection and the lock leaks (see the relay's migrate).
// Migrations are additive. The caller's context bounds the wait.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if dl, ok := ctx.Deadline(); ok {
		if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL lock_timeout = %d", time.Until(dl).Milliseconds()+1)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("migration lock: %w", err)
	}
	if _, err := tx.Exec(ctx, pgSchema); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// NewPostgresStore connects and creates the schema if needed.
func NewPostgresStore(ctx context.Context, dsn string) (Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("postgres: invalid DSN") // never echo the DSN (it may hold a password)
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := migrate(cctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres schema: %w", err)
	}
	return &pgStore{pool: pool}, nil
}

func pgErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return ErrConflict
		case "23503":
			return ErrNotFound
		}
	}
	return err
}

const userCols = `tenant, id, user_name, external_id, display_name, active, subject, created, modified`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.Tenant, &u.ID, &u.UserName, &u.ExternalID, &u.DisplayName, &u.Active, &u.Subject, &u.Created, &u.Modified)
	return u, pgErr(err)
}

func (s *pgStore) CreateUser(ctx context.Context, u User) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO ligus_auth_users (tenant, id, user_name, user_name_lc, external_id, display_name, active, subject, created, modified)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		u.Tenant, u.ID, u.UserName, strings.ToLower(u.UserName), u.ExternalID, u.DisplayName, u.Active, u.Subject, u.Created, u.Modified)
	return pgErr(err)
}

func (s *pgStore) GetUser(ctx context.Context, tenant, id string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM ligus_auth_users WHERE tenant=$1 AND id=$2`, tenant, id))
}

func (s *pgStore) FindUser(ctx context.Context, tenant, attr, value string) (User, error) {
	if value == "" {
		return User{}, ErrNotFound
	}
	var col string
	switch attr {
	case "userName":
		col, value = "user_name_lc", strings.ToLower(value)
	case "externalId":
		col = "external_id"
	case "subject":
		col = "subject"
	default:
		return User{}, ErrNotFound
	}
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM ligus_auth_users WHERE tenant=$1 AND `+col+`=$2`, tenant, value))
}

func (s *pgStore) ListUsers(ctx context.Context, tenant string) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM ligus_auth_users WHERE tenant=$1 ORDER BY created, id`, tenant)
	if err != nil {
		return nil, pgErr(err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, pgErr(rows.Err())
}

func (s *pgStore) UpdateUser(ctx context.Context, u User) error {
	tag, err := s.pool.Exec(ctx, `UPDATE ligus_auth_users SET user_name=$3, user_name_lc=$4, external_id=$5, display_name=$6, active=$7, subject=$8, modified=$9
		WHERE tenant=$1 AND id=$2`,
		u.Tenant, u.ID, u.UserName, strings.ToLower(u.UserName), u.ExternalID, u.DisplayName, u.Active, u.Subject, u.Modified)
	if err != nil {
		return pgErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *pgStore) DeleteUser(ctx context.Context, tenant, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE ligus_auth_refresh SET revoked=true WHERE tenant=$1 AND user_id=$2`, tenant, id); err != nil {
			return pgErr(err)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM ligus_auth_users WHERE tenant=$1 AND id=$2`, tenant, id)
		if err != nil {
			return pgErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *pgStore) setMembers(ctx context.Context, tx pgx.Tx, g Group) error {
	if _, err := tx.Exec(ctx, `DELETE FROM ligus_auth_group_members WHERE tenant=$1 AND group_id=$2`, g.Tenant, g.ID); err != nil {
		return pgErr(err)
	}
	for _, m := range sortedUnique(g.Members) {
		if _, err := tx.Exec(ctx, `INSERT INTO ligus_auth_group_members (tenant, group_id, user_id) VALUES ($1,$2,$3)`, g.Tenant, g.ID, m); err != nil {
			return pgErr(err)
		}
	}
	return nil
}

func (s *pgStore) CreateGroup(ctx context.Context, g Group) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ligus_auth_groups (tenant, id, display_name, display_name_lc, external_id, created, modified) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			g.Tenant, g.ID, g.DisplayName, strings.ToLower(g.DisplayName), g.ExternalID, g.Created, g.Modified); err != nil {
			return pgErr(err)
		}
		return s.setMembers(ctx, tx, g)
	})
}

func (s *pgStore) members(ctx context.Context, tenant, id string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_id FROM ligus_auth_group_members WHERE tenant=$1 AND group_id=$2 ORDER BY user_id`, tenant, id)
	if err != nil {
		return nil, pgErr(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, pgErr(rows.Err())
}

func (s *pgStore) GetGroup(ctx context.Context, tenant, id string) (Group, error) {
	var g Group
	err := s.pool.QueryRow(ctx, `SELECT tenant, id, display_name, external_id, created, modified FROM ligus_auth_groups WHERE tenant=$1 AND id=$2`, tenant, id).
		Scan(&g.Tenant, &g.ID, &g.DisplayName, &g.ExternalID, &g.Created, &g.Modified)
	if err != nil {
		return Group{}, pgErr(err)
	}
	g.Members, err = s.members(ctx, tenant, id)
	return g, err
}

func (s *pgStore) ListGroups(ctx context.Context, tenant string) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM ligus_auth_groups WHERE tenant=$1 ORDER BY created, id`, tenant)
	if err != nil {
		return nil, pgErr(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := make([]Group, 0, len(ids))
	for _, id := range ids {
		g, err := s.GetGroup(ctx, tenant, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func (s *pgStore) UpdateGroup(ctx context.Context, g Group) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ligus_auth_groups SET display_name=$3, display_name_lc=$4, external_id=$5, modified=$6 WHERE tenant=$1 AND id=$2`,
			g.Tenant, g.ID, g.DisplayName, strings.ToLower(g.DisplayName), g.ExternalID, g.Modified)
		if err != nil {
			return pgErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return s.setMembers(ctx, tx, g)
	})
}

func (s *pgStore) DeleteGroup(ctx context.Context, tenant, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ligus_auth_groups WHERE tenant=$1 AND id=$2`, tenant, id)
	if err != nil {
		return pgErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *pgStore) UserGroupNames(ctx context.Context, tenant, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT g.display_name FROM ligus_auth_group_members m JOIN ligus_auth_groups g ON g.tenant=m.tenant AND g.id=m.group_id
		WHERE m.tenant=$1 AND m.user_id=$2 ORDER BY g.display_name`, tenant, userID)
	if err != nil {
		return nil, pgErr(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, pgErr(rows.Err())
}

func (s *pgStore) SetGrant(ctx context.Context, tenant, group string, workspaces []string) error {
	ws := sortedUnique(workspaces)
	if len(ws) == 0 {
		_, err := s.pool.Exec(ctx, `DELETE FROM ligus_auth_grants WHERE tenant=$1 AND grp=$2`, tenant, group)
		return pgErr(err)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO ligus_auth_grants (tenant, grp, workspaces) VALUES ($1,$2,$3)
		ON CONFLICT (tenant, grp) DO UPDATE SET workspaces=EXCLUDED.workspaces`, tenant, group, ws)
	return pgErr(err)
}

func (s *pgStore) ListGrants(ctx context.Context, tenant string) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT grp, workspaces FROM ligus_auth_grants WHERE tenant=$1`, tenant)
	if err != nil {
		return nil, pgErr(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g string
		var ws []string
		if err := rows.Scan(&g, &ws); err != nil {
			return nil, err
		}
		out[g] = ws
	}
	return out, pgErr(rows.Err())
}

const refreshCols = `hash, tenant, family_id, user_id, client_id, device_id, device_key, idp_groups, session_start, expires_at, created_at, used, revoked`

func (s *pgStore) insertRefresh(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, rt RefreshToken) error {
	groups := rt.IdPGroups
	if groups == nil {
		groups = []string{}
	}
	_, err := q.Exec(ctx, `INSERT INTO ligus_auth_refresh (`+refreshCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		rt.Hash, rt.Tenant, rt.FamilyID, rt.UserID, rt.ClientID, rt.DeviceID, rt.DeviceKey, groups, rt.SessionStart, rt.ExpiresAt, rt.CreatedAt, rt.Used, rt.Revoked)
	return pgErr(err)
}

func (s *pgStore) PutRefresh(ctx context.Context, rt RefreshToken) error {
	return s.insertRefresh(ctx, s.pool, rt)
}

func scanRefresh(row pgx.Row) (RefreshToken, error) {
	var rt RefreshToken
	err := row.Scan(&rt.Hash, &rt.Tenant, &rt.FamilyID, &rt.UserID, &rt.ClientID, &rt.DeviceID, &rt.DeviceKey, &rt.IdPGroups, &rt.SessionStart, &rt.ExpiresAt, &rt.CreatedAt, &rt.Used, &rt.Revoked)
	if len(rt.IdPGroups) == 0 {
		rt.IdPGroups = nil
	}
	return rt, pgErr(err)
}

func (s *pgStore) GetRefresh(ctx context.Context, hash string) (RefreshToken, error) {
	return scanRefresh(s.pool.QueryRow(ctx, `SELECT `+refreshCols+` FROM ligus_auth_refresh WHERE hash=$1`, hash))
}

func (s *pgStore) RotateRefresh(ctx context.Context, oldHash string, next RefreshToken) error {
	reused := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		old, err := scanRefresh(tx.QueryRow(ctx, `SELECT `+refreshCols+` FROM ligus_auth_refresh WHERE hash=$1 FOR UPDATE`, oldHash))
		if err != nil {
			return err
		}
		if old.Used || old.Revoked {
			reused = true
			_, err := tx.Exec(ctx, `UPDATE ligus_auth_refresh SET revoked=true WHERE tenant=$1 AND family_id=$2`, old.Tenant, old.FamilyID)
			return pgErr(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE ligus_auth_refresh SET used=true WHERE hash=$1`, oldHash); err != nil {
			return pgErr(err)
		}
		return s.insertRefresh(ctx, tx, next)
	})
	if err != nil {
		return err
	}
	if reused {
		return ErrRefreshReused
	}
	return nil
}

func (s *pgStore) RevokeFamily(ctx context.Context, tenant, familyID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE ligus_auth_refresh SET revoked=true WHERE tenant=$1 AND family_id=$2`, tenant, familyID)
	return pgErr(err)
}

func (s *pgStore) RevokeUser(ctx context.Context, tenant, userID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE ligus_auth_refresh SET revoked=true WHERE tenant=$1 AND user_id=$2 AND NOT revoked`, tenant, userID)
	if err != nil {
		return 0, pgErr(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *pgStore) RevokeDevice(ctx context.Context, tenant, deviceID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE ligus_auth_refresh SET revoked=true WHERE tenant=$1 AND device_id=$2 AND NOT revoked`, tenant, deviceID)
	if err != nil {
		return 0, pgErr(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *pgStore) PruneRefresh(ctx context.Context, now int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM ligus_auth_refresh WHERE expires_at < $1`, now)
	return pgErr(err)
}

func (s *pgStore) Close() error { s.pool.Close(); return nil }
