package relay

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Every relay pod migrates at startup. Without a lock, concurrent
// CREATE TABLE / CREATE INDEX IF NOT EXISTS on a fresh database race in the
// catalog (unique violations on pg_type / pg_class) and pods crash-loop.
// With the advisory lock, N pods migrating at once all succeed.
func TestPG_ConcurrentMigrationsTakeTheLock(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run Postgres integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("migrate_test_%d", rand.Int64N(1<<40))
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") //nolint:errcheck
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, err := newPostgresStore(ctx, u.String())
			if err != nil {
				errs <- err
				return
			}
			st.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent migration failed: %v", err)
	}
}

// pgTestSchema makes a throwaway schema and returns a DSN using it.
func pgTestSchema(t *testing.T, admin *pgxpool.Pool, dsn string) string {
	t.Helper()
	ctx := context.Background()
	schema := fmt.Sprintf("migrate_test_%d", rand.Int64N(1<<40))
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// A pod that holds the migration lock and hangs (or a lock leaked by a
// pooler, below) must not keep every other pod waiting forever: startup gives
// up after migrateLockWait with an error, and the orchestrator restarts it.
func TestPG_MigrationLockWaitIsBounded(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run Postgres integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	target := pgTestSchema(t, admin, dsn)
	holder, err := admin.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		t.Fatal(err)
	}
	defer holder.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockKey) //nolint:errcheck
	old := migrateLockWait
	migrateLockWait = 2 * time.Second
	defer func() { migrateLockWait = old }()
	done := make(chan error, 1)
	go func() {
		st, err := newPostgresStore(ctx, target)
		if err == nil {
			st.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("migrated although another session held the migration lock")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("startup still waiting on the migration lock after 20s: an unbounded wait")
	}
}

// Behind a transaction-pooling PgBouncer (Fly Managed Postgres, most hosted
// Postgres) consecutive statements of one client land on different server
// connections. A session lock taken by one statement and released by another
// then leaks on the server connection that took it, and every later boot
// waits on it. TEST_PGBOUNCER_URL: the same database through PgBouncer in
// pool_mode=transaction (server_round_robin=1 makes it show quickly).
func TestPG_MigrationLeavesNoLockBehindAPooler(t *testing.T) {
	dsn, pooled := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_PGBOUNCER_URL")
	if dsn == "" || pooled == "" {
		t.Skip("set TEST_DATABASE_URL and TEST_PGBOUNCER_URL (transaction pooling) to run")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	old := migrateLockWait
	migrateLockWait = 5 * time.Second
	defer func() { migrateLockWait = old }()
	key := uint64(migrationLockKey)
	hi, lo := uint32(key>>32), uint32(key&0xffffffff)
	// The default schema: PgBouncer doesn't carry a search_path startup
	// parameter onto its server connections. Migrations are idempotent.
	for i := 0; i < 30; i++ {
		st, err := newPostgresStore(ctx, pooled)
		if err != nil {
			t.Fatalf("boot %d through the pooler: %v", i, err)
		}
		st.Close()
		var held int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted
			AND classid = $1::bigint::oid AND objid = $2::bigint::oid`, int64(hi), int64(lo)).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if held != 0 {
			t.Fatalf("boot %d left the migration lock held by %d server session(s)", i, held)
		}
	}
}
