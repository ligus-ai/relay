package langstrothauth

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pods starting together all create the schema; under the advisory lock none
// of them fails on a catalog race.
func TestPGConcurrentMigrations(t *testing.T) {
	dsn := os.Getenv("LANGSTROTH_AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set LANGSTROTH_AUTH_TEST_DATABASE_URL to run Postgres tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("auth_migrate_%d", rand.Int64N(1<<40))
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") //nolint:errcheck
	u, _ := url.Parse(dsn)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, err := NewPostgresStore(ctx, u.String())
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

// Through a transaction-pooling PgBouncer the migration must not leave its
// advisory lock held on a server connection (a session lock's unlock lands
// on another one). LANGSTROTH_AUTH_TEST_PGBOUNCER_URL: the same database through
// PgBouncer, pool_mode=transaction.
func TestPGMigrationLeavesNoLockBehindAPooler(t *testing.T) {
	dsn, pooled := os.Getenv("LANGSTROTH_AUTH_TEST_DATABASE_URL"), os.Getenv("LANGSTROTH_AUTH_TEST_PGBOUNCER_URL")
	if dsn == "" || pooled == "" {
		t.Skip("set LANGSTROTH_AUTH_TEST_DATABASE_URL and LANGSTROTH_AUTH_TEST_PGBOUNCER_URL to run")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	key := uint64(migrationLockKey)
	hi, lo := int64(key>>32), int64(key&0xffffffff)
	// The default schema: PgBouncer doesn't carry a search_path startup
	// parameter onto its server connections. Migrations are idempotent.
	for i := 0; i < 10; i++ {
		st, err := NewPostgresStore(ctx, pooled)
		if err != nil {
			t.Fatalf("boot %d through the pooler: %v", i, err)
		}
		st.Close()
		var held int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted
			AND classid = $1::bigint::oid AND objid = $2::bigint::oid`, hi, lo).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if held != 0 {
			t.Fatalf("boot %d left the migration lock held by %d server session(s)", i, held)
		}
	}
}
