package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// langstroth-relay — the rendezvous + envelope-forwarding server.
//
// Address resolution (cloud-friendly), most specific first:
//  1. $PORT (set by Fly / Cloud Run / Railway / Heroku) → 0.0.0.0:$PORT
//  2. $LANGSTROTH_RELAY_ADDR (full host:port)
//  3. default 0.0.0.0:8443
//
// Storage:
//   - $DATABASE_URL set        → shared Postgres store (HA; no data migration).
//   - else $LANGSTROTH_RELAY_DATA_DIR → in-memory + JSON snapshot (single instance).
//   - else                      → in-memory only (ephemeral; tests).
//
// $LANGSTROTH_RELAY_FRIEND_CAP (optional) caps accepted friends per account.

// Main runs the open relay binary (cmd/langstroth-relay).
func Main() {
	// Structured JSON logs (request lines come from the observability middleware).
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "help", "--help", "-h":
			exitWith(cmdHelp(args[1:], os.Stdout))
		}
		cmd, ok := commands[args[0]]
		if !ok {
			exitWith(usageErrorf("unknown command %q (the server takes no arguments; try `langstroth-relay help`)", args[0]))
		}
		if wantsHelp(args[1:]) {
			exitWith(cmdHelp([]string{args[0]}, os.Stdout))
		}
		exitWith(cmd(args[1:]))
	}

	// Before anything reads a setting: a variable under a name from before
	// the Langstroth rename (HIVE_RELAY_*, LIGUS_RELAY_*; no longer read), or
	// an unreadable secret file (either would read as unset: push or the
	// tunnel off, an open access gate, the memory store), stops the relay.
	fatalIf(removedEnvError(os.Environ()))
	fatalIf(secretFilesConfigError(os.Getenv))
	fatalIf(entitlementConfigError())
	fatalIf(tenancyConfigError())
	fatalIf(evictionConfigError())
	fatalIf(routesConfigError(getenv))
	fatalIf(apnsWithoutTunnelError(getenv))

	store, err := buildStore(context.Background())
	fatalIf(err)
	defer store.Close()

	// Stop on Ctrl-C or SIGTERM (a redeploy from the orchestrator).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := New(Options{Store: store, FriendCap: friendCapFromEnv()})

	// Periodically snapshot durable state so an unexpected crash loses at most a
	// few seconds; a graceful shutdown flushes once more below.
	stopFlush := make(chan struct{})
	if store.PersistenceEnabled() {
		go flushLoop(store, stopFlush)
	}

	// Bound envelope growth on backends that don't prune inline (Postgres). The
	// in-memory store already enforces the same caps at write time.
	if pruner, ok := store.(housekeepingPruner); ok {
		go pruneLoop(pruner, stopFlush)
	}
	// Idle rooms (LANGSTROTH_RELAY_ROOM_RETENTION_DAYS): a whole room at a
	// time, never envelopes out of a room in use (docs/tenancy.md).
	lim := communityLimitsFromEnv()
	lim.log()
	if rs, ok := store.(roomStore); ok && lim.roomRetention > 0 {
		go roomRetentionLoop(rs, lim.roomRetention, stopFlush)
	}
	// Expired attachment blobs (LANGSTROTH_RELAY_BLOB_RETENTION_DAYS).
	bcfg := blobConfigFromEnv()
	bcfg.log()
	if bs, ok := store.(blobStore); ok && bcfg.enabled {
		go blobRetentionLoop(bs, stopFlush)
	}
	// Expired contact records and old drops, on every backend (the memory
	// store also hides expired records on access).
	if cs, ok := store.(ContactStore); ok {
		go contactPruneLoop(cs, stopFlush)
	}

	addr := resolveAddr()
	// Timeouts bound how long a single connection can tie up resources, which
	// defends against Slowloris (trickled headers/body) and stuck peers. The
	// relay is poll-based, not long-lived streaming, so modest read/write
	// deadlines are safe.
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           restrictRoutes(srv.Handler(), getenv),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// Tunnel WebSockets are hijacked (Shutdown doesn't see them): close them
	// with shutting_down so clients reconnect with backoff.
	httpServer.RegisterOnShutdown(srv.ShutdownTunnels)

	go func() {
		fmt.Printf("langstroth-relay listening on %s\n", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "langstroth-relay: serve error: %v\n", err)
			stop()
		}
	}()

	<-ctx.Done()
	close(stopFlush)

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutCtx)

	// Final flush on the way out so a planned redeploy never loses state.
	if err := store.Flush(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "langstroth-relay: final flush failed: %v\n", err)
	}
}

// buildStore selects the storage backend from the environment.
//
// The public production relay sets LANGSTROTH_RELAY_REQUIRE_DB=1 so it REFUSES to boot
// on the ephemeral in-memory fallback: a missing/typo'd DATABASE_URL there would
// otherwise silently serve every client from volatile memory and lose state on
// the next machine move (P2-16). Self-hosters leave it unset and keep the
// snapshot-store fallback.
func buildStore(ctx context.Context) (Store, error) {
	dsn := getenv("DATABASE_URL")
	if envBool("LANGSTROTH_RELAY_REQUIRE_DB") && dsn == "" {
		return nil, fmt.Errorf("LANGSTROTH_RELAY_REQUIRE_DB is set but DATABASE_URL is empty: refusing to boot on the ephemeral in-memory store")
	}
	if dsn != "" {
		return newPostgresStore(ctx, dsn)
	}
	if dir := getenv("LANGSTROTH_RELAY_DATA_DIR"); dir != "" {
		return newMemoryStoreWithPersistence(dir), nil
	}
	return newMemoryStore(), nil
}

func resolveAddr() string {
	if port := getenv("PORT"); port != "" {
		return "0.0.0.0:" + port
	}
	if addr := getenv("LANGSTROTH_RELAY_ADDR"); addr != "" {
		return addr
	}
	return "0.0.0.0:8443"
}

func friendCapFromEnv() *int {
	if v := getenv("LANGSTROTH_RELAY_FRIEND_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return &n
		}
	}
	return nil
}

func flushLoop(store Store, stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if err := store.Flush(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "langstroth-relay: snapshot flush failed: %v\n", err)
			}
		}
	}
}

// housekeepingPruner is implemented by backends whose side tables need
// periodic pruning (Postgres): the inbox and terminal friend requests
// (P2-13). Workspace envelopes are never pruned out of a room (eviction.go);
// the keyring is bounded by refusing rotations past its caps.
type housekeepingPruner interface {
	PruneInbox(ctx context.Context, maxRows int, maxAge time.Duration) (int64, error)
	PruneFriendRequests(ctx context.Context, maxAge time.Duration) (int64, error)
}

func pruneLoop(pruner housekeepingPruner, stop <-chan struct{}) {
	inboxAge := daysEnv("LANGSTROTH_RELAY_INBOX_RETENTION_DAYS", defaultInboxMaxAgeDays)
	friendReqAge := daysEnv("LANGSTROTH_RELAY_FRIEND_REQ_RETENTION_DAYS", defaultFriendReqMaxAgeDays)
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			runPrune("inbox", func() (int64, error) {
				return pruner.PruneInbox(context.Background(), defaultInboxMaxRows, inboxAge)
			})
			runPrune("friend_requests", func() (int64, error) {
				return pruner.PruneFriendRequests(context.Background(), friendReqAge)
			})
		}
	}
}

func contactPruneLoop(cs ContactStore, stop <-chan struct{}) {
	cfg := contactConfigFromEnv()
	dropAge, hold := cfg.dropMaxAge, cfg.limits.ReclaimHold
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			runPrune("contacts", func() (int64, error) {
				return cs.PruneContacts(context.Background(), nowUnix(), dropAge, hold)
			})
		}
	}
}

// runPrune executes one prune step and logs the outcome.
func runPrune(what string, fn func() (int64, error)) {
	n, err := fn()
	if err != nil {
		slog.Warn("prune failed", "table", what, "error", err)
	} else if n > 0 {
		slog.Info("pruned rows", "table", what, "deleted", n)
	}
}

// daysEnv reads a non-negative day count from env, else the default (0 disables).
func daysEnv(name string, def int) time.Duration {
	observeDefault(name, float64(def))
	d := def
	if v := getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			d = n
		}
	}
	return time.Duration(d) * 24 * time.Hour
}

// commands are the subcommands; no argument runs the server.
var commands = map[string]func(args []string) error{
	"keygen": func(args []string) error {
		if len(args) > 0 {
			return usageErrorf("keygen takes no arguments")
		}
		return cmdKeygen()
	},
	"issue":           cmdIssue,
	"bootstrap-agent": cmdBootstrapAgent,
	"check":           func(args []string) error { return cmdCheck(args, os.Stdout) },
}

// exitWith ends a subcommand: 0 on success, 2 for a usage error, else 1.
func exitWith(err error) {
	switch {
	case err == nil:
		os.Exit(exitOK)
	case errors.Is(err, errChecksFailed):
		os.Exit(exitFailed) // the report already said why
	case errors.Is(err, errUsage):
		fmt.Fprintf(os.Stderr, "langstroth-relay: %v\n", err)
		os.Exit(exitUsage)
	default:
		fmt.Fprintf(os.Stderr, "langstroth-relay: %v\n", err)
		os.Exit(exitFailed)
	}
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "langstroth-relay: %v\n", err)
		os.Exit(1)
	}
}
