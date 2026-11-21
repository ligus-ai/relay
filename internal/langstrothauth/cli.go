package langstrothauth

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func osStderr() io.Writer { return os.Stderr }

const usage = `langstroth-auth: sign in with any OIDC provider, get short-lived relay tokens

  langstroth-auth [serve] [--config FILE]   run the service (default; LANGSTROTH_AUTH_CONFIG)
  langstroth-auth keygen --out FILE         create an issuer key (0600); prints only the public key
  langstroth-auth pubkey [--config FILE]    print the issuer public key for LANGSTROTH_RELAY_TOKEN_PUBKEY
  langstroth-auth check-config [--config FILE]
  langstroth-auth gen-token                 print a random token (for SCIM or the admin API)
  langstroth-auth hash-token                read a token on stdin, print its SHA-256 (scim_token_sha256)

Secrets: the issuer key comes from signing_key_file, LANGSTROTH_AUTH_SIGNING_KEY_FILE,
a systemd credential named langstroth-auth-signing-key, or LANGSTROTH_AUTH_SIGNING_KEY.
The admin API token comes from LANGSTROTH_AUTH_ADMIN_TOKEN_FILE or LANGSTROTH_AUTH_ADMIN_TOKEN.
`

// Main runs the langstroth-auth binary.
func Main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	// A LIGUS_AUTH_* name (no longer read) would silently drop its setting.
	if err := removedEnvError(os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "langstroth-auth:", err)
		os.Exit(1)
	}
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "keygen":
		err = cmdKeygen(args)
	case "pubkey":
		err = cmdPubkey(args)
	case "check-config":
		err = cmdCheck(args)
	case "gen-token":
		fmt.Println(randToken(32))
	case "hash-token":
		line, rerr := bufio.NewReader(os.Stdin).ReadString('\n')
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			err = rerr
			break
		}
		if strings.TrimSpace(line) == "" {
			err = errors.New("no token on stdin")
			break
		}
		fmt.Println(sha256Hex(strings.TrimSpace(line)))
	case "help", "-h", "--help":
		fmt.Fprint(os.Stderr, usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "langstroth-auth:", err)
		os.Exit(1)
	}
}

const (
	defaultConfigPath = "/etc/langstroth-auth/config.json"
	formerConfigPath  = "/etc/ligus-auth/config.json"
)

func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	def := authGetenv("LANGSTROTH_AUTH_CONFIG")
	if def == "" {
		def = defaultConfigPath
		// Installs from before the Langstroth rename mount the file here.
		if _, err := os.Stat(def); errors.Is(err, os.ErrNotExist) {
			if _, err := os.Stat(formerConfigPath); err == nil {
				def = formerConfigPath
			}
		}
	}
	path := fs.String("config", def, "configuration file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *path, nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "file to create (mode 0600; never overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out FILE is required (the key is never printed)")
	}
	pub, err := WriteNewSigningKey(*out)
	if err != nil {
		return err
	}
	fmt.Printf("public_key=%s\n# Set LANGSTROTH_RELAY_TOKEN_PUBKEY=%s on the relay. The private key stays in %s.\n", pub, pub, *out)
	return nil
}

func cmdPubkey(args []string) error {
	path, err := configFlag("pubkey", args)
	if err != nil {
		return err
	}
	file := ""
	if c, err := LoadConfig(path); err == nil {
		file = c.SigningKeyFile
	}
	k, _, err := LoadSigningKey(file)
	if err != nil {
		return err
	}
	srvPub := k.Public()
	fmt.Printf("%x\n", srvPub)
	return nil
}

func cmdCheck(args []string) error {
	path, err := configFlag("check-config", args)
	if err != nil {
		return err
	}
	c, err := LoadConfig(path)
	if err != nil {
		return err
	}
	if _, _, err := LoadSigningKey(c.SigningKeyFile); err != nil {
		return err
	}
	fmt.Printf("ok: %d tenant(s)\n", len(c.Tenants))
	return nil
}

func adminTokenFromEnv() (string, error) {
	return readSecret(authGetenv("LANGSTROTH_AUTH_ADMIN_TOKEN_FILE"), authEnvName("LANGSTROTH_AUTH_ADMIN_TOKEN"))
}

// storeDSN is the Postgres DSN: the env var named by store.dsn_env, or the
// file named by <dsn_env>_FILE (a mounted Secret; never both).
func storeDSN(c *Config) (string, error) {
	file := authGetenv(c.Store.DSNEnv + "_FILE")
	env := ""
	if authGetenv(c.Store.DSNEnv) != "" {
		env = authEnvName(c.Store.DSNEnv)
	}
	dsn, err := readSecret(file, env)
	if err != nil {
		return "", fmt.Errorf("store postgres: %w", err)
	}
	if dsn == "" {
		return "", fmt.Errorf("store postgres: set %s or %s_FILE", c.Store.DSNEnv, c.Store.DSNEnv)
	}
	return dsn, nil
}

func openStore(ctx context.Context, c *Config) (Store, error) {
	if c.Store.Driver == "postgres" {
		dsn, err := storeDSN(c)
		if err != nil {
			return nil, err
		}
		return NewPostgresStore(ctx, dsn)
	}
	if c.Store.Path == "" {
		slog.Warn("langstroth-auth: store.path is empty; users and sessions are lost on restart")
	}
	return NewFileStore(c.Store.Path)
}

func cmdServe(args []string) error {
	path, err := configFlag("serve", args)
	if err != nil {
		return err
	}
	c, err := LoadConfig(path)
	if err != nil {
		return err
	}
	key, source, err := LoadSigningKey(c.SigningKeyFile)
	if err != nil {
		return err
	}
	if source == "env" {
		slog.Warn("langstroth-auth: issuer key read from LANGSTROTH_AUTH_SIGNING_KEY; prefer a 0600 file or a systemd credential")
	}
	adminTok, err := adminTokenFromEnv()
	if err != nil {
		return fmt.Errorf("admin token: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := openStore(ctx, c)
	if err != nil {
		return err
	}
	defer store.Close()
	var audit io.Writer
	if c.AuditLog != "" {
		f, err := os.OpenFile(c.AuditLog, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("audit log: %w", err)
		}
		defer f.Close()
		audit = f
	}
	srv, err := New(ctx, Options{Config: c, Store: store, Key: key, AdminToken: adminTok, AuditWriter: audit})
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				if err := store.PruneRefresh(ctx, now.Unix()); err != nil {
					slog.Error("langstroth-auth: prune refresh tokens", "error", err)
				}
			}
		}
	}()
	mk := func(addr string, h http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	}
	servers := []*http.Server{mk(c.Listen, srv.Handler())}
	if c.AdminListen != "" && adminTok != "" {
		servers = append(servers, mk(c.AdminListen, srv.AdminHandler()))
	} else if c.AdminListen != "" {
		slog.Warn("langstroth-auth: admin_listen is set but no admin token; the admin API stays off")
	}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) { errc <- s.ListenAndServe() }(s)
	}
	slog.Info("langstroth-auth listening", "addr", c.Listen, "admin", c.AdminListen != "" && adminTok != "", "tenants", len(c.Tenants), "token_pubkey", srv.PublicKeyHex())
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return nil
}
