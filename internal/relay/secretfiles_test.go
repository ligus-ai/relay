package relay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A secret file the relay can't read must stop it at startup. Before, the
// read error only logged a warning (a _FILE) or was ignored (the secrets
// directory) and the setting came back empty: an unreadable
// LANGSTROTH_RELAY_TOKEN_PUBKEY made an open relay, an unreadable DATABASE_URL
// file the in-memory store.
func TestSecretFilesConfigError_unreadableFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-0000 files")
	}
	dir := t.TempDir()
	pk := filepath.Join(dir, "LANGSTROTH_RELAY_TOKEN_PUBKEY")
	if err := os.WriteFile(pk, []byte(strings.Repeat("ab", 32)), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := checkEnvFiles(t, map[string]string{secretsDirEnv: dir}); err == nil {
		t.Error("an unreadable file in the secrets directory must be refused")
	}
	db := filepath.Join(dir, "db")
	if err := os.WriteFile(db, []byte("postgres://x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := checkEnvFiles(t, map[string]string{"DATABASE_URL_FILE": db}); err == nil {
		t.Error("an unreadable DATABASE_URL_FILE must be refused")
	}
	if err := checkEnvFiles(t, map[string]string{"LANGSTROTH_RELAY_ACCESS_TOKENS_FILE": filepath.Join(dir, "missing")}); err == nil {
		t.Error("a missing _FILE must be refused")
	}
	if err := checkEnvFiles(t, map[string]string{secretsDirEnv: filepath.Join(dir, "nope")}); err == nil {
		t.Error("a missing secrets directory must be refused")
	}
}

// checkEnvFiles runs the startup check with m as the only relay settings in
// the environment.
func checkEnvFiles(t *testing.T, m map[string]string) error {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, envPrefix) || k == "DATABASE_URL_FILE" {
			t.Setenv(k, "")
		}
	}
	for k, v := range m {
		t.Setenv(k, v)
	}
	return secretFilesConfigError(os.Getenv)
}

func TestSecretFilesConfigError_emptyFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tok")
	if err := os.WriteFile(f, []byte("\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := checkEnvFiles(t, map[string]string{"LANGSTROTH_RELAY_METRICS_TOKEN_FILE": f}); err == nil {
		t.Error("an empty _FILE would silently turn its setting off; refuse it")
	}
}

func TestSecretFilesConfigError_readableIsFine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LANGSTROTH_RELAY_METRICS_TOKEN"), []byte("m\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "..data"), 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "db")
	if err := os.WriteFile(f, []byte("postgres://x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := checkEnvFiles(t, map[string]string{secretsDirEnv: dir, "DATABASE_URL_FILE": f}); err != nil {
		t.Errorf("readable files: %v", err)
	}
	if err := checkEnvFiles(t, nil); err != nil {
		t.Errorf("no files: %v", err)
	}
}

// The process-level wiring: an unreadable file in the directory must not
// resolve to the empty string as if unset (that is what turned the gate off).
func TestResolveSetting_unreadableDirFileIsNotUnset(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-0000 files")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LANGSTROTH_RELAY_TOKEN_PUBKEY"), []byte("k"), 0o000); err != nil {
		t.Fatal(err)
	}
	var warned []string
	warn := func(key, msg string, args ...any) { warned = append(warned, key) }
	if v := resolveSetting("LANGSTROTH_RELAY_TOKEN_PUBKEY", env(map[string]string{secretsDirEnv: dir}), readSecretFile, warn); v != "" {
		t.Fatalf("got %q", v)
	}
	if len(warned) == 0 {
		t.Error("an unreadable secrets-directory file must at least be reported")
	}
}
