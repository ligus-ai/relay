package langstrothauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreDSNFromEnvOrFile(t *testing.T) {
	c := &Config{}
	c.Store.Driver = "postgres"
	c.Store.DSNEnv = "LANGSTROTH_AUTH_TEST_DSN"

	t.Setenv("LANGSTROTH_AUTH_TEST_DSN", "")
	t.Setenv("LANGSTROTH_AUTH_TEST_DSN_FILE", "")
	if _, err := storeDSN(c); err == nil || !strings.Contains(err.Error(), "LANGSTROTH_AUTH_TEST_DSN_FILE") {
		t.Fatalf("unset: err = %v", err)
	}

	t.Setenv("LANGSTROTH_AUTH_TEST_DSN", "postgres://env")
	if got, err := storeDSN(c); err != nil || got != "postgres://env" {
		t.Fatalf("env: %q %v", got, err)
	}

	f := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(f, []byte("postgres://file\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANGSTROTH_AUTH_TEST_DSN_FILE", f)
	if _, err := storeDSN(c); err == nil {
		t.Fatal("both env and file set must be refused")
	}
	t.Setenv("LANGSTROTH_AUTH_TEST_DSN", "")
	if got, err := storeDSN(c); err != nil || got != "postgres://file" {
		t.Fatalf("file: %q %v", got, err)
	}

	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := storeDSN(c); err == nil {
		t.Fatal("world-readable DSN file must be refused")
	}
}
