package langstrothauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LIGUS_AUTH_* names are not read, and any of them stops the service.
func TestRemovedAuthEnvNames(t *testing.T) {
	t.Setenv("LIGUS_AUTH_ENV_ALIAS_TEST", "former")
	if got := authGetenv("LANGSTROTH_AUTH_ENV_ALIAS_TEST"); got != "" {
		t.Fatalf("former name must not be read, got %q", got)
	}
	err := removedEnvError(os.Environ())
	if err == nil || !strings.Contains(err.Error(), "LIGUS_AUTH_ENV_ALIAS_TEST -> LANGSTROTH_AUTH_ENV_ALIAS_TEST") || strings.Contains(err.Error(), "former") {
		t.Fatalf("want an error naming the new name and not the value, got %v", err)
	}
	if err := removedEnvError([]string{"LANGSTROTH_AUTH_X=1"}); err != nil {
		t.Fatalf("canonical names: %v", err)
	}
}

func TestSigningKeyFromEnvAndFormerCredential(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteNewSigningKey(filepath.Join(dir, "ligus-auth-signing-key")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANGSTROTH_AUTH_SIGNING_KEY_FILE", "")
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, src, err := LoadSigningKey(""); err != nil || src != "file" {
		t.Fatalf("former systemd credential name: %q %v", src, err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("LANGSTROTH_AUTH_SIGNING_KEY_FILE", filepath.Join(dir, "ligus-auth-signing-key"))
	if _, src, err := LoadSigningKey(""); err != nil || src != "file" {
		t.Fatalf("LANGSTROTH_AUTH_SIGNING_KEY_FILE: %q %v", src, err)
	}
}
