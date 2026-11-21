package relay

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The names from before the Langstroth rename are not read at all.
func TestRemovedEnvNamesAreNotRead(t *testing.T) {
	t.Setenv("HIVE_RELAY_MAX_BODY_BYTES", "1234")
	t.Setenv("LIGUS_RELAY_INVITE_REQUIRE_FRIEND", "1")
	if got := envInt64("LANGSTROTH_RELAY_MAX_BODY_BYTES", 1); got != 1 {
		t.Fatalf("HIVE_RELAY_* must not be read, got %d", got)
	}
	if envBool("LANGSTROTH_RELAY_INVITE_REQUIRE_FRIEND") {
		t.Fatal("LIGUS_RELAY_* must not be read")
	}
	t.Setenv("LANGSTROTH_RELAY_MAX_BODY_BYTES", "99")
	if got := envInt64("LANGSTROTH_RELAY_MAX_BODY_BYTES", 1); got != 99 {
		t.Fatalf("canonical name: got %d", got)
	}
}

// Main refuses to start while any HIVE_RELAY_* or LIGUS_RELAY_* variable is
// set, naming the new name, so a forgotten secret can't silently turn push or
// the tunnel off. The values are never echoed.
func TestRemovedEnvError(t *testing.T) {
	for _, tc := range []struct {
		environ []string
		want    string
	}{
		{[]string{"HIVE_RELAY_TUNNEL=open"}, "HIVE_RELAY_TUNNEL -> LANGSTROTH_RELAY_TUNNEL"},
		{[]string{"HIVE_RELAY_APNS_KEY=PEMSECRET"}, "HIVE_RELAY_APNS_KEY -> LANGSTROTH_RELAY_APNS_KEY"},
		{[]string{"LIGUS_RELAY_APNS_TOPIC=com.example"}, "LIGUS_RELAY_APNS_TOPIC -> LANGSTROTH_RELAY_APNS_TOPIC"},
		{[]string{"HIVE_RELAY_ADMIN_LOGINS="}, "HIVE_RELAY_ADMIN_LOGINS"},
		{[]string{"HIVE_RELAY_URL=http://x"}, "HIVE_RELAY_URL"},
	} {
		err := removedEnvError(append([]string{"PORT=1", "LANGSTROTH_RELAY_ADDR=x"}, tc.environ...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: want an error naming %q, got %v", tc.environ, tc.want, err)
		}
		if strings.Contains(err.Error(), "PEMSECRET") || strings.Contains(err.Error(), "com.example") {
			t.Fatalf("error echoes a value: %v", err)
		}
	}
	if err := removedEnvError([]string{"LANGSTROTH_RELAY_TUNNEL=open", "DATABASE_URL=x", "LIGUS_RELAY_URL=http://client"}); err != nil {
		t.Fatalf("canonical names and the client's LIGUS_RELAY_URL: %v", err)
	}
}

func TestResolveSettingFiles(t *testing.T) {
	files := map[string]string{
		"/run/db":                           "postgres://from-file",
		"/run/token":                        "tok",
		"/s/LANGSTROTH_RELAY_METRICS_TOKEN": "from-dir",
		"/s/DATABASE_URL":                   "postgres://from-dir",
		"/s/LANGSTROTH_RELAY_APNS_KEY":      "pem-from-dir",
		"/s/LIGUS_RELAY_ACCESS_TOKENS":      "former-name",
	}
	read := func(p string) (string, error) {
		if v, ok := files[p]; ok {
			return v, nil
		}
		return "", fmt.Errorf("open %s: %w", p, fs.ErrNotExist)
	}
	dir := map[string]string{"LANGSTROTH_RELAY_SECRETS_DIR": "/s"}
	cases := []struct {
		name string
		env  map[string]string
		key  string
		want string
	}{
		{"env wins over file", map[string]string{"DATABASE_URL": "env", "DATABASE_URL_FILE": "/run/db"}, "DATABASE_URL", "env"},
		{"unprefixed _FILE", map[string]string{"DATABASE_URL_FILE": "/run/db"}, "DATABASE_URL", "postgres://from-file"},
		{"canonical _FILE", map[string]string{"LANGSTROTH_RELAY_METRICS_TOKEN_FILE": "/run/token"}, "LANGSTROTH_RELAY_METRICS_TOKEN", "tok"},
		{"former _FILE ignored", map[string]string{"LIGUS_RELAY_METRICS_TOKEN_FILE": "/run/token", "HIVE_RELAY_METRICS_TOKEN_FILE": "/run/token"}, "LANGSTROTH_RELAY_METRICS_TOKEN", ""},
		{"_FILE wins over dir", map[string]string{"LANGSTROTH_RELAY_METRICS_TOKEN_FILE": "/run/token", "LANGSTROTH_RELAY_SECRETS_DIR": "/s"}, "LANGSTROTH_RELAY_METRICS_TOKEN", "tok"},
		{"dir", dir, "LANGSTROTH_RELAY_METRICS_TOKEN", "from-dir"},
		{"former dir env ignored", map[string]string{"LIGUS_RELAY_SECRETS_DIR": "/s"}, "LANGSTROTH_RELAY_METRICS_TOKEN", ""},
		{"former file name in dir ignored", dir, "LANGSTROTH_RELAY_ACCESS_TOKENS", ""},
		{"dir for unprefixed", dir, "DATABASE_URL", "postgres://from-dir"},
		{"missing file in dir", dir, "LANGSTROTH_RELAY_ADDR", ""},
		{"unreadable _FILE is empty", map[string]string{"DATABASE_URL_FILE": "/nope"}, "DATABASE_URL", ""},
		{"_FILE names never recurse", dir, "LANGSTROTH_RELAY_APNS_KEY_FILE", ""},
		{"APNS_KEY skips its own _FILE", map[string]string{"LANGSTROTH_RELAY_APNS_KEY_FILE": "/run/token"}, "LANGSTROTH_RELAY_APNS_KEY", ""},
		{"APNS_KEY still reads the dir", dir, "LANGSTROTH_RELAY_APNS_KEY", "pem-from-dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveSetting(tc.key, func(k string) string { return tc.env[k] }, read, func(string, string, ...any) {})
			if got != tc.want {
				t.Fatalf("resolveSetting(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestGetenvReadsRealFileAndTrims(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LANGSTROTH_RELAY_FILE_TEST_SETTING"), []byte("v1\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANGSTROTH_RELAY_SECRETS_DIR", dir)
	if got := getenv("LANGSTROTH_RELAY_FILE_TEST_SETTING"); got != "v1" {
		t.Fatalf("got %q", got)
	}
}

// A secrets directory holding a file under a removed name stops the relay
// (the file would otherwise be ignored).
func TestCheckSecretFilesRefusesRemovedNames(t *testing.T) {
	dir := t.TempDir()
	write := func(n, v string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, n), []byte(v), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	lookup := func(k string) string {
		if k == "LANGSTROTH_RELAY_SECRETS_DIR" {
			return dir
		}
		return ""
	}
	write("LANGSTROTH_RELAY_ACCESS_TOKENS", "a\n")
	if err := checkSecretFiles(lookup, nil); err != nil {
		t.Fatalf("canonical names: %v", err)
	}
	write("LIGUS_RELAY_METRICS_TOKEN", "m")
	err := checkSecretFiles(lookup, nil)
	if err == nil || !strings.Contains(err.Error(), "LIGUS_RELAY_METRICS_TOKEN -> LANGSTROTH_RELAY_METRICS_TOKEN") {
		t.Fatalf("a LIGUS_RELAY_* file must stop the relay, got %v", err)
	}
}
