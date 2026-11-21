package relay

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/langstroth-ai/langstroth-relay/internal/envalias"
)

// Relay settings are named LANGSTROTH_RELAY_*. The names from before the
// Langstroth rename (HIVE_RELAY_*, LIGUS_RELAY_*) are not read, and main
// refuses to start while any of them is set (removedEnvError), so a secret
// left under an old name can't silently turn push, the tunnel or the access
// gate off. Names outside the prefix (PORT, DATABASE_URL, ...) are read as-is.

const envPrefix = "LANGSTROTH_RELAY_"

// removedEnvPrefixes are the prefixes before the Langstroth rename.
var removedEnvPrefixes = []string{"HIVE_RELAY_", "LIGUS_RELAY_"}

// removedEnvExempt are variables of the Ligus client under a removed prefix
// that the relay never read, so an exported client setting in the same shell
// doesn't stop a local relay.
var removedEnvExempt = map[string]bool{"LIGUS_RELAY_URL": true}

// settingSuffix returns the part of name after envPrefix.
func settingSuffix(name string) (string, bool) {
	return strings.CutPrefix(name, envPrefix)
}

// removedEnvError refuses to start while a HIVE_RELAY_* or LIGUS_RELAY_*
// variable is set, naming its LANGSTROTH_RELAY_* replacement (never its
// value).
func removedEnvError(environ []string) error {
	return envalias.Removed(environ, envPrefix, removedEnvPrefixes, removedEnvExempt)
}

var envWarned sync.Map // warning key -> struct{}

// getenv returns the value for a relay setting (LANGSTROTH_RELAY_<X>, or an
// unprefixed name such as DATABASE_URL).
//
// When the variable itself is unset, a setting can come from a file (for
// Kubernetes Secrets mounted as files, so secrets stay out of the process
// environment):
//
//  1. the file named by <NAME>_FILE (LANGSTROTH_RELAY_<X>_FILE;
//     DATABASE_URL_FILE for unprefixed names);
//  2. the file $LANGSTROTH_RELAY_SECRETS_DIR/<NAME>.
//
// The environment wins over a _FILE, which wins over the directory. One
// trailing run of whitespace is trimmed. Names that already end in _FILE are
// never resolved from files themselves, and settings with their own _FILE
// meaning (APNS_KEY, whose APNS_KEY_FILE the relay opens itself) skip step 1.
func getenv(name string) string {
	return resolveSetting(name, os.Getenv, readSecretFile, warnEnvOnce)
}

// secretsDirEnv names the directory of one-file-per-setting secrets.
const secretsDirEnv = envPrefix + "SECRETS_DIR"

// noFileFallback lists settings whose <NAME>_FILE already means something
// else (a path the relay reads itself).
var noFileFallback = map[string]bool{"APNS_KEY": true}

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), " \t\r\n"), nil
}

// resolveSetting is lookup plus the file fallbacks described on getenv.
func resolveSetting(name string, lookup func(string) string, read func(string) (string, error), warn func(key, msg string, args ...any)) string {
	if v := lookup(name); v != "" || strings.HasSuffix(name, "_FILE") {
		return v
	}
	short, _ := settingSuffix(name)
	if !noFileFallback[short] {
		if path := strings.TrimSpace(lookup(name + "_FILE")); path != "" {
			v, err := read(path)
			if err != nil {
				// Never echo the contents; the path is fine to log.
				warn(name+"_FILE", "cannot read setting file", "var", name+"_FILE", "err", err)
				return ""
			}
			return v
		}
	}
	dir := strings.TrimSpace(lookup(secretsDirEnv))
	if dir == "" || short == "SECRETS_DIR" || strings.ContainsAny(name, "/\\") {
		return ""
	}
	v, err := read(filepath.Join(dir, name))
	if err == nil {
		return v
	}
	if !errors.Is(err, fs.ErrNotExist) {
		// Unreadable is not unset: secretFilesConfigError stops the
		// process at startup; this is for a file that changed later.
		warn(name+"@dir", "cannot read setting file", "var", name, "dir", secretsDirEnv, "err", err)
	}
	return ""
}

// secretFilesConfigError refuses to start when a secret file the relay was
// pointed at can't be read or is empty: every <NAME>_FILE among the relay's
// settings (and DATABASE_URL_FILE), and every file in
// LANGSTROTH_RELAY_SECRETS_DIR. getenv treats an unreadable file as unset, and
// for the access gate (LANGSTROTH_RELAY_TOKEN_PUBKEY,
// LANGSTROTH_RELAY_ACCESS_TOKENS) unset means open, for DATABASE_URL the
// in-memory store: a wrong file mode or a typo'd path must stop the relay
// instead. It also refuses a file in the directory named with a removed
// prefix (HIVE_RELAY_*, LIGUS_RELAY_*), which would otherwise be ignored.
func secretFilesConfigError(lookup func(string) string) error {
	var names []string
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok {
			names = append(names, k)
		}
	}
	return checkSecretFiles(lookup, names)
}

func checkSecretFiles(lookup func(string) string, names []string) error {
	seen := map[string]bool{}
	check := func(label, path string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: cannot read %s: %w", label, path, err)
		}
		if strings.TrimSpace(string(b)) == "" {
			return fmt.Errorf("%s: %s is empty", label, path)
		}
		return nil
	}
	for _, k := range names {
		if seen[k] || !strings.HasSuffix(k, "_FILE") {
			continue
		}
		seen[k] = true
		if _, ok := settingSuffix(k); !ok && k != "DATABASE_URL_FILE" {
			continue
		}
		if p := strings.TrimSpace(lookup(k)); p != "" {
			if err := check(k, p); err != nil {
				return err
			}
		}
	}
	dir := strings.TrimSpace(lookup(secretsDirEnv))
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%s: %w", secretsDirEnv, err)
	}
	var files []string
	for _, e := range entries {
		// A mounted Secret's ..data / ..<timestamp> entries.
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			continue
		}
		files = append(files, e.Name())
		if err := check(secretsDirEnv+"/"+e.Name(), p); err != nil {
			return err
		}
	}
	if err := removedEnvError(files); err != nil {
		return fmt.Errorf("%s: %w", secretsDirEnv, err)
	}
	return nil
}

func warnEnvOnce(key, msg string, args ...any) {
	if _, loaded := envWarned.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	slog.Warn(msg, args...)
}
