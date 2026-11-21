package langstrothauth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/langstroth-ai/langstroth-relay/internal/relay"
)

// credentialName is the systemd credential (LoadCredential=) that holds the
// issuer seed when no file or env var is configured.
const credentialName = "langstroth-auth-signing-key"

// formerCredentialName is the credential's name before the Langstroth rename,
// still read when the new one is absent.
const formerCredentialName = "ligus-auth-signing-key"

// LoadSigningKey loads the issuer's Ed25519 key, most explicit first:
//
//  1. the configured signing_key_file (or LANGSTROTH_AUTH_SIGNING_KEY_FILE);
//  2. $CREDENTIALS_DIRECTORY/langstroth-auth-signing-key (systemd
//     credentials; the former name ligus-auth-signing-key is read too);
//  3. LANGSTROTH_AUTH_SIGNING_KEY (hex seed; discouraged: env leaks into /proc and
//     crash dumps).
//
// The file holds the 64-hex-char seed that `langstroth-auth keygen` writes. The
// key is never logged or printed; errors name only the source.
func LoadSigningKey(file string) (ed25519.PrivateKey, string, error) {
	if file == "" {
		file = authGetenv("LANGSTROTH_AUTH_SIGNING_KEY_FILE")
	}
	if file == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			for _, n := range []string{credentialName, formerCredentialName} {
				p := filepath.Join(dir, n)
				if _, err := os.Stat(p); err == nil {
					file = p
					break
				}
			}
		}
	}
	if file != "" {
		v, err := readSecret(file, "")
		if err != nil {
			return nil, "", fmt.Errorf("signing key: %w", err)
		}
		k, ok := relay.ParseSigningKey(v)
		if !ok {
			return nil, "", errors.New("signing key file does not hold a 64-hex-char Ed25519 seed")
		}
		return k, "file", nil
	}
	if v := strings.TrimSpace(authGetenv("LANGSTROTH_AUTH_SIGNING_KEY")); v != "" {
		k, ok := relay.ParseSigningKey(v)
		if !ok {
			return nil, "", errors.New("LANGSTROTH_AUTH_SIGNING_KEY is not a 64-hex-char Ed25519 seed")
		}
		return k, "env", nil
	}
	return nil, "", errors.New("no signing key: set signing_key_file, LANGSTROTH_AUTH_SIGNING_KEY_FILE, a systemd credential named langstroth-auth-signing-key, or LANGSTROTH_AUTH_SIGNING_KEY")
}

// WriteNewSigningKey creates a fresh issuer seed in path (mode 0600, refusing
// to overwrite) and returns the public key as hex. The seed is never printed.
func WriteNewSigningKey(path string) (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey)), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// randBytes returns n bytes from the OS CSPRNG.
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("langstroth-auth: random source failed: " + err.Error())
	}
	return b
}

// randToken returns n random bytes, base64url-encoded without padding.
func randToken(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }

// hashID shortens an identifier for the audit log: HMAC-SHA256 under a
// process salt, 16 hex chars. Correlatable within one process lifetime, not
// reversible by dictionary.
func hashID(salt []byte, v string) string {
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// subjectHash is the "uid" claim: SHA-256 over the IdP issuer and subject,
// 32 hex chars. It identifies the upstream account without carrying it.
func subjectHash(issuer, sub string) string {
	h := sha256.Sum256([]byte(issuer + "\x00" + sub))
	return hex.EncodeToString(h[:16])
}
