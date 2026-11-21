package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// tokenPrefix is the first segment of the compact wire format:
//
//	hrt1.<b64url(claims_json)>.<b64url(ed25519_sig)>
//
// The signature covers the ASCII bytes of "hrt1.<b64url(claims_json)>" (the
// first two parts joined by "."), so claims can't be altered without the key.
const tokenPrefix = "hrt1"

// TokenClaims are carried by a signed access token. Forward-compatible:
// unknown fields are ignored on decode, and the relay ignores any capability it
// does not yet enforce. Field names match the Rust issuer's serde output.
type TokenClaims struct {
	Sub           string   `json:"sub"`
	Plan          string   `json:"plan"`
	Exp           uint64   `json:"exp"`
	MaxMembers    *uint32  `json:"max_members"`
	RetentionDays *uint32  `json:"retention_days"`
	Turn          bool     `json:"turn"`
	Caps          []string `json:"caps"`
	// Workspaces optionally confines the token to these workspace ids ("*" =
	// any). Enforced only when LANGSTROTH_RELAY_WORKSPACE_SCOPE is claims or strict
	// (scope.go); omitted from the JSON when empty, so tokens minted without it
	// are byte-identical to before.
	Workspaces []string `json:"workspaces,omitempty"`
	// Tid, Uid and Did are set by langstroth-auth (cmd/langstroth-auth): the tenant, a
	// hash of the upstream IdP subject, and the device id whose key proved
	// possession at mint time. All are omitted from the JSON when empty, so
	// tokens minted without them are byte-identical to before. The relay
	// enforces only Tid, and only when LANGSTROTH_RELAY_TENANTS is set.
	Tid string `json:"tid,omitempty"`
	Uid string `json:"uid,omitempty"`
	Did string `json:"did,omitempty"`
}

// IsExpired reports whether Exp is set and now-or-past.
func (c TokenClaims) IsExpired(nowUnix int64) bool {
	return c.Exp != 0 && uint64(nowUnix) >= c.Exp
}

// HasCap reports whether the subject holds a named RBAC capability.
func (c TokenClaims) HasCap(cap string) bool {
	for _, x := range c.Caps {
		if x == cap {
			return true
		}
	}
	return false
}

// verifyToken validates a compact hrt1 token against the issuer public key,
// returning the claims iff the signature is valid. Expiry is not checked here
// (kept clock-free); the caller checks IsExpired.
func verifyToken(token string, pub ed25519.PublicKey) (TokenClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return TokenClaims{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return TokenClaims{}, false
	}
	signed := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signed), sig) {
		return TokenClaims{}, false
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return TokenClaims{}, false
	}
	var claims TokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return TokenClaims{}, false
	}
	return claims, true
}

// IssueToken mints a compact hrt1 token with the issuer's Ed25519 key. It is
// the exported form of the issuer used by langstroth-relay issue and langstroth-auth.
func IssueToken(priv ed25519.PrivateKey, claims TokenClaims) string { return issueToken(priv, claims) }

// VerifyToken checks a compact hrt1 token against an issuer public key and
// returns its claims. Expiry is not checked (see TokenClaims.IsExpired).
func VerifyToken(token string, pub ed25519.PublicKey) (TokenClaims, bool) {
	return verifyToken(token, pub)
}

// ParsePubkey parses an Ed25519 public key from hex or base64.
func ParsePubkey(s string) (ed25519.PublicKey, bool) { return parsePubkey(s) }

// ParseSigningKey parses a 64-char hex Ed25519 seed into a private key.
func ParseSigningKey(h string) (ed25519.PrivateKey, bool) { return parseSigningKey(h) }

// parsePubkey parses an Ed25519 public key from hex (64 chars) or base64
// (url-safe or standard, with or without padding).
func parsePubkey(s string) (ed25519.PublicKey, bool) {
	s = strings.TrimSpace(s)
	var raw []byte
	if len(s) == 64 && isHex(s) {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, false
		}
		raw = b
	} else {
		for _, enc := range []*base64.Encoding{
			base64.RawURLEncoding, base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding,
		} {
			if b, err := enc.DecodeString(s); err == nil {
				raw = b
				break
			}
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// entitlementKind selects who may use the relay.
type entitlementKind int

const (
	// entOpen — self-host default: anyone may connect (the URL is not a secret).
	entOpen entitlementKind = iota
	// entTokens — a static allowlist of opaque bearer tokens (coarse on/off gate).
	entTokens
	// entSigned — signed hrt1 tokens verified against the issuer's public key.
	entSigned
	// entDeny — admits nobody (a configured issuer key that doesn't parse).
	entDeny
)

// entitlementConfigError reports an access-gate setting that can't be used,
// so the binary refuses to start instead of serving with a broken gate.
func entitlementConfigError() error {
	if pk := getenv("LANGSTROTH_RELAY_TOKEN_PUBKEY"); pk != "" {
		if _, ok := parsePubkey(pk); !ok {
			return errors.New("LANGSTROTH_RELAY_TOKEN_PUBKEY is set but is not an Ed25519 public key (64 hex chars or base64)")
		}
	}
	if pk := getenv("LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT"); pk != "" {
		if getenv("LANGSTROTH_RELAY_TOKEN_PUBKEY") == "" {
			return errors.New("LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT is set without LANGSTROTH_RELAY_TOKEN_PUBKEY")
		}
		if _, ok := parsePubkey(pk); !ok {
			return errors.New("LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT is set but is not an Ed25519 public key (64 hex chars or base64)")
		}
	}
	if ts := tenantsFromEnv(); ts != nil {
		if getenv("LANGSTROTH_RELAY_TOKEN_PUBKEY") == "" {
			return errors.New("LANGSTROTH_RELAY_TENANTS needs signed tokens: set LANGSTROTH_RELAY_TOKEN_PUBKEY")
		}
		if len(ts) == 0 {
			return errors.New("LANGSTROTH_RELAY_TENANTS is set but lists no tenant id")
		}
		// tid confines which tokens are admitted, not which workspaces they
		// reach: without strict scope one tenant's token would read and write
		// every other tenant's workspaces.
		if workspaceScopeFromEnv() != scopeStrict {
			return errors.New("LANGSTROTH_RELAY_TENANTS needs LANGSTROTH_RELAY_WORKSPACE_SCOPE=strict, or one tenant's tokens reach every workspace")
		}
	}
	return nil
}

// tenantsFromEnv reads LANGSTROTH_RELAY_TENANTS (comma-separated tenant ids). It
// returns nil when the setting is unset (tenant confinement off, the default)
// and an empty non-nil slice when it is set but lists nothing.
func tenantsFromEnv() []string {
	raw, set := lookupRelayEnv("LANGSTROTH_RELAY_TENANTS")
	if !set {
		return nil
	}
	out := []string{}
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// lookupRelayEnv is getenv that also reports whether the setting is present
// (a set-but-blank value counts as set, so it fails closed at startup).
func lookupRelayEnv(name string) (string, bool) {
	if v := getenv(name); v != "" {
		return v, true
	}
	_, ok := os.LookupEnv(name)
	return "", ok
}

// entitlementPolicy decides whether a presented bearer token is admitted.
type entitlementPolicy struct {
	kind entitlementKind
	// tokenHashes holds SHA-256 hex of each allowlisted token (entTokens). Storing
	// and comparing hashes (fixed length, constant-time) instead of the raw tokens
	// avoids the data-dependent, early-exiting string compare of a raw-token map
	// lookup, which could leak a valid token's length/prefix by timing (P3-13).
	tokenHashes []string
	pubkey      ed25519.PublicKey // entSigned
	// nextPubkey is an optional second issuer key (LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT)
	// accepted alongside pubkey while the issuer rotates its signing key.
	nextPubkey ed25519.PublicKey
	// tenants, when non-nil, confines signed tokens to these "tid" claims
	// (LANGSTROTH_RELAY_TENANTS). A token without a tid is refused. Off (nil) by
	// default.
	tenants []string
}

// entitlementFromEnv resolves the policy, most specific first:
//  1. LANGSTROTH_RELAY_TOKEN_PUBKEY (hex/base64 Ed25519) → verify signed tokens;
//  2. LANGSTROTH_RELAY_ACCESS_TOKENS (comma-separated)   → static allowlist;
//  3. otherwise                                    → open (self-host default).
func entitlementFromEnv() entitlementPolicy {
	if pk := getenv("LANGSTROTH_RELAY_TOKEN_PUBKEY"); pk != "" {
		if vk, ok := parsePubkey(pk); ok {
			p := entitlementPolicy{kind: entSigned, pubkey: vk, tenants: tenantsFromEnv()}
			if next := getenv("LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT"); next != "" {
				nk, ok := parsePubkey(next)
				if !ok {
					os.Stderr.WriteString("LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT is set but unparseable; denying every token\n")
					return entitlementPolicy{kind: entDeny}
				}
				p.nextPubkey = nk
			}
			return p
		}
		// Parsing failed: fail closed. Falling through would run the relay on
		// the allowlist or, with none, open: a typo would silently ungate it.
		os.Stderr.WriteString("LANGSTROTH_RELAY_TOKEN_PUBKEY is set but unparseable; denying every token\n")
		return entitlementPolicy{kind: entDeny}
	}
	if v := strings.TrimSpace(getenv("LANGSTROTH_RELAY_ACCESS_TOKENS")); v != "" {
		var hashes []string
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				hashes = append(hashes, sha256hex(t))
			}
		}
		if len(hashes) > 0 {
			return entitlementPolicy{kind: entTokens, tokenHashes: hashes}
		}
	}
	return entitlementPolicy{kind: entOpen}
}

// EntitlementFromEnv is the exported, interface-typed constructor the OSS binary
// and downstream builds use to get the default env-driven verifier.
func EntitlementFromEnv() EntitlementVerifier { return entitlementFromEnv() }

// Allow reports whether a presented bearer token is admitted at nowUnix. The
// returned claims are non-nil only for signed tokens (for claim-based enforcement).
// It satisfies EntitlementVerifier.
func (p entitlementPolicy) Allow(token string, nowUnix int64) (*TokenClaims, bool) {
	switch p.kind {
	case entOpen:
		return nil, true
	case entTokens:
		h := sha256hex(token)
		ok := false
		// Compare against every allowlisted hash with a constant-time compare and
		// no early exit on match, so neither which token matched nor whether an
		// early byte differed is observable by timing (P3-13).
		for _, want := range p.tokenHashes {
			if constantTimeEq(h, want) {
				ok = true
			}
		}
		return nil, ok
	case entSigned:
		claims, ok := verifyToken(token, p.pubkey)
		if !ok && p.nextPubkey != nil {
			claims, ok = verifyToken(token, p.nextPubkey)
		}
		if !ok || claims.IsExpired(nowUnix) {
			return nil, false
		}
		if p.tenants != nil && !tenantAllowed(p.tenants, claims.Tid) {
			return nil, false
		}
		return &claims, true
	default:
		return nil, false
	}
}

// tenantAllowed reports whether tid is one of the configured tenants. An
// empty tid never matches.
func tenantAllowed(tenants []string, tid string) bool {
	if tid == "" {
		return false
	}
	for _, t := range tenants {
		if t == tid {
			return true
		}
	}
	return false
}

// parseSigningKey parses a 64-char-hex Ed25519 seed into a private key.
func parseSigningKey(h string) (ed25519.PrivateKey, bool) {
	h = strings.TrimSpace(h)
	if len(h) != 64 || !isHex(h) {
		return nil, false
	}
	seed, err := hex.DecodeString(h)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(seed), true
}

// issueToken mints a compact hrt1 token (the inverse of verifyToken).
func issueToken(priv ed25519.PrivateKey, claims TokenClaims) string {
	body := tokenPrefix + "." + base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	sig := ed25519.Sign(priv, []byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(sig)
}
