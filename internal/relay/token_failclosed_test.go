package relay

import "testing"

// F-12: a set but unparseable LANGSTROTH_RELAY_TOKEN_PUBKEY fell through to the
// static allowlist or, with none, to the open policy: a typo in the issuer
// key silently ran the relay ungated. It now denies every token.
func TestMalformedTokenPubkeyFailsClosed(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", "not-a-key")
	t.Setenv("LANGSTROTH_RELAY_ACCESS_TOKENS", "")
	p := EntitlementFromEnv()
	if _, ok := p.Allow("", nowUnix()); ok {
		t.Fatal("malformed issuer key admitted an anonymous caller (fail open)")
	}
	if _, ok := p.Allow("anything", nowUnix()); ok {
		t.Fatal("malformed issuer key admitted a token")
	}
	if err := entitlementConfigError(); err == nil {
		t.Fatal("startup check must report the malformed key")
	}
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", "")
	if err := entitlementConfigError(); err != nil {
		t.Fatalf("unset key is fine: %v", err)
	}
}
