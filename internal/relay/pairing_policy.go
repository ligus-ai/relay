package relay

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Pairing payload policy.
//
// The short-code broker (/v1/pair) stores its payload in cleartext in relay
// memory, where the relay operator can read it. Old clients used it to hand
// over the hivews1: workspace invite, which carries the workspace's E2EE key,
// so the relay operator could read every workspace paired that way. The relay
// now takes only payloads that are safe to show the operator:
//
//   - a public peer friend code: "hive_" + base64url(32-byte public key), or the
//     legacy "hivepeer1:" + 64 hex characters (what Ligus 2.0 clients publish);
//   - a sealed payload: "sealed1:" + base64url(ciphertext), at least
//     minSealedPairBytes long. The relay can't check that the bytes are really
//     encrypted; the prefix is the client's declaration that they are.
//
// Workspace invites (hivews1: / ligusws1:) are refused with a message saying
// so; anything else is refused as unsupported. Both get 422.
const (
	sealedPairPrefix   = "sealed1:"
	minSealedPairBytes = 32 // nonce/ephemeral key + AEAD tag, at the least
	peerKeyBytes       = 32
)

var cleartextInvitePrefixes = []string{"hivews1:", "ligusws1:"}

// pairPayloadError reports why a pairing payload is refused, or "" when it is
// accepted.
func pairPayloadError(payload string) string {
	p := strings.TrimSpace(payload)
	lower := strings.ToLower(p)
	for _, pre := range cleartextInvitePrefixes {
		if strings.HasPrefix(lower, pre) {
			return "workspace invites carry the workspace key and can't be brokered by the relay; share the invite over a channel you trust"
		}
	}
	switch {
	case strings.HasPrefix(p, "hive_"):
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(p, "hive_")); err == nil && len(b) == peerKeyBytes {
			return ""
		}
	case strings.HasPrefix(p, "hivepeer1:"):
		h := strings.TrimPrefix(p, "hivepeer1:")
		if b, err := hex.DecodeString(h); err == nil && len(b) == peerKeyBytes {
			return ""
		}
	case strings.HasPrefix(p, sealedPairPrefix):
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(p, sealedPairPrefix)); err == nil && len(b) >= minSealedPairBytes {
			return ""
		}
	}
	return "unsupported pairing payload: expected a peer friend code or a sealed1: payload"
}
