package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pairFrom(t *testing.T, h http.Handler, addr, payload string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"payload": payload})
	req := httptest.NewRequest(http.MethodPost, "/v1/pair", strings.NewReader(string(b)))
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func peerCode() string { return "hive_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }

// One client (one address) can't take every live pairing code: on a public
// relay that let a single address answer 503 to everyone's pairing for the
// codes' lifetime.
func TestPairingPerClientCap(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_PAIRINGS_PER_CLIENT", "3")
	h := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}}).Handler()
	for i := 0; i < 3; i++ {
		if rec := pairFrom(t, h, "203.0.113.7:1000", peerCode()); rec.Code != http.StatusOK {
			t.Fatalf("pairing %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := pairFrom(t, h, "203.0.113.7:1001", peerCode())
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("4th code from one client: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	var body refusalBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != refPairCodes {
		t.Fatalf("refusal body %s (%v)", rec.Body, err)
	}
	if rec := pairFrom(t, h, "198.51.100.9:1000", peerCode()); rec.Code != http.StatusOK {
		t.Fatalf("another client: %d %s", rec.Code, rec.Body)
	}
	// IPv6: a client is its /64, and one /48 holds 65536 of them; together
	// they get pairCodesSlash48Factor times the per-client cap.
	for i := 0; i < 3*pairCodesSlash48Factor; i++ {
		if rec := pairFrom(t, h, fmt.Sprintf("[2001:db8:1:%x::1]:1", i), peerCode()); rec.Code != http.StatusOK {
			t.Fatalf("/64 %d of one /48: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := pairFrom(t, h, "[2001:db8:1:ffff::1]:1", peerCode()); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("past the /48 cap: %d %s", rec.Code, rec.Body)
	}
	if rec := pairFrom(t, h, "[2001:db8:2::1]:1", peerCode()); rec.Code != http.StatusOK {
		t.Fatalf("another /48: %d %s", rec.Code, rec.Body)
	}
}

// Live pairing payloads are held in memory: their total size is bounded, so
// a flood of large payloads can't run a small machine out of memory.
func TestPairingBytesCap(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_PAIRINGS_PER_CLIENT", "0")
	t.Setenv("LANGSTROTH_RELAY_MAX_PAIRING_BYTES", "20000")
	h := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}}).Handler()
	big := sealedPairPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 6000)) // 8008 bytes
	for i := 0; i < 2; i++ {
		if rec := pairFrom(t, h, "203.0.113.7:1000", big); rec.Code != http.StatusOK {
			t.Fatalf("pairing %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := pairFrom(t, h, "203.0.113.7:1000", big); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("past the byte cap: %d %s", rec.Code, rec.Body)
	}
	if rec := pairFrom(t, h, "203.0.113.7:1000", peerCode()); rec.Code != http.StatusOK {
		t.Fatalf("a small code still fits: %d %s", rec.Code, rec.Body)
	}
}

func TestPairingDefaultsBoundMemory(t *testing.T) {
	s := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	if s.maxPairingBytes <= 0 || s.maxPairingBytes > 64<<20 {
		t.Fatalf("default live pairing bytes %d: must be bounded well under a 512 MB machine", s.maxPairingBytes)
	}
	if s.maxPairingsPerClient <= 0 || s.maxPairingsPerClient > 100 {
		t.Fatalf("default per-client live pairings %d", s.maxPairingsPerClient)
	}
}
