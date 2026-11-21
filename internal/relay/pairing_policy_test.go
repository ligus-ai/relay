package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testFriendCode is a current-client friend code: "hive_" + base64url(32-byte
// public key), what Ligus 2.0's p2p_share_code publishes.
var testFriendCode = "hive_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))

func createPair(t *testing.T, url string, payload string) (int, string) {
	t.Helper()
	resp, body := do(t, "POST", url+"/v1/pair", "", map[string]any{"payload": payload})
	var pr struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &pr)
	return resp.StatusCode, pr.Code
}

// Old clients brokered the hivews1: workspace invite, which carries the E2EE
// workspace key in cleartext, through /v1/pair. The relay refuses that format
// (and its renamed spelling) outright.
func TestPairingRefusesCleartextWorkspaceInvites(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()
	invite := "hivews1:" + base64.RawURLEncoding.EncodeToString([]byte(`{"relay":"https://r","room":"w","key":"AAAA"}`))
	for _, p := range []string{
		invite,
		"  " + invite + "\n",
		"ligusws1:" + strings.TrimPrefix(invite, "hivews1:"),
		"HIVEWS1:" + strings.TrimPrefix(invite, "hivews1:"),
	} {
		status, code := createPair(t, ts.URL, p)
		if status != http.StatusUnprocessableEntity || code != "" {
			t.Errorf("payload %.20q: status %d code %q, want 422 and no code", p, status, code)
		}
	}
}

// Anything that is neither a public friend code nor a sealed payload is
// refused: the broker stores payloads in cleartext, so it only takes what is
// safe to show the relay operator.
func TestPairingRequiresKnownPayloadForm(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()
	refused := []string{
		"invite-blob",
		`{"relay":"https://r","key":"AAAA"}`,
		"hive_" + base64.RawURLEncoding.EncodeToString(make([]byte, 31)), // wrong key length
		"hive_not*base64",
		"hivepeer1:xyz",
		"hivepeer1:" + strings.Repeat("ab", 31),
		"sealed1:",
		"sealed1:" + base64.RawURLEncoding.EncodeToString(make([]byte, 8)), // too short to be sealed
		"sealed1:@@@@",
	}
	for _, p := range refused {
		if status, _ := createPair(t, ts.URL, p); status != http.StatusUnprocessableEntity {
			t.Errorf("payload %q: status %d, want 422", p, status)
		}
	}
	accepted := []string{
		testFriendCode,
		"hivepeer1:" + strings.Repeat("ab", 32),
		"sealed1:" + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	}
	for _, p := range accepted {
		if status, code := createPair(t, ts.URL, p); status != http.StatusOK || code == "" {
			t.Errorf("payload %q: status %d code %q, want 200 with a code", p, status, code)
		}
	}
}

// A pairing code is single-use: the first successful resolve consumes it.
func TestPairingCodeIsSingleUse(t *testing.T) {
	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()
	status, code := createPair(t, ts.URL, testFriendCode)
	if status != 200 || code == "" {
		t.Fatalf("create: %d %q", status, code)
	}
	resp, body := do(t, "GET", ts.URL+"/v1/pair/"+code, "", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), testFriendCode) {
		t.Fatalf("first resolve: %d %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, "GET", ts.URL+"/v1/pair/"+code, "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second resolve of a consumed code: %d, want 404", resp.StatusCode)
	}
}

// The TTL still applies to an unresolved code.
func TestPairingCodeExpires(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	srv.pairings["ABCDEF"] = pairing{payload: testFriendCode, expiresAt: time.Now().Add(-time.Second)}
	r := httptest.NewRequest("GET", "/v1/pair/ABCDEF", nil)
	r.SetPathValue("code", "ABCDEF")
	w := httptest.NewRecorder()
	srv.resolvePairing(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expired code: %d, want 404", w.Code)
	}
}
