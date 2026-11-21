package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// resolveMiss sends one pairing-code guess that cannot match and returns the
// status, optionally adding one request header.
func resolveMiss(t *testing.T, h http.Handler, remote, header, value string) int {
	t.Helper()
	r := httptest.NewRequest("GET", "/v1/pair/ZZZZZZ", nil)
	r.RemoteAddr = remote
	if header != "" {
		r.Header.Set(header, value)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// F-01: off Fly, a client could set Fly-Client-IP itself and get a fresh
// rate-limit bucket per request, so the pairing-code guess cap (10 misses per
// minute) never applied. Off Fly the header must be ignored.
func TestClientIPIgnoresSpoofedFlyHeader(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("LANGSTROTH_RELAY_TRUSTED_PROXIES", "")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()
	blocked := false
	for i := 0; i < maxResolveFailures+5; i++ {
		code := resolveMiss(t, h, "203.0.113.7:4000", "Fly-Client-IP", fmt.Sprintf("198.51.100.%d", i+1))
		if code == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("rotating a client-supplied Fly-Client-IP evaded the pairing guess limit")
	}
}

// On Fly (FLY_APP_NAME set by the platform) the edge overwrites Fly-Client-IP,
// so it stays the client address there.
func TestClientIPFlyHeaderTrustedOnFly(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "relay-test")
	t.Setenv("LANGSTROTH_RELAY_TRUSTED_PROXIES", "")
	p := clientIPPolicyFromEnv()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.16.0.2:1234"
	r.Header.Set("Fly-Client-IP", "198.51.100.9")
	if got := p.ip(r); got != "198.51.100.9" {
		t.Fatalf("on Fly want the Fly-Client-IP, got %q", got)
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("LANGSTROTH_RELAY_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1")
	t.Setenv("LANGSTROTH_RELAY_CLIENT_IP_HEADER", "")
	p := clientIPPolicyFromEnv()
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"untrusted peer: header ignored", "203.0.113.5:1", []string{"198.51.100.1"}, "203.0.113.5"},
		{"trusted peer: client from XFF", "10.1.2.3:1", []string{"198.51.100.1"}, "198.51.100.1"},
		{"spoofed leftmost entry ignored", "10.1.2.3:1", []string{"6.6.6.6, 198.51.100.1"}, "198.51.100.1"},
		{"trusted hops skipped", "10.1.2.3:1", []string{"198.51.100.1, 10.9.9.9", "192.0.2.1"}, "198.51.100.1"},
		{"garbage entry stops the walk", "10.1.2.3:1", []string{"198.51.100.1, not-an-ip"}, "10.1.2.3"},
		{"no header: peer", "10.1.2.3:1", nil, "10.1.2.3"},
		{"ipv4-mapped peer", "[::ffff:10.1.2.3]:1", []string{"198.51.100.1"}, "198.51.100.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := p.ip(r); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestClientIPCustomHeader(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("LANGSTROTH_RELAY_TRUSTED_PROXIES", "10.0.0.0/8")
	t.Setenv("LANGSTROTH_RELAY_CLIENT_IP_HEADER", "X-Real-IP")
	p := clientIPPolicyFromEnv()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	r.Header.Set("X-Real-IP", "198.51.100.4")
	if got := p.ip(r); got != "198.51.100.4" {
		t.Fatalf("got %q", got)
	}
	r.Header.Set("X-Real-IP", "junk")
	if got := p.ip(r); got != "10.0.0.1" {
		t.Fatalf("junk header must fall back to the peer, got %q", got)
	}
}

// Behind a trusted ingress, distinct clients get distinct buckets: one
// client's failed guesses don't lock out everyone else.
func TestTrustedProxySeparatesClients(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("LANGSTROTH_RELAY_TRUSTED_PROXIES", "10.0.0.0/8")
	t.Setenv("LANGSTROTH_RELAY_CLIENT_IP_HEADER", "")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()
	for i := 0; i < maxResolveFailures; i++ {
		resolveMiss(t, h, "10.0.0.9:1", "X-Forwarded-For", "198.51.100.66")
	}
	if code := resolveMiss(t, h, "10.0.0.9:1", "X-Forwarded-For", "198.51.100.66"); code != http.StatusTooManyRequests {
		t.Fatalf("the guessing client should be blocked, got %d", code)
	}
	if code := resolveMiss(t, h, "10.0.0.9:1", "X-Forwarded-For", "198.51.100.67"); code != http.StatusNotFound {
		t.Fatalf("another client behind the same ingress must not be blocked, got %d", code)
	}
}

// F-02: an IPv6 client normally holds a whole /64 and can pick a fresh source
// address per request; keying limits on the full address gave it a fresh
// bucket each time.
func TestIPv6RotationWithinA64SharesABucket(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("LANGSTROTH_RELAY_TRUSTED_PROXIES", "")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()
	blocked := false
	for i := 0; i < maxResolveFailures+5; i++ {
		remote := fmt.Sprintf("[2001:db8:1:2::%x]:4000", i+1)
		if resolveMiss(t, h, remote, "", "") == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("rotating addresses inside one IPv6 /64 evaded the pairing guess limit")
	}
	// A different /64 is a different client.
	if code := resolveMiss(t, h, "[2001:db8:1:3::1]:4000", "", ""); code != http.StatusNotFound {
		t.Fatalf("another /64 must not be blocked, got %d", code)
	}
}
