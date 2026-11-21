package relay

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A client may hold only so many ordinary requests open at once. Each can
// hold several MiB (a 4 MiB body being decoded, a page of envelopes being
// written to a reader that reads slowly), so without a per-client bound
// one address holding hundreds open could run a small machine out of memory.
func TestPerClientInflightCap(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_INFLIGHT_PER_CLIENT", "2")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	// Two requests whose bodies never finish arriving.
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = fmt.Fprintf(c, "POST /v1/workspaces/w%d/envelopes HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{", i)
	}
	time.Sleep(100 * time.Millisecond)
	resp, b := blobHTTP(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("third request in flight (cap 2): %d %s", resp.StatusCode, b)
	}
	var rb refusalBody
	if err := json.Unmarshal(b, &rb); err != nil || rb.Error != refClientInflight {
		t.Fatalf("refusal %s", b)
	}
	// Health and the status page are never refused.
	if resp, _ := blobHTTP(t, "GET", ts.URL+"/v1/health", "", nil); resp.StatusCode != 200 {
		t.Fatalf("health: %d", resp.StatusCode)
	}
}

// Off by default, like the other community limits.
func TestPerClientInflightOffByDefault(t *testing.T) {
	s := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	if s.lim.inflight != nil {
		t.Fatal("per-client in-flight cap must be off unless configured")
	}
}
