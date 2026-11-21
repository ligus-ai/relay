package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stalledDownload sends a blob GET and never reads the answer.
func stalledDownload(t *testing.T, base, path, token string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4 << 10)
	}
	_, _ = fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n\r\n", path, token)
	return c
}

// A download holds the whole blob (up to 25 MiB) in memory while it is
// written, and nothing bounded how many ran at once or how long a client
// that stops reading could keep one: a few such clients ran a 512 MB
// machine out of memory. Downloads now take an in-flight slot (relay-wide
// and per downloader) and are cut off when the reader stalls.
func TestHTTPBlobDownloadsInFlightCappedAndStallsCutOff(t *testing.T) {
	idle, grace := blobIdleTimeout, blobRateGrace
	blobIdleTimeout, blobRateGrace = 300*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { blobIdleTimeout, blobRateGrace = idle, grace })
	t.Setenv("LANGSTROTH_RELAY_BLOB_DOWNLOAD_INFLIGHT", "1")
	t.Setenv("LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_INFLIGHT", "1")
	sk := testKey(t)
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	tk := func(sub string) string {
		return issueToken(sk, TokenClaims{Sub: sub, Exp: uint64(time.Now().Add(time.Hour).Unix())})
	}
	alice, bob := tk("alice"), tk("bob")
	seedHTTP(t, ts.URL, "w", alice)
	resp, b := blobHTTP(t, "POST", ts.URL+"/v1/workspaces/w/blobs", alice, make([]byte, 16<<20))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %s", resp.StatusCode, b)
	}
	var br blobResp
	_ = json.Unmarshal(b, &br)
	path := "/v1/workspaces/w/blobs/" + br.ID

	_ = stalledDownload(t, ts.URL, path, alice)
	time.Sleep(100 * time.Millisecond)
	resp, b = blobHTTP(t, "GET", ts.URL+path, bob, nil)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(b), limBlobInflight) || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("a second download while one is in flight (cap 1): %d %.200s", resp.StatusCode, b)
	}
	// The stalled reader is cut off and gives its slot back.
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, b = blobHTTP(t, "GET", ts.URL+path, bob, nil)
		if resp.StatusCode == http.StatusOK && len(b) == 16<<20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a stalled download still holds the slot: %d", resp.StatusCode)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
