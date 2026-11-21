package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Every 429 and 507 carries Retry-After and a JSON body with a stable code
// (docs/reference.md, "Refusals"), so a client can back off and tell a full room from a
// busy relay.

func wantRefusal(t *testing.T, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status %d (%s), want %d", resp.StatusCode, body, status)
	}
	ra, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || ra < 1 {
		t.Fatalf("%s: Retry-After %q", code, resp.Header.Get("Retry-After"))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s: Content-Type %q", code, ct)
	}
	var b refusalBody
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("%s: body is not JSON: %s", code, body)
	}
	if b.Error != code || b.Message == "" || b.RetryAfter != int64(ra) {
		t.Fatalf("body %+v, want error=%q retryAfter=%d", b, code, ra)
	}
}

func send(t *testing.T, method, url, ip string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, url, rd)
	if ip != "" {
		r.Header.Set("X-Forwarded-For", ip)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestRefusalsCarryRetryAfterAndCode(t *testing.T) {
	t.Run("room_bytes", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_ROOM_MAX_BYTES": "16"})
		send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", "0123456789")
		resp, b := send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", "9876543210")
		wantRefusal(t, resp, b, http.StatusInsufficientStorage, "room_bytes")
	})
	t.Run("room_envelopes", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_ROOM_MAX_ENVELOPES": "1"})
		send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", 1)
		resp, b := send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", 2)
		wantRefusal(t, resp, b, http.StatusInsufficientStorage, "room_envelopes")
	})
	t.Run("store_bytes", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_MAX_STORE_BYTES": "1100"})
		send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", 1)
		resp, b := send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", strings.Repeat("x", 200))
		wantRefusal(t, resp, b, http.StatusInsufficientStorage, "store_bytes")
	})
	t.Run("keyring", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_MAX_KEYRING_PER_WS": "1"})
		send(t, "POST", ts.URL+"/v1/workspaces/w/keyring", "", map[string]int{"v": 1})
		resp, b := send(t, "POST", ts.URL+"/v1/workspaces/w/keyring", "", map[string]int{"v": 2})
		wantRefusal(t, resp, b, http.StatusInsufficientStorage, "keyring")
	})
	t.Run("client_rooms", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_MAX_ROOMS_PER_CLIENT": "1"})
		send(t, "POST", ts.URL+"/v1/workspaces/a/envelopes", "", 1)
		resp, b := send(t, "POST", ts.URL+"/v1/workspaces/b/envelopes", "", 1)
		wantRefusal(t, resp, b, http.StatusTooManyRequests, "client_rooms")
	})
	t.Run("ip_rate", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_IP_RATE": "0.001", "LANGSTROTH_RELAY_IP_BURST": "1"})
		send(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil)
		resp, b := send(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil)
		wantRefusal(t, resp, b, http.StatusTooManyRequests, "ip_rate")
	})
	t.Run("room_rate", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_ROOM_RATE": "0.001", "LANGSTROTH_RELAY_ROOM_BURST": "1"})
		send(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil)
		resp, b := send(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil)
		wantRefusal(t, resp, b, http.StatusTooManyRequests, "room_rate")
	})
	t.Run("write_rate", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_PUSH_RATE": "0.001", "LANGSTROTH_RELAY_PUSH_BURST": "1"})
		send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", 1)
		resp, b := send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", 2)
		wantRefusal(t, resp, b, http.StatusTooManyRequests, "write_rate")
	})
	t.Run("read_rate", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_READ_RATE": "0.001", "LANGSTROTH_RELAY_READ_BURST": "1"})
		send(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil)
		resp, b := send(t, "GET", ts.URL+"/v1/workspaces/w/envelopes", "", nil)
		wantRefusal(t, resp, b, http.StatusTooManyRequests, "read_rate")
	})
	t.Run("room_writer_rate", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_WS_WRITER_RATE": "0.001", "LANGSTROTH_RELAY_WS_WRITER_BURST": "1"})
		send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", 1)
		resp, b := send(t, "POST", ts.URL+"/v1/workspaces/w/envelopes", "", 2)
		wantRefusal(t, resp, b, http.StatusTooManyRequests, "room_writer_rate")
	})
	t.Run("contacts_full", func(t *testing.T) {
		ts := limitServer(t, map[string]string{"LANGSTROTH_RELAY_MAX_CONTACTS": "1"})
		for i, want := range []int{200, 507} {
			cid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, cidRawBytes))
			key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, writeKeyRawBytes))
			resp, b := send(t, "PUT", ts.URL+"/v1/contacts/"+cid, "", map[string]any{"record": map[string]int{"n": i}, "writeKey": key})
			if want == 200 {
				if resp.StatusCode != 200 {
					t.Fatalf("first contact: %d %s", resp.StatusCode, b)
				}
				continue
			}
			wantRefusal(t, resp, b, http.StatusInsufficientStorage, "contacts_full")
		}
	})
}
