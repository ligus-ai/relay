package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getBody(t *testing.T, h http.Handler, path string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "192.0.2.1:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

// F-08: GET keyring / candidates / presence returned every retained row in one
// response. With up to 2 000 keyring rows and 1 000 device blobs per workspace,
// each up to the 4 MiB body cap, one GET made the relay load and encode up to
// 8 GiB (Postgres reads every row), so a writer could OOM the relay with a few
// cheap reads. Responses are now bounded by LANGSTROTH_RELAY_MAX_LIST_BYTES (keyring
// keeps the newest rows).
func checkListCap(t *testing.T, store Store) {
	t.Setenv("LANGSTROTH_RELAY_MAX_LIST_BYTES", "50000")
	srv := New(Options{Store: store, Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()
	for i := 0; i < 10; i++ {
		row := fmt.Sprintf(`{"n":%d,"pad":%q}`, i, strings.Repeat("k", 20000))
		if code := postRaw(t, h, "/v1/workspaces/wl/keyring", row, fmt.Sprintf("192.0.2.%d:1", i+1)); code != 200 {
			t.Fatalf("keyring post: %d", code)
		}
		dev := fmt.Sprintf(`{"device_id":"d%d","data":%q}`, i, strings.Repeat("c", 20000))
		for _, rt := range []string{"candidates", "presence"} {
			if code := postRaw(t, h, "/v1/workspaces/wl/"+rt, dev, fmt.Sprintf("192.0.2.%d:1", i+1)); code != 200 {
				t.Fatalf("%s post: %d", rt, code)
			}
		}
	}
	code, body := getBody(t, h, "/v1/workspaces/wl/keyring")
	if code != 200 || len(body) > 70000 {
		t.Fatalf("keyring response %d bytes (status %d), want it bounded", len(body), code)
	}
	var rows []struct{ N int }
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) == 0 || rows[len(rows)-1].N != 9 {
		t.Fatalf("keyring must keep the newest rows in order: %v %+v", err, rows)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].N != rows[i-1].N+1 {
			t.Fatalf("keyring rows out of order: %+v", rows)
		}
	}
	for _, rt := range []string{"candidates", "presence"} {
		code, body := getBody(t, h, "/v1/workspaces/wl/"+rt)
		var m map[string]json.RawMessage
		if code != 200 || len(body) > 70000 || json.Unmarshal(body, &m) != nil || len(m) == 0 {
			t.Fatalf("%s response %d bytes, %d entries (status %d), want bounded and non-empty", rt, len(body), len(m), code)
		}
	}
}

func TestListResponsesBoundedMemory(t *testing.T) { checkListCap(t, newMemoryStore()) }

func TestPG_ListResponsesBounded(t *testing.T) { checkListCap(t, pgStore(t)) }

// Small rows are never dropped under the default cap.

// Small rows are never dropped under the default cap.
func TestListCapDefault(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_LIST_BYTES", "")
	if got := listCapFromEnv(); got != defaultMaxListBytes {
		t.Fatalf("default list cap %d", got)
	}
}

func TestNewestWithin(t *testing.T) {
	rows := []json.RawMessage{[]byte("aaaa"), []byte("bb"), []byte("cc"), []byte("dddddddd")}
	if got := newestWithin(rows, 3); len(got) != 1 || string(got[0]) != "dddddddd" {
		t.Fatalf("an oversized newest row is still returned alone: %q", got)
	}
	if got := newestWithin(rows, 12); len(got) != 3 || string(got[0]) != "bb" {
		t.Fatalf("newest rows within the cap, in order: %q", got)
	}
	if got := newestWithin(rows, 0); len(got) != 4 {
		t.Fatalf("0 = unbounded: %q", got)
	}
}
