package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postRaw(t *testing.T, h http.Handler, path, body, remote string) int {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func blob(n int) string { return `"` + strings.Repeat("a", n) + `"` }

// F-06: the memory store had no global byte ceiling. Per-workspace caps
// (50 000 envelopes, 2 000 keyring rows, 1 000 device blobs, each up to the
// 4 MiB body cap) multiply by an unbounded number of workspace ids, so an
// anonymous client on an open relay could grow the heap until the process was
// OOM-killed, and the snapshot then reloaded the same data on restart. With
// LANGSTROTH_RELAY_MAX_STORE_BYTES set, writes past the budget get 507 instead.
func TestMemoryStoreByteBudget(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_STORE_BYTES", "300000")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()
	routes := []string{"envelopes", "keyring"}
	full := false
	for i := 0; i < 20 && !full; i++ {
		for _, rt := range routes {
			code := postRaw(t, h, fmt.Sprintf("/v1/workspaces/w%d/%s", i, rt), blob(20000), fmt.Sprintf("192.0.2.%d:1", i+1))
			if code == http.StatusInsufficientStorage {
				full = true
				break
			}
			if code != http.StatusOK {
				t.Fatalf("%s write %d: %d", rt, i, code)
			}
		}
	}
	if !full {
		t.Fatal("writes past LANGSTROTH_RELAY_MAX_STORE_BYTES were accepted")
	}
	// Device blobs count too, and replacing one with a smaller one frees room.
	dev := func(id string, n int) string { return fmt.Sprintf(`{"device_id":%q,"data":%s}`, id, blob(n)) }
	if code := postRaw(t, h, "/v1/workspaces/wx/presence", dev("d1", 20000), "192.0.2.200:1"); code != http.StatusInsufficientStorage {
		t.Fatalf("presence past the budget: want 507, got %d", code)
	}
}

func TestMemoryStoreBytesAccounting(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_STORE_BYTES", "1000000")
	t.Setenv("LANGSTROTH_RELAY_MAX_DEVICE_BLOBS_PER_WS", "1")
	s := newMemoryStore()
	ctx := t.Context()
	for i := 0; i < 5; i++ {
		if _, err := s.AppendEnvelope(ctx, "w", []byte(blob(100)), fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.PutPresence(ctx, "w", "d1", []byte(blob(50)))
	_ = s.PutPresence(ctx, "w", "d1", []byte(blob(10)))
	_ = s.PutPresence(ctx, "w", "d2", []byte(blob(10))) // evicts d1
	want := int64(wsOverheadBytes+len("w")) + int64(5*(100+2)+(10+2))
	if got := s.storeBytes; got != want {
		t.Fatalf("storeBytes = %d, want %d", got, want)
	}
}

// Off by default: no budget.
func TestMemoryStoreBudgetOffByDefault(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_STORE_BYTES", "")
	if s := newMemoryStore(); s.maxStoreBytes != 0 {
		t.Fatalf("default budget = %d, want 0 (off)", s.maxStoreBytes)
	}
}

// F-06b: each new workspace costs heap (its maps and slices) that the byte
// budget didn't count, so tiny writes to fresh workspace ids still grew the
// heap without bound under LANGSTROTH_RELAY_MAX_STORE_BYTES.
func TestMemoryStoreBudgetCountsWorkspaces(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_STORE_BYTES", "20000")
	s := newMemoryStore()
	ctx := t.Context()
	full := false
	for i := 0; i < 1000; i++ {
		if _, err := s.AppendEnvelope(ctx, fmt.Sprintf("w%d", i), []byte(`1`), ""); err == ErrStoreFull {
			full = true
			break
		}
	}
	if !full {
		t.Fatal("1000 fresh workspaces fit in a 20000-byte budget")
	}
}
