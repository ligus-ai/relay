package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Past the per-workspace rotation cap, a new rotation is refused (507) and the
// stored ones are kept: evicting the oldest let junk rotations push the real
// ones out of the keyring.
func TestKeyringCapRefusesInsteadOfEvicting(t *testing.T) {
	s := newMemoryStore()
	s.maxKeyringPerWS = 2
	for i := 0; i < 2; i++ {
		if err := s.AppendKeyRotation(bg, "ws", raw(`{"v":`+itoa(i)+`}`)); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	err := s.AppendKeyRotation(bg, "ws", raw(`{"v":"junk"}`))
	if !errors.Is(err, ErrKeyringFull) || !errors.Is(err, ErrStoreFull) {
		t.Fatalf("rotation past the cap: err %v, want ErrKeyringFull", err)
	}
	kr, _ := s.KeyRotations(bg, "ws")
	if len(kr) != 2 || string(kr[0]) != `{"v":0}` || string(kr[1]) != `{"v":1}` {
		t.Fatalf("stored rotations changed: %s", kr)
	}
	// Another workspace is unaffected.
	if err := s.AppendKeyRotation(bg, "other", raw(`{"v":0}`)); err != nil {
		t.Fatalf("other workspace: %v", err)
	}
}

// A byte cap per workspace keeps the whole keyring inside one bounded listing.
func TestKeyringByteCapRefuses(t *testing.T) {
	s := newMemoryStore()
	s.maxKeyringBytesPerWS = 20
	if err := s.AppendKeyRotation(bg, "ws", raw(`{"v":"0123456789"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendKeyRotation(bg, "ws", raw(`{"v":"0123456789"}`)); !errors.Is(err, ErrKeyringFull) {
		t.Fatalf("second rotation over the byte cap: %v", err)
	}
	if kr, _ := s.KeyRotations(bg, "ws"); len(kr) != 1 {
		t.Fatalf("want 1 stored rotation, got %d", len(kr))
	}
}

// Over HTTP: 507 past the cap, 413 for an oversized rotation, and the listing
// still returns the original rotations.
func TestKeyringHTTPCapAndSize(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_KEYRING_PER_WS", "1")
	t.Setenv("LANGSTROTH_RELAY_MAX_ROTATION_BYTES", "64")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := newTestHTTP(t, srv)

	post := func(body string) int {
		resp, err := http.Post(ts+"/v1/workspaces/ws/keyring", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(`{"blob":"` + strings.Repeat("a", 100) + `"}`); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized rotation: %d, want 413", code)
	}
	if code := post(`{"v":1}`); code != 200 {
		t.Fatalf("first rotation: %d", code)
	}
	if code := post(`{"v":2}`); code != http.StatusInsufficientStorage {
		t.Fatalf("rotation past the cap: %d, want 507", code)
	}
	resp, body := do(t, "GET", ts+"/v1/workspaces/ws/keyring", "", nil)
	if resp.StatusCode != 200 || string(body) != `[{"v":1}]` {
		t.Fatalf("keyring: %d %s", resp.StatusCode, body)
	}
}

// The prune loop no longer evicts keyring rows oldest-first.
func TestPruneLoopHasNoKeyringEviction(t *testing.T) {
	var p housekeepingPruner = (*postgresStore)(nil)
	if _, ok := p.(interface {
		PruneKeyring(context.Context, int) (int64, error)
	}); ok {
		t.Fatal("postgresStore still has an oldest-first PruneKeyring")
	}
}

func newTestHTTP(t *testing.T, srv *Server) string {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}
