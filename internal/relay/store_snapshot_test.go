package relay

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Populate a store with social + envelope data, then flush.
	s := newMemoryStoreWithPersistence(dir)
	_, _ = s.RegisterAccountDevice(bg, 1, "alice", "d1", strptr("nodeA"), nil, 100)
	_, _ = s.RegisterAccountDevice(bg, 2, "bob", "d2", nil, nil, 100)
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "alice", b, "bob", 1, nil)
	_, _ = s.AcceptFriendRequest(bg, req.ID, b, nil)
	_, _ = s.PushAccountEvent(bg, a, raw(`{"kind":"ping"}`))
	_, _ = s.AppendEnvelope(bg, "ws1", raw(`{"ct":"opaque"}`), "")
	if err := s.Flush(bg); err != nil {
		t.Fatal(err)
	}

	// A fresh store loading the same dir sees the persisted graph.
	restored := newMemoryStoreWithPersistence(dir)
	if f, _ := restored.AreFriends(bg, a, b); !f {
		t.Fatal("friendship should persist")
	}
	if n, _ := restored.FriendCount(bg, a); n != 1 {
		t.Fatalf("friend count %d", n)
	}
	if k, ok, _ := restored.AccountKeyForLogin(bg, "bob"); !ok || k != b {
		t.Fatal("login index should persist")
	}
	if devs, _ := restored.AccountDevices(bg, a); len(devs) != 1 {
		t.Fatalf("devices %d", len(devs))
	}
	if rows, _ := restored.AccountInboxAfter(bg, a, 0); len(rows) != 1 {
		t.Fatalf("inbox %d", len(rows))
	}
	if env, _ := restored.EnvelopesAfter(bg, "ws1", 0); len(env) != 1 {
		t.Fatalf("envelopes %d", len(env))
	}
}

func TestMissingSnapshotStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	s := newMemoryStoreWithPersistence(dir)
	if !s.PersistenceEnabled() {
		t.Fatal("persistence should be enabled")
	}
	if devs, _ := s.AccountDevices(bg, "github:1"); len(devs) != 0 {
		t.Fatal("fresh store should be empty")
	}
	// In-memory store (no path): flush is a no-op.
	if err := newMemoryStore().Flush(bg); err != nil {
		t.Fatalf("no-path flush should be nil: %v", err)
	}
	_ = filepath.Join(dir, snapshotFile)
}

// F-07: the snapshot (token and invite-code hashes, user records, APNs device
// tokens, rosters, ciphertext) was written 0644 in a 0755 directory, readable
// by every local user on a shared host.
func TestSnapshotFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s := newMemoryStoreWithPersistence(dir)
	if _, err := s.AppendEnvelope(t.Context(), "w", []byte(`"x"`), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.persistPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("snapshot mode %v is readable by group/other", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		t.Errorf("data dir mode %v is open to group/other", di.Mode().Perm())
	}
}
