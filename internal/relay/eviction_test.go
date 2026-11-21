package relay

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Per-envelope eviction is removed (docs/tenancy.md, "What a client needs
// from the relay"): a Ligus client folds a room's whole log from seq 1 and
// never backfills, so evicting the oldest envelopes (the founder's seed)
// permanently breaks every device that joins afterwards. Room quotas
// (refusal) and whole-room retention replace it.

// With no settings at all, a room past the old 50 000 default keeps its seed.
func TestEnvelopeEvictionOffByDefault(t *testing.T) {
	s := newMemoryStore()
	body := raw(`1`)
	for i := 0; i < 50_001; i++ {
		if _, err := s.AppendEnvelope(bg, "ws", body, ""); err != nil {
			t.Fatal(err)
		}
	}
	rows, _, err := s.EnvelopesPage(bg, "ws", 0, 1, 1<<20)
	if err != nil || len(rows) != 1 || rows[0].Seq != 1 {
		t.Fatalf("the room's seed (seq 1) was evicted: %+v %v", rows, err)
	}
}

// An old snapshot holding more envelopes than the old cap loads whole.
func TestSnapshotRestoreKeepsWholeLog(t *testing.T) {
	s := newMemoryStore()
	for i := 0; i < 5; i++ {
		if _, err := s.AppendEnvelope(bg, "ws", raw(`1`), ""); err != nil {
			t.Fatal(err)
		}
	}
	w := s.workspace("ws")
	for i := range w.envAt {
		w.envAt[i] = time.Now().Add(-400 * 24 * time.Hour).Unix() // very old
	}
	snap := s.toSnapshot()
	t.Setenv("LANGSTROTH_RELAY_MAX_ENVELOPES", "0")
	r := newMemoryStore()
	r.restore(snap)
	if rows, _ := r.EnvelopesAfter(bg, "ws", 0); len(rows) != 5 {
		t.Fatalf("restore dropped envelopes: %d left", len(rows))
	}
}

// The removed settings refuse to start unless they are 0 (a no-op), so an
// operator who set a bound learns it is gone instead of silently losing it.
func TestRemovedEvictionSettingsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, val string
		bad       bool
	}{
		{"LANGSTROTH_RELAY_MAX_ENVELOPES", "50000", true},
		{"LANGSTROTH_RELAY_MAX_ENVELOPES", "0", false},
		{"LANGSTROTH_RELAY_MAX_ENVELOPES", "", false},
		{"LANGSTROTH_RELAY_RETENTION_DAYS", "30", true},
		{"LANGSTROTH_RELAY_RETENTION_DAYS", "0", false},
		{"LANGSTROTH_RELAY_MAX_ENVELOPES", "junk", true},
	} {
		t.Run(tc.name+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.name, tc.val)
			err := evictionConfigError()
			if (err != nil) != tc.bad {
				t.Fatalf("%s=%q: err=%v, want refusal=%v", tc.name, tc.val, err, tc.bad)
			}
			if err != nil && !strings.Contains(err.Error(), "LANGSTROTH_RELAY_ROOM_") {
				t.Fatalf("the refusal should name the replacement: %v", err)
			}
		})
	}
}

// Postgres has no envelope prune any more (it ran hourly at the 50 000
// default, so a v0.3.0 deploy relying on the default would have kept
// evicting seeds).
func TestPostgresHasNoEnvelopePrune(t *testing.T) {
	var s any = (*postgresStore)(nil)
	if _, ok := s.(interface {
		PruneEnvelopes(context.Context, int, time.Duration) (int64, error)
	}); ok {
		t.Fatal("postgresStore still prunes envelopes out of rooms")
	}
}
