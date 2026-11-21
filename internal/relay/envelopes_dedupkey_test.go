package relay

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// F-09: the client-chosen Idempotency-Key / X-Hive-Event-Id was stored
// verbatim (memory dedup map and per-envelope key, Postgres dedup_key) with no
// length bound, so a header of up to the server's 1 MB header limit rode along
// with every envelope, outside the body cap and the store byte budget. Long
// keys are now stored as their SHA-256, which dedups identically.
func TestDedupKeyBounded(t *testing.T) {
	long := strings.Repeat("k", 100000)
	for _, h := range []string{"Idempotency-Key", "X-Hive-Event-Id"} {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(h, long)
		k := dedupKeyFor(r, []byte(`"x"`))
		if len(k) > maxDedupKeyLen {
			t.Fatalf("%s: stored key is %d bytes", h, len(k))
		}
		r2 := httptest.NewRequest("POST", "/", nil)
		r2.Header.Set(h, long)
		if dedupKeyFor(r2, []byte(`"y"`)) != k {
			t.Fatalf("%s: the same long key must map to the same stored key", h)
		}
		r3 := httptest.NewRequest("POST", "/", nil)
		r3.Header.Set(h, long+"z")
		if dedupKeyFor(r3, []byte(`"x"`)) == k {
			t.Fatalf("%s: different long keys must not collide", h)
		}
	}
	// Short keys map to the same fixed-length, writer-scoped form.
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-Hive-Event-Id", "0192f6a0-0000-7000-8000-000000000001")
	got := dedupKeyFor(r, nil)
	if len(got) > maxDedupKeyLen || got == "0192f6a0-0000-7000-8000-000000000001" {
		t.Fatalf("short key not scoped: %q", got)
	}
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header.Set("Idempotency-Key", "0192f6a0-0000-7000-8000-000000000001")
	if dedupKeyFor(r2, nil) != got {
		t.Fatal("the same key from the same writer must map to the same stored key")
	}
}
