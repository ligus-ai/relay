package relay

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func timeResolves(t *testing.T, live int) time.Duration {
	t.Helper()
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	exp := time.Now().Add(time.Hour)
	srv.pairMu.Lock()
	for i := 0; i < live; i++ {
		srv.pairings[fmt.Sprintf("C%07d", i)] = pairing{payload: "p", expiresAt: exp}
	}
	srv.pairMu.Unlock()
	start := time.Now()
	for i := 0; i < 300; i++ {
		r := httptest.NewRequest("GET", "/v1/pair/ZZZZZZ", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.%d.%d:1", i/250, i%250+1)
		r.SetPathValue("code", "ZZZZZZ")
		srv.resolvePairing(httptest.NewRecorder(), r)
	}
	return time.Since(start)
}

// F-11: every pairing create and resolve swept every live code (up to 50 000)
// and every client's failure window while holding the one pairing mutex, and
// a resolve swept before checking the caller's block. Anyone could hold that
// lock busy (stalling pairing for everyone) with cheap requests once enough
// codes were live. Sweeps now run at most once per second.
func TestPairingSweepIsNotPerRequest(t *testing.T) {
	small := timeResolves(t, 0)
	big := timeResolves(t, 50000)
	if big > 20*small+50*time.Millisecond {
		t.Fatalf("300 resolves took %v with 50k live codes vs %v with none: per-request sweep", big, small)
	}
}
