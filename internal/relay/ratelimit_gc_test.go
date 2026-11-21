package relay

import (
	"strconv"
	"testing"
	"time"
)

// Every distinct key (a client /64, a workspace id an attacker picks) adds a
// bucket. A bucket that has refilled to its burst is the same as no bucket,
// so once the map is large it is pruned of those at once instead of keeping
// every key for ten minutes: a flood of fresh keys can't grow it without
// bound and run a small machine out of memory.
func TestIPRateLimiterPrunesRefilledBucketsUnderPressure(t *testing.T) {
	l := newIPRateLimiter(1000, 2) // refills in 2 ms
	for i := 0; i < limiterGCKeys+500; i++ {
		l.allow("k" + strconv.Itoa(i))
	}
	time.Sleep(limiterGCMinInterval + 50*time.Millisecond)
	l.allow("fresh")
	l.mu.Lock()
	n := len(l.seen)
	l.mu.Unlock()
	if n > 10 {
		t.Fatalf("%d buckets kept after every one refilled; want them pruned", n)
	}
}

// Pruning is lossless: a bucket still short of tokens is kept.
func TestIPRateLimiterKeepsDrainedBuckets(t *testing.T) {
	l := newIPRateLimiter(0.001, 1)
	if !l.allow("drained") || l.allow("drained") {
		t.Fatal("setup: the second request must be refused")
	}
	for i := 0; i < limiterGCKeys+10; i++ {
		l.allow("k" + strconv.Itoa(i))
	}
	time.Sleep(limiterGCMinInterval + 50*time.Millisecond)
	l.allow("fresh")
	if l.allow("drained") {
		t.Fatal("a drained bucket was pruned: its client got a fresh burst")
	}
}
