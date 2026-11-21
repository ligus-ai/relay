package relay

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Abuse controls for the hot paths. Both are generous by default and env-tunable
// so they only ever stop abuse, never legitimate sync / catch-up.
//
//   LANGSTROTH_RELAY_PUSH_RATE   per-IP envelope-push tokens/sec (0 disables)   default 100
//   LANGSTROTH_RELAY_PUSH_BURST  per-IP push burst capacity                     default 300
//   LANGSTROTH_RELAY_MAX_SSE     max concurrent SSE streams (0 = unlimited)     default 2000

// ipRateLimiter is a per-key token bucket. Keyed on the real client IP (see
// clientIP, which reads a forwarding header only from a trusted proxy).
type ipRateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // bucket capacity
	seen   map[string]*ipBucket
	lastGC time.Time
}

// A limiter holding limiterGCKeys buckets or more prunes the ones that have
// refilled to their burst (no different from an absent bucket), at most every
// limiterGCMinInterval; below that, idle buckets go every ten minutes.
const (
	limiterGCKeys        = 20000
	limiterGCMinInterval = time.Second
)

type ipBucket struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter(rate, burst float64) *ipRateLimiter {
	return &ipRateLimiter{rate: rate, burst: burst, seen: map[string]*ipBucket{}, lastGC: time.Now()}
}

// allow consumes one token for key; false means the caller is over the limit.
func (l *ipRateLimiter) allow(key string) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Occasionally drop idle buckets so the map can't grow without bound;
	// under pressure (a flood of fresh keys), also every bucket that has
	// refilled, which loses nothing.
	pressure := len(l.seen) >= limiterGCKeys && now.Sub(l.lastGC) >= limiterGCMinInterval
	if pressure || now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.seen {
			idle := now.Sub(b.last)
			if idle > 10*time.Minute || (pressure && b.tokens+idle.Seconds()*l.rate >= l.burst) {
				delete(l.seen, k)
			}
		}
		l.lastGC = now
	}
	b := l.seen[key]
	if b == nil {
		b = &ipBucket{tokens: l.burst, last: now}
		l.seen[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// concurrencyLimiter caps concurrent long-lived handlers (SSE streams) so an
// attacker can't exhaust goroutines/FDs by opening streams without bound.
type concurrencyLimiter struct {
	max int64
	cur atomic.Int64
}

func newConcurrencyLimiter(max int64) *concurrencyLimiter { return &concurrencyLimiter{max: max} }

// acquire reserves a slot; ok=false means the cap is reached. Call the returned
// func to release (safe even when ok=false or the limiter is nil/unlimited).
func (c *concurrencyLimiter) acquire() (release func(), ok bool) {
	if c == nil || c.max <= 0 {
		return func() {}, true
	}
	if c.cur.Add(1) > c.max {
		c.cur.Add(-1)
		return func() {}, false
	}
	var once sync.Once
	return func() { once.Do(func() { c.cur.Add(-1) }) }, true
}

// noteDefault, when set (tests only), sees the default each numeric
// setting falls back to, so settings_test.go can compare it with the help.
var noteDefault atomic.Pointer[func(name string, def float64)]

func observeDefault(name string, def float64) {
	if f := noteDefault.Load(); f != nil {
		(*f)(name, def)
	}
}

func envFloat(name string, def float64) float64 {
	observeDefault(name, def)
	if v := getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envInt64(name string, def int64) int64 {
	observeDefault(name, float64(def))
	if v := getenv(name); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// keyedConcurrencyLimiter caps concurrent long-lived handlers per key (per
// client for SSE streams), so one client can't take every slot of the
// instance-wide concurrencyLimiter. Keys with no open slot are dropped, so the
// map holds only clients with a live stream.
type keyedConcurrencyLimiter struct {
	max int64
	mu  sync.Mutex
	cur map[string]int64
}

func newKeyedConcurrencyLimiter(max int64) *keyedConcurrencyLimiter {
	return &keyedConcurrencyLimiter{max: max, cur: map[string]int64{}}
}

// acquire reserves a slot for key; ok=false means key is at its cap. The
// returned release is idempotent.
func (c *keyedConcurrencyLimiter) acquire(key string) (release func(), ok bool) {
	if c == nil || c.max <= 0 {
		return func() {}, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur[key] >= c.max {
		return func() {}, false
	}
	c.cur[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.cur[key]--; c.cur[key] <= 0 {
				delete(c.cur, key)
			}
		})
	}, true
}

// size reports how many keys hold a slot (tests).
func (c *keyedConcurrencyLimiter) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cur)
}

// allowWait is allow that also reports, when refused, how long until the
// bucket holds a token again (for Retry-After).
func (l *ipRateLimiter) allowWait(key string) (bool, time.Duration) {
	if l.allow(key) {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.seen[key]
	if b == nil || l.rate <= 0 {
		return false, time.Second
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}
