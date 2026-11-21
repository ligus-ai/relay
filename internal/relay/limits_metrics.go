package relay

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Limit and tenant metrics (docs/tenancy.md, "Metrics"). Process-wide like
// the client-address policy: one relay process serves one /metrics.
//
// Tenant label values come only from configured tenant ids, and at most
// maxTenantLabels distinct values are emitted; the rest are summed under
// tenant="_other", so a misconfiguration can't explode the series count.

const otherTenantLabel = "_other"

const defaultMetricsMaxTenants = 50

type limitCounters struct {
	byLimit map[string]*atomic.Int64 // fixed keys (allLimitNames)

	labels map[string]bool // tenant ids reported under their own label (read-only)

	mu      sync.Mutex
	tenants map[string]*tenantCounters // label value → counters
}

type tenantCounters struct {
	requests atomic.Int64
	byLimit  map[string]*atomic.Int64
}

func newLimitCounters(maxLabels int, tenantIDs []string) *limitCounters {
	c := &limitCounters{byLimit: map[string]*atomic.Int64{}, tenants: map[string]*tenantCounters{}, labels: map[string]bool{}}
	for i, t := range tenantIDs {
		if i < maxLabels {
			c.labels[t] = true
		}
	}
	for _, l := range allLimitNames {
		c.byLimit[l] = new(atomic.Int64)
	}
	return c
}

var limitStats atomic.Pointer[limitCounters]

func init() { limitStats.Store(newLimitCounters(0, nil)) }

// resetLimitStats starts a fresh counter set with the tenant label set (New
// does this once per server).
func resetLimitStats(maxLabels int, tenantIDs []string) {
	limitStats.Store(newLimitCounters(maxLabels, tenantIDs))
}

// tenant returns the counters for a tenant label: the tenant id when it is
// one of the first maxLabels configured tenants, else "_other".
func (c *limitCounters) tenant(t string) *tenantCounters {
	if !c.labels[t] {
		t = otherTenantLabel
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tc := c.tenants[t]
	if tc == nil {
		tc = &tenantCounters{byLimit: map[string]*atomic.Int64{}}
		for _, l := range allLimitNames {
			tc.byLimit[l] = new(atomic.Int64)
		}
		c.tenants[t] = tc
	}
	return tc
}

// tenantLabel is the label value tenant is reported under.
func (c *limitCounters) tenantLabel(t string) string {
	if c.labels[t] {
		return t
	}
	return otherTenantLabel
}

// countLimit records one refusal of limit (and of tenant, when non-empty).
func countLimit(limit, tenant string) {
	c := limitStats.Load()
	if n := c.byLimit[limit]; n != nil {
		n.Add(1)
	}
	if tenant != "" {
		if n := c.tenant(tenant).byLimit[limit]; n != nil {
			n.Add(1)
		}
	}
}

// countTenantRequest records one admitted request of tenant.
func countTenantRequest(tenant string) {
	if tenant != "" {
		limitStats.Load().tenant(tenant).requests.Add(1)
	}
}

// roomGaugeTTL bounds how often /metrics reads the room totals (on Postgres a
// scan of relay_rooms): /metrics can be open and isn't rate limited.
const roomGaugeTTL = 10 * time.Second

type roomGaugeCache struct {
	mu           sync.Mutex
	rooms, bytes int64
	at           time.Time
}

func (s *Server) roomTotals(ctx context.Context, rs roomStore) (int64, int64, error) {
	c := &s.roomGauge
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < roomGaugeTTL {
		return c.rooms, c.bytes, nil
	}
	rooms, bytes, err := rs.RoomTotals(ctx)
	if err != nil {
		return 0, 0, err
	}
	c.rooms, c.bytes, c.at = rooms, bytes, time.Now()
	return rooms, bytes, nil
}

// writeLimitMetrics appends the limit, room and tenant series to /metrics.
func (s *Server) writeLimitMetrics(ctx context.Context, w io.Writer) {
	c := limitStats.Load()
	fmt.Fprintf(w, "# HELP hive_relay_limit_rejections_total Requests refused by a relay limit.\n")
	fmt.Fprintf(w, "# TYPE hive_relay_limit_rejections_total counter\n")
	for _, l := range allLimitNames {
		fmt.Fprintf(w, "hive_relay_limit_rejections_total{limit=%q} %d\n", l, c.byLimit[l].Load())
	}
	rs, ok := s.store.(roomStore)
	if ok {
		if rooms, bytes, err := s.roomTotals(ctx, rs); err == nil {
			fmt.Fprintf(w, "# HELP hive_relay_rooms Rooms holding data.\n# TYPE hive_relay_rooms gauge\nhive_relay_rooms %d\n", rooms)
			fmt.Fprintf(w, "# HELP hive_relay_room_bytes Stored room bytes (envelope bodies and key rotations).\n# TYPE hive_relay_room_bytes gauge\nhive_relay_room_bytes %d\n", bytes)
		}
	}
	// Tenant series only behind the metrics token: on an open /metrics they
	// would tell anyone which tenants share the relay and how much each uses
	// (startup refuses tenancy without the token; this covers library use).
	if s.tenancy == nil || s.metricsToken == "" {
		return
	}
	c.mu.Lock()
	labels := make([]string, 0, len(c.tenants))
	for t := range c.tenants {
		labels = append(labels, t)
	}
	c.mu.Unlock()
	sort.Strings(labels)
	fmt.Fprintf(w, "# HELP hive_relay_tenant_requests_total Admitted requests per tenant.\n# TYPE hive_relay_tenant_requests_total counter\n")
	for _, t := range labels {
		fmt.Fprintf(w, "hive_relay_tenant_requests_total{tenant=%q} %d\n", t, c.tenant(t).requests.Load())
	}
	fmt.Fprintf(w, "# HELP hive_relay_tenant_limit_rejections_total Requests refused by a limit, per tenant.\n# TYPE hive_relay_tenant_limit_rejections_total counter\n")
	for _, t := range labels {
		tc := c.tenant(t)
		for _, l := range allLimitNames {
			if n := tc.byLimit[l].Load(); n > 0 {
				fmt.Fprintf(w, "hive_relay_tenant_limit_rejections_total{tenant=%q,limit=%q} %d\n", t, l, n)
			}
		}
	}
	if !ok {
		return
	}
	// Usage gauges for configured tenants, folded past the label cap.
	type use struct{ bytes, rooms int64 }
	usage := map[string]*use{}
	order := []string{}
	for _, t := range s.tenancy.ids {
		label := c.tenantLabel(t)
		b, r, err := rs.TenantUsage(ctx, t)
		if err != nil {
			continue
		}
		u := usage[label]
		if u == nil {
			u = &use{}
			usage[label] = u
			order = append(order, label)
		}
		u.bytes += b
		u.rooms += r
	}
	fmt.Fprintf(w, "# HELP hive_relay_tenant_bytes Stored room bytes per tenant.\n# TYPE hive_relay_tenant_bytes gauge\n")
	for _, t := range order {
		fmt.Fprintf(w, "hive_relay_tenant_bytes{tenant=%q} %d\n", t, usage[t].bytes)
	}
	fmt.Fprintf(w, "# HELP hive_relay_tenant_rooms Rooms per tenant.\n# TYPE hive_relay_tenant_rooms gauge\n")
	for _, t := range order {
		fmt.Fprintf(w, "hive_relay_tenant_rooms{tenant=%q} %d\n", t, usage[t].rooms)
	}
}
