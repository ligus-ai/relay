package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pairing codes: confusion-free alphabet (no I/L/O/U), 6 chars → ~1e9 combos.
const (
	codeAlphabet   = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	codeLen        = 6
	defaultPairTTL = 600
	maxPairTTL     = 3600
	maxPairPayload = 8192

	// resolvePairing is attempt-capped per client so the short code space can't
	// be enumerated: more than maxResolveFailures misses inside resolveWindow
	// from one client → 429 until the window rolls over.
	maxResolveFailures = 10
	resolveWindow      = time.Minute
)

// maxRequestBodyBytes bounds every JSON request body (env LANGSTROTH_RELAY_MAX_BODY_BYTES,
// default 4 MiB) to stop multi-GB uploads from exhausting memory.
var maxRequestBodyBytes = bodyCapFromEnv()

func bodyCapFromEnv() int64 {
	const def = 4 << 20 // 4 MiB
	if v := getenv("LANGSTROTH_RELAY_MAX_BODY_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// Options configure a Server. Only Store is required; the rest default to the
// open-relay behavior. Downstream builds may inject implementations of the seams
// (see seams.go) here without touching this package.
type Options struct {
	Store       Store               // required
	Entitlement EntitlementVerifier // nil → EntitlementFromEnv()
	WriteGuard  WriteGuard          // nil → allow all writes (content-blind)
	ReadGuard   ReadGuard           // nil → allow all reads (open relay read-openness)
	Hooks       Hooks               // nil → no-op
	FriendCap   *int                // nil → unlimited
	AdminAuth   AdminAuthorizer     // nil → /v1/admin/* disabled (404)
	// Membership enables relay-managed team roster routes + the membership guard.
	// Also enabled by env LANGSTROTH_RELAY_MEMBERSHIP=1. Off → the relay is unchanged
	// (no roster routes, content-blind forwarding).
	Membership bool
	// TunnelPolicy enables the hive-tunnel/1 phone ↔ host relay (tunnel.go).
	// nil → TunnelPolicyFromEnv semantics: LANGSTROTH_RELAY_TUNNEL=off|open|allowlist
	// (default off = /v1/tunnel/* answers 404).
	TunnelPolicy TunnelPolicy
	// PushSender delivers end-to-end encrypted pushes for tunnel hosts.
	// nil → the built-in APNs sender when LANGSTROTH_RELAY_APNS_* is set
	// (push_apns.go), else push unavailable.
	PushSender PushSender
	// GitHubRoutes registers the deprecated GitHub social routes (directory,
	// account, friends) for older clients. Also enabled by env
	// LANGSTROTH_RELAY_GITHUB_ROUTES=on. Off (the v0.3 default) → 404. Removed in v0.4.
	GitHubRoutes bool
}

// Server holds the durable Store plus the ephemeral, instance-local pieces
// (short pairing codes), the access verifier, and the optional seams.
type Server struct {
	store       Store
	entitlement EntitlementVerifier
	guard       WriteGuard      // nil = content-blind (no membership check)
	readGuard   ReadGuard       // nil = open read-openness (no membership check)
	hooks       Hooks           // nil = no-op
	adminAuth   AdminAuthorizer // nil = admin API disabled
	membership  bool            // relay-managed team membership: routes + guard
	// Optional signed-identity verifier for membership (LANGSTROTH_RELAY_MEMBERSHIP_PUBKEY).
	// Decoupled from the access gate: it lets the relay read a caller's
	// identity (a signed hrt1 token's Sub) for membership enforcement WITHOUT
	// forcing the access policy to entSigned — so teams can run on an OPEN relay
	// (collaboration stays open; only claimed workspaces require a member token).
	memberVerifier ed25519.PublicKey
	friendCap      *int
	httpClient     *http.Client
	// verify authenticates a GitHub token → user. Defaults to verifyGitHub
	// (a live api.github.com call); tests override it.
	verify func(ctx context.Context, token string) (*githubUser, error)

	pairMu       sync.Mutex
	pairings     map[string]pairing
	pairAttempts map[string]*pairAttempt // client → recent failed-resolve window
	maxPairings  int                     // cap on live pairing codes (0 = unlimited)
	pairSweptAt  time.Time               // last sweep of pairings/pairAttempts (≤ 1/s)

	pushLimiter    *ipRateLimiter           // per-IP write rate limit (all unauth writes)
	sseLimiter     *concurrencyLimiter      // cap on concurrent SSE streams
	sseClient      *keyedConcurrencyLimiter // per-client cap on concurrent SSE streams
	readLimiter    *ipRateLimiter           // per-client rate on workspace reads
	wsWriterLimit  *ipRateLimiter           // per-(workspace,writer) envelope-append rate
	ghLimiter      *ipRateLimiter           // per-IP rate on GitHub-authenticated routes
	inviteLimiter  *ipRateLimiter           // per-(sender,recipient) account-invite rate
	ghCache        *identityCache           // token-hash → identity, short TTL
	metricsToken   string                   // ops credential for /metrics (env; "" = open)
	metricsTokHash string                   // sha256 of metricsToken for constant-time compare

	tunnel *tunnelHub // nil = tunnel off

	wsScope string // LANGSTROTH_RELAY_WORKSPACE_SCOPE: off | claims | strict (scope.go)

	maxListBytes int // LANGSTROTH_RELAY_MAX_LIST_BYTES: keyring/candidates/presence response bound (listcap.go)

	maxRotationBytes int // LANGSTROTH_RELAY_MAX_ROTATION_BYTES: one key rotation's size (0 = body cap only)

	githubRoutes bool // deprecated GitHub social routes registered (github_routes.go)

	contacts   ContactStore // nil = /v1/contacts/ off (404)
	contactCfg contactConfig
	contactLim contactLimiters

	lim       communityLimits // room quotas, request rates, retention (limits.go)
	blobs     blobConfig      // blob channel limits (blobs.go)
	blobStore blobStore       // nil = the store has no blobs (routes 404)
	tenancy   *tenancyConf    // nil = tenancy off (tenancy.go)

	pairCount map[string]int // live pairing codes per tenant (tenancy only)

	// Live pairing codes per client (pairClient) and per IPv6 /48
	// (pairSlash48), and the bytes their payloads hold in memory
	// (pairBytes): one address can't take every code, and a flood of large
	// payloads can't exhaust a small machine's memory.
	pairClient           map[string]int
	pairSlash48          map[string]int
	pairBytes            int64
	maxPairingsPerClient int   // LANGSTROTH_RELAY_MAX_PAIRINGS_PER_CLIENT (0 = off)
	maxPairingBytes      int64 // LANGSTROTH_RELAY_MAX_PAIRING_BYTES (0 = off)

	roomGauge roomGaugeCache // /metrics room totals, re-read at most every roomGaugeTTL

	healthMu      sync.Mutex // guards the cached /v1/health ping result
	healthErr     error
	healthChecked time.Time
}

type pairing struct {
	payload   string
	expiresAt time.Time
	tenant    string // tenancy: the tenant the code lives in
	client    string // clientKey of the creator (pairClient)
	slash48   string // the creator's IPv6 /48, "" for IPv4 (pairSlash48)
}

// newPairCode draws a pairing code (a variable so tests can force collisions).
var newPairCode = randomPairCode

// pairAttempt tracks a client's failed pairing-code guesses inside one window.
type pairAttempt struct {
	failures int
	resetAt  time.Time
}

// New builds a Server from Options, filling in open-relay defaults.
func New(o Options) *Server {
	if o.Entitlement == nil {
		o.Entitlement = EntitlementFromEnv()
	}
	metricsToken := strings.TrimSpace(getenv("LANGSTROTH_RELAY_METRICS_TOKEN"))
	// Client address policy for rate limits and logs (clientip.go).
	activeClientIP.Store(clientIPPolicyFromEnv())
	s := &Server{
		store:            o.Store,
		entitlement:      o.Entitlement,
		guard:            o.WriteGuard,
		readGuard:        o.ReadGuard,
		hooks:            o.Hooks,
		adminAuth:        o.AdminAuth,
		membership:       o.Membership || membershipFromEnv(),
		friendCap:        o.FriendCap,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
		pairings:         map[string]pairing{},
		pairAttempts:     map[string]*pairAttempt{},
		maxPairings:      int(envInt64("LANGSTROTH_RELAY_MAX_PAIRINGS", defaultMaxLivePairings)),
		pushLimiter:      newIPRateLimiter(envFloat("LANGSTROTH_RELAY_PUSH_RATE", 100), envFloat("LANGSTROTH_RELAY_PUSH_BURST", 300)),
		sseLimiter:       newConcurrencyLimiter(envInt64("LANGSTROTH_RELAY_MAX_SSE", 2000)),
		sseClient:        newKeyedConcurrencyLimiter(envInt64("LANGSTROTH_RELAY_MAX_SSE_PER_CLIENT", defaultMaxSSEPerClient)),
		readLimiter:      newIPRateLimiter(envFloat("LANGSTROTH_RELAY_READ_RATE", defaultReadRate), envFloat("LANGSTROTH_RELAY_READ_BURST", defaultReadBurst)),
		wsWriterLimit:    newIPRateLimiter(envFloat("LANGSTROTH_RELAY_WS_WRITER_RATE", defaultWSWriterRate), envFloat("LANGSTROTH_RELAY_WS_WRITER_BURST", defaultWSWriterBurst)),
		ghLimiter:        newIPRateLimiter(envFloat("LANGSTROTH_RELAY_GITHUB_RATE", defaultGitHubAuthRate), envFloat("LANGSTROTH_RELAY_GITHUB_BURST", defaultGitHubAuthBurst)),
		inviteLimiter:    newIPRateLimiter(envFloat("LANGSTROTH_RELAY_INVITE_RATE", defaultInviteRate), envFloat("LANGSTROTH_RELAY_INVITE_BURST", defaultInviteBurst)),
		ghCache:          newIdentityCache(ghIdentityTTL, ghNegativeTTL),
		metricsToken:     metricsToken,
		wsScope:          workspaceScopeFromEnv(),
		maxListBytes:     listCapFromEnv(),
		maxRotationBytes: int(max(envInt64("LANGSTROTH_RELAY_MAX_ROTATION_BYTES", defaultMaxRotationBytes), 0)),
	}
	if metricsToken != "" {
		s.metricsTokHash = sha256hex(metricsToken)
	}
	s.lim = communityLimitsFromEnv()
	s.blobs = blobConfigFromEnv()
	if bs, ok := o.Store.(blobStore); ok {
		s.blobStore = bs
	}
	s.pairCount = map[string]int{}
	s.pairClient = map[string]int{}
	s.pairSlash48 = map[string]int{}
	s.maxPairingsPerClient = int(max(envInt64("LANGSTROTH_RELAY_MAX_PAIRINGS_PER_CLIENT", defaultMaxPairingsPerClient), 0))
	s.maxPairingBytes = max(envInt64("LANGSTROTH_RELAY_MAX_PAIRING_BYTES", defaultMaxPairingBytes), 0)
	tc, terr := tenancyFromEnv()
	switch {
	case terr != nil:
		// Main refuses to start on this (tenancyConfigError); a library
		// caller gets a relay that admits nobody rather than an open one.
		slog.Error("tenancy config refused; denying every token", "error", terr)
		s.entitlement = entitlementPolicy{kind: entDeny}
	case tc != nil:
		s.tenancy = tc
		s.entitlement = tenancyVerifier{tc: tc}
	}
	var tenantIDs []string
	if s.tenancy != nil {
		tenantIDs = s.tenancy.ids
	}
	resetLimitStats(int(envInt64("LANGSTROTH_RELAY_METRICS_MAX_TENANTS", defaultMetricsMaxTenants)), tenantIDs)
	s.githubRoutes = o.GitHubRoutes || githubRoutesFromEnv()
	s.contactCfg = contactConfigFromEnv()
	s.contactLim = contactLimitersFromEnv()
	if s.contactCfg.enabled {
		if cs, ok := o.Store.(ContactStore); ok {
			s.contacts = cs
		} else {
			slog.Warn("store does not implement ContactStore; /v1/contacts/ is off")
		}
	}
	// A tenant-confined gate is always workspace-strict (see
	// entitlementConfigError): tid alone would let one tenant's token reach
	// another tenant's workspaces.
	if ep, ok := s.entitlement.(entitlementPolicy); ok && ep.tenants != nil {
		s.wsScope = scopeStrict
	}
	s.verify = s.verifyGitHub
	tunnelPolicy := o.TunnelPolicy
	if tunnelPolicy == nil {
		// The registration token must pass the relay's own access gate when
		// one is configured (hrt1 / access tokens); the open policy admits any.
		tunnelPolicy = tunnelPolicyFromEnv(s.entitlement)
	}
	if tunnelPolicy != nil {
		push := o.PushSender
		if push == nil {
			// The built-in APNs sender, when LANGSTROTH_RELAY_APNS_* is configured
			// (push_apns.go); otherwise push stays unavailable.
			push = pushSenderFromEnv()
		}
		s.tunnel = newTunnelHub(s.store, tunnelPolicy, push)
		s.tunnel.tenancy = s.tenancy
	}
	// When membership is on, default the guards to the built-in roster guard
	// (unless a downstream build supplied its own). The guard is content-blind
	// and no-ops for unclaimed workspaces, so this never breaks the open default.
	if s.membership {
		if s.guard == nil {
			s.guard = membershipGuard{store: s.store}
		}
		if s.readGuard == nil {
			s.readGuard = membershipGuard{store: s.store}
		}
		// Optional identity verifier, independent of the access policy.
		if pk := strings.TrimSpace(getenv("LANGSTROTH_RELAY_MEMBERSHIP_PUBKEY")); pk != "" {
			if vk, ok := parsePubkey(pk); ok {
				s.memberVerifier = vk
			} else {
				os.Stderr.WriteString("LANGSTROTH_RELAY_MEMBERSHIP_PUBKEY set but unparseable; ignoring\n")
			}
		}
	}
	return s
}

// claimsCtxKey carries the verified token claims from the gate to the handlers
// (so a WriteGuard can read claims/RBAC without re-verifying).
type claimsCtxKey struct{}

func claimsFrom(ctx context.Context) *TokenClaims {
	c, _ := ctx.Value(claimsCtxKey{}).(*TokenClaims)
	return c
}

func nowUnix() int64 { return time.Now().Unix() }

// Handler builds the /v1 router. Everything except /v1/health sits behind the
// access gate (a no-op when the policy is Open, i.e. self-hosted).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	m := newMetrics()

	// Public landing page at the exact root, and the health check.
	mux.HandleFunc("GET /{$}", s.statusPage)
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /metrics", s.guardMetrics(func(w http.ResponseWriter, r *http.Request) {
		m.handler(w, r)
		s.writeLimitMetrics(r.Context(), w)
	}))

	mux.HandleFunc("POST /v1/workspaces/{id}/envelopes", s.scoped(s.postEnvelope))
	mux.HandleFunc("GET /v1/workspaces/{id}/envelopes", s.scoped(s.listEnvelopes))
	mux.HandleFunc("GET /v1/workspaces/{id}/events", s.scoped(s.streamEvents))
	mux.HandleFunc("POST /v1/workspaces/{id}/candidates", s.scoped(s.publishCandidates))
	mux.HandleFunc("GET /v1/workspaces/{id}/candidates", s.scoped(s.listCandidates))
	mux.HandleFunc("POST /v1/workspaces/{id}/presence", s.scoped(s.publishPresence))
	mux.HandleFunc("GET /v1/workspaces/{id}/presence", s.scoped(s.listPresence))
	mux.HandleFunc("POST /v1/workspaces/{id}/keyring", s.scoped(s.publishKeyring))
	mux.HandleFunc("GET /v1/workspaces/{id}/keyring", s.scoped(s.listKeyring))

	// Relay-managed team membership (opt-in: Options.Membership / env). Off →
	// these routes are unregistered (404), matching the plain content-blind relay.
	if s.membership {
		mux.HandleFunc("GET /v1/workspaces/{id}/members", s.scoped(s.membersList))
		mux.HandleFunc("POST /v1/workspaces/{id}/members", s.scoped(s.memberUpsert))
		mux.HandleFunc("DELETE /v1/workspaces/{id}/members/{account}", s.scoped(s.memberRemove))
		mux.HandleFunc("POST /v1/workspaces/{id}/members/claim", s.scoped(s.membershipClaim))
		mux.HandleFunc("POST /v1/workspaces/{id}/invites", s.scoped(s.inviteCreate))
		mux.HandleFunc("GET /v1/workspaces/{id}/invites", s.scoped(s.invitesList))
		mux.HandleFunc("DELETE /v1/workspaces/{id}/invites/{inviteId}", s.scoped(s.inviteRevoke))
		mux.HandleFunc("POST /v1/workspaces/{id}/join", s.scoped(s.workspaceJoin))
	}

	mux.HandleFunc("POST /v1/pair", s.createPairing)
	mux.HandleFunc("GET /v1/pair/{code}", s.resolvePairing)

	// Deprecated GitHub social routes (directory / account / friends): only
	// with Options.GitHubRoutes or LANGSTROTH_RELAY_GITHUB_ROUTES=on, else 404. Removed
	// in v0.4.
	s.registerGitHubRoutes(mux)

	// Contacts (v0.3): opaque signed records + sealed drop boxes.
	s.registerContacts(mux)

	// User/token management — gated by the AdminAuthorizer seam (not the relay
	// access token), so these bypass the access gate below.
	mux.HandleFunc("POST /v1/admin/users", s.adminCreateUser)
	mux.HandleFunc("GET /v1/admin/users", s.adminListUsers)
	mux.HandleFunc("POST /v1/admin/users/{id}/tokens", s.adminIssueToken)
	mux.HandleFunc("POST /v1/admin/users/{id}/disabled", s.adminSetDisabled)
	mux.HandleFunc("DELETE /v1/admin/tokens/{id}", s.adminRevokeToken)

	// Blob channel (blobs.go): additive; off → 404.
	s.registerBlobs(mux)

	// Tenant admin scope (tenancy only; 404 otherwise).
	if s.tenancy != nil {
		s.registerTenantAdmin(mux)
	}

	// Relay tunnel (hive-tunnel/1). Off → unregistered, so /v1/tunnel/* is 404.
	if s.tunnel != nil {
		s.tunnel.register(mux)
	}

	return m.observe(s.gate(mux))
}

// RefreshTunnelStatus tells the relay that hostID's TunnelPolicy status may
// have changed (for example, a downstream policy changed its admission). The cached
// status is dropped, so the next phone connect asks the policy again, and a
// connected host is re-checked at once and sent {"t":"status"} if it changed.
// Without this, a change takes effect within the 60 s status cache. A no-op
// when the tunnel is off; safe from any goroutine.
func (s *Server) RefreshTunnelStatus(hostID string) {
	if s.tunnel != nil {
		s.tunnel.refreshStatus(hostID)
	}
}

// ShutdownTunnels closes every tunnel WebSocket with shutting_down (4011) and
// stops tunnel housekeeping. Wire it to http.Server.RegisterOnShutdown: hijacked
// connections aren't closed by http.Server.Shutdown.
func (s *Server) ShutdownTunnels() {
	if s.tunnel != nil {
		s.tunnel.shutdown()
	}
}

// gate rejects /v1/* (except health) unless the caller is admitted, and stashes
// the verified claims in the request context for downstream enforcement.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Per-client request rate (LANGSTROTH_RELAY_IP_RATE), before any
		// authentication work, on every route but status, health and metrics.
		if s.lim.ip != nil && limitedPath(r.URL.Path) {
			if ok, wait := s.lim.ip.allowWait(clientKey(r)); !ok {
				tooMany(w, limIPRate, "", wait, "rate limit exceeded")
				return
			}
		}
		if s.lim.inflight != nil && inflightPath(r.URL.Path) {
			release, ok := s.lim.acquireInflight(r)
			if !ok {
				countLimit(limClientInflight, "")
				refuse(w, http.StatusTooManyRequests, refClientInflight, "too many requests in progress from this client", retryInflight)
				return
			}
			defer release()
		}
		if r.URL.Path == "/" || r.URL.Path == "/v1/health" || r.URL.Path == "/metrics" || strings.HasPrefix(r.URL.Path, "/v1/admin/") ||
			strings.HasPrefix(r.URL.Path, "/v1/tunnel/") || (s.tenancy != nil && (r.URL.Path == "/v1/tenant" || strings.HasPrefix(r.URL.Path, "/v1/tenant/"))) {
			// The tunnel authenticates hosts and phones itself (signed
			// challenges + host-signed credentials); a host's registration
			// token is checked against this same access policy (tunnel_policy.go).
			// The status page, health, and metrics are public; the admin API runs
			// its own AdminAuthorizer (an operator credential, not a relay token).
			next.ServeHTTP(w, r)
			return
		}
		claims, ok := s.entitlement.Allow(bearerToken(r), nowUnix())
		if !ok {
			http.Error(w, "relay requires a valid access token", http.StatusUnauthorized)
			return
		}
		// If the access token carried no identity (e.g. the open policy) but a
		// membership identity key is configured, try to read a signed identity
		// from the same bearer — so membership can enforce per-caller without the
		// access gate having to fail-close every tokenless client.
		if claims == nil && s.memberVerifier != nil {
			if c, valid := verifyToken(bearerToken(r), s.memberVerifier); valid && (c.Exp == 0 || int64(c.Exp) > nowUnix()) {
				claims = &c
			}
		}
		if claims != nil {
			r = r.WithContext(context.WithValue(r.Context(), claimsCtxKey{}, claims))
		}
		// Tenancy: the tenant is the verified token's (tenancyVerifier
		// admitted only a configured tid under one of its keys). Nothing in
		// the request but the token can name it.
		if s.tenancy != nil {
			t := (*tenantConf)(nil)
			if claims != nil {
				t = s.tenancy.tenants[claims.Tid]
			}
			if t == nil {
				http.Error(w, "relay requires a valid access token", http.StatusUnauthorized)
				return
			}
			if t.rate != nil {
				if ok, wait := t.rate.allowWait(t.id); !ok {
					tooMany(w, limTenantRate, t.id, wait, "tenant rate limit exceeded")
					return
				}
			}
			countTenantRequest(t.id)
			r = r.WithContext(withTenant(r.Context(), t))
		}
		next.ServeHTTP(w, r)
	})
}

// enforceWrite runs the optional WriteGuard before a workspace write. The open
// relay has no guard → always allowed (content-blind forwarding). Returns false
// (after writing 403) when the guard rejects.
func (s *Server) enforceWrite(w http.ResponseWriter, r *http.Request, workspace string) bool {
	if s.guard == nil {
		return true
	}
	if err := s.guard.CheckWrite(r.Context(), workspace, claimsFrom(r.Context()), r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// enforceRead authorizes a workspace *read* (envelopes / keyring / presence /
// candidates). It requires the same relay access check the write path requires:
// under a token-gated policy (allowlist or signed hrt1) the caller must present
// a valid token — exactly the credential existing clients already attach to
// every GET — and under the open policy (self-host default) reads stay open,
// mirroring content-blind write forwarding. The check is content-blind: it
// inspects only the presented access token, never the body.
//
// The top-level access gate (see gate) already vets every /v1 route, so
// this is the explicit, handler-level read-authorization point — closing S5's
// read half by construction and guarding against a future router refactor that
// might move a read off the gate. Returns false (after writing 401) when the
// access token is missing or invalid.
func (s *Server) enforceRead(w http.ResponseWriter, r *http.Request, workspace string) bool {
	// Per-client read rate (keyed like the write limiter), so one client can't
	// loop the list routes and keep the store busy for everyone else.
	if rateRefused(w, s.readLimiter, clientKey(r), refReadRate, "rate limit exceeded") {
		return false
	}
	if _, ok := s.entitlement.Allow(bearerToken(r), nowUnix()); !ok {
		http.Error(w, "relay requires a valid access token", http.StatusUnauthorized)
		return false
	}
	// ReadGuard seam: nil on the open relay (read-openness unchanged); a downstream
	// build can enforce membership on reads here, mirroring enforceWrite/WriteGuard.
	if s.readGuard != nil {
		if err := s.readGuard.CheckRead(r.Context(), workspace, claimsFrom(r.Context()), r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
	}
	return true
}

// afterWorkspaceWrite fires the optional metering/audit Hook.
func (s *Server) afterWorkspaceWrite(ctx context.Context, workspace string, seq uint64) {
	if s.hooks != nil {
		s.hooks.WorkspaceWritten(ctx, workspace, seq, claimsFrom(ctx))
	}
}

// health is the liveness/readiness probe. It actually round-trips the store
// (not just "return ok") so an orchestrator pulls a wedged or disconnected
// backend out of rotation: 200 "ok" when the store answers, 503 otherwise.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.cachedPing(r.Context()); err != nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// cachedPing round-trips the store but memoizes the result for a short TTL, so a
// flood of health probes can't hammer the backend with a DB round-trip each
// (P3-15). A cold or stale cache does one bounded (2s) ping.
func (s *Server) cachedPing(ctx context.Context) error {
	now := time.Now()
	s.healthMu.Lock()
	if !s.healthChecked.IsZero() && now.Sub(s.healthChecked) < healthPingCacheTTL {
		err := s.healthErr
		s.healthMu.Unlock()
		return err
	}
	s.healthMu.Unlock()

	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := s.store.Ping(pctx)

	s.healthMu.Lock()
	s.healthErr = err
	s.healthChecked = time.Now()
	s.healthMu.Unlock()
	return err
}

// guardMetrics optionally protects /metrics with an ops credential (P3-15). When
// LANGSTROTH_RELAY_METRICS_TOKEN is set, /metrics requires a matching bearer (constant-
// time compared); unset keeps it open for back-compat with existing scrapers.
func (s *Server) guardMetrics(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.metricsToken != "" {
			if !constantTimeEq(sha256hex(bearerToken(r)), s.metricsTokHash) {
				http.Error(w, "metrics authorization required", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// ── Workspace sync handlers ───────────────────────────────────────────────────

// limitWrite applies the per-IP write-path rate limit shared by every
// unauthenticated write (envelopes, keyring, presence, candidates, pairing), so
// no unauth write path is left unbounded (P2-12). Returns false (after writing
// 429) when the caller is over the limit.
func (s *Server) limitWrite(w http.ResponseWriter, r *http.Request) bool {
	return !rateRefused(w, s.pushLimiter, clientKey(r), refWriteRate, "rate limit exceeded")
}

func (s *Server) postEnvelope(w http.ResponseWriter, r *http.Request) {
	if !s.limitWrite(w, r) {
		return
	}
	// Per-(workspace,writer) quota: bound how fast one identity can churn this
	// workspace's retention window so it can't rapidly evict another member's
	// history (P1-6). Content-blind — keyed on the token subject or client
	// IP, never the body.
	id := r.PathValue("id")
	if rateRefused(w, s.wsWriterLimit, id+"|"+writerTag(r.Context(), clientKey(r)), refRoomWriterRate, "workspace write quota exceeded") {
		return
	}
	var body json.RawMessage
	if !readJSON(w, r, &body) {
		return
	}
	if !s.enforceWrite(w, r, id) {
		return
	}
	seq, err := s.store.AppendEnvelope(r.Context(), id, body, dedupKeyFor(r, body))
	if storeErr(w, err) {
		return
	}
	s.afterWorkspaceWrite(r.Context(), id, seq)
	writeJSON(w, http.StatusOK, map[string]uint64{"seq": seq})
}

// dedupKeyFor derives the idempotency key for an envelope push. It stays content-
// blind (never inspects plaintext) and backward-compatible with existing clients:
//
//   - An explicit client-supplied id wins (Idempotency-Key, or the hive-native
//     X-Hive-Event-Id), letting a client name the event directly. It is scoped
//     to the writer (token subject, else client address), so one writer
//     can't claim another's key and turn that writer's push into a silent
//     duplicate.
//   - Absent a header, we hash the opaque sealed body (sha256). A re-push resends
//     byte-identical ciphertext, so the hash dedups it with no client change. Two
//     genuinely-distinct events can't collide in practice: every sealed body
//     carries a unique event id + random nonce inside the ciphertext the relay
//     can't see, so distinct events always have distinct bytes.
//
// The result is opaque to the store — a hash or an id, never event content.
func dedupKeyFor(r *http.Request, body json.RawMessage) string {
	k := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if k == "" {
		k = strings.TrimSpace(r.Header.Get("X-Hive-Event-Id"))
	}
	if k != "" {
		return scopedDedupKey(writerTag(r.Context(), clientKey(r)), k)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// maxDedupKeyLen bounds a stored client-chosen idempotency key. The stored
// form is a fixed-length hash of (writer, key), so a header can't attach up to
// the 1 MB header limit to every envelope outside the body cap.
const maxDedupKeyLen = 128

func scopedDedupKey(writer, k string) string {
	return "wk-sha256:" + sha256hex(writer+"\x00"+k)
}

func (s *Server) listEnvelopes(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRead(w, r, r.PathValue("id")) {
		return
	}
	after := afterParam(r)
	rows, more, err := pageEnvelopes(r.Context(), s.store, r.PathValue("id"), after, limitParam(r), envelopePageMaxBytes)
	if storeErr(w, err) {
		return
	}
	next := after
	if len(rows) > 0 {
		next = rows[len(rows)-1].Seq
	}
	w.Header().Set(headerEnvelopesNext, strconv.FormatUint(next, 10))
	if more {
		w.Header().Set(headerEnvelopesMore, "true")
	}
	writeJSON(w, http.StatusOK, rows)
}

// sseKeepAlive is the idle heartbeat interval. A comment line every ~25s keeps
// proxies and load balancers from culling an otherwise-silent stream.
const sseKeepAlive = 25 * time.Second

// streamEvents is the Server-Sent Events push endpoint that replaces the 3s
// poll (ROADMAP step 1). It is a content-blind *nudge* channel: on every new
// envelope appended to this workspace it emits `data: {"seq":N}` so the client
// wakes and pulls (over the existing GET /envelopes cursor). It never streams
// envelope bodies — the relay stays content-blind.
//
// Read-authorized exactly like the other workspace reads (enforceRead), so
// under a token-gated policy an unauthenticated connect is 401 and under the
// open policy it stays open.
func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.enforceRead(w, r, id) {
		return
	}
	// Cap concurrent streams so an attacker can't exhaust goroutines/FDs by
	// opening SSE connections without bound. The slot is held for the stream's
	// lifetime and released on return (client disconnect / context cancel).
	release, ok := s.sseLimiter.acquire()
	if !ok {
		http.Error(w, "too many concurrent streams", http.StatusServiceUnavailable)
		return
	}
	defer release()
	// And per client (the token subject when there is one, else the
	// client address), so one client can't hold every slot.
	releaseClient, ok := s.sseClient.acquire(writerTag(r.Context(), clientKey(r)))
	if !ok {
		refuse(w, http.StatusTooManyRequests, refSSEStreams, "too many concurrent streams from this client", retrySSE)
		return
	}
	defer releaseClient()

	// CRITICAL: the global http.Server.WriteTimeout (30s) would sever this
	// long-lived stream mid-flight. Clear the per-connection write (and read)
	// deadline so only the client disconnect / request context ends it. This
	// touches ONLY this connection — the server-wide timeouts that protect the
	// poll/JSON routes are unchanged. (SetWriteDeadline is unsupported on some
	// ResponseWriters, e.g. httptest.ResponseRecorder; ignore that error.)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // ask nginx et al. not to buffer the stream
	w.WriteHeader(http.StatusOK)

	// Announce liveness immediately so the client knows the stream is open.
	if _, err := io.WriteString(w, ": connected\n\n"); err != nil {
		return
	}
	_ = rc.Flush()

	// Subscribe before reading the head seq, so an append racing this setup is
	// either counted in latestSeq or delivered on the channel (never lost).
	var ch <-chan uint64
	if ns, ok := s.store.(notifyStore); ok {
		var unsubscribe func()
		ch, unsubscribe = ns.subscribeWorkspace(id)
		defer unsubscribe()
		if seq, err := ns.latestSeq(r.Context(), id); err == nil {
			if _, err := fmt.Fprintf(w, "data: {\"seq\":%d}\n\n", seq); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}

	keepAlive := time.NewTicker(sseKeepAlive)
	defer keepAlive.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done(): // client disconnected — close cleanly
			return
		case seq := <-ch: // new append (ch is nil if the store can't notify → only keep-alives)
			if _, err := fmt.Fprintf(w, "data: {\"seq\":%d}\n\n", seq); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		case <-keepAlive.C:
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

type deviceBlobReq struct {
	DeviceID string          `json:"device_id"`
	Data     json.RawMessage `json:"data"`
}

func (s *Server) publishCandidates(w http.ResponseWriter, r *http.Request) {
	if !s.limitWrite(w, r) {
		return
	}
	var b deviceBlobReq
	if !readJSON(w, r, &b) {
		return
	}
	if len(b.DeviceID) > maxDeviceIDLen {
		http.Error(w, "device_id too long", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	if !s.enforceWrite(w, r, id) {
		return
	}
	if storeErr(w, s.store.PutCandidate(r.Context(), id, b.DeviceID, b.Data)) {
		return
	}
	writeJSON(w, http.StatusOK, okResp())
}

func (s *Server) listCandidates(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRead(w, r, r.PathValue("id")) {
		return
	}
	m, err := s.candidates(r.Context(), r.PathValue("id"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) publishPresence(w http.ResponseWriter, r *http.Request) {
	if !s.limitWrite(w, r) {
		return
	}
	var b deviceBlobReq
	if !readJSON(w, r, &b) {
		return
	}
	if len(b.DeviceID) > maxDeviceIDLen {
		http.Error(w, "device_id too long", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	if !s.enforceWrite(w, r, id) {
		return
	}
	if storeErr(w, s.store.PutPresence(r.Context(), id, b.DeviceID, b.Data)) {
		return
	}
	writeJSON(w, http.StatusOK, okResp())
}

func (s *Server) listPresence(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRead(w, r, r.PathValue("id")) {
		return
	}
	m, err := s.presenceBlobs(r.Context(), r.PathValue("id"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) publishKeyring(w http.ResponseWriter, r *http.Request) {
	if !s.limitWrite(w, r) {
		return
	}
	var body json.RawMessage
	if !readJSON(w, r, &body) {
		return
	}
	if s.maxRotationBytes > 0 && len(body) > s.maxRotationBytes {
		http.Error(w, "key rotation too large", http.StatusRequestEntityTooLarge)
		return
	}
	id := r.PathValue("id")
	if !s.enforceWrite(w, r, id) {
		return
	}
	if storeErr(w, s.store.AppendKeyRotation(r.Context(), id, body)) {
		return
	}
	s.afterWorkspaceWrite(r.Context(), id, 0)
	writeJSON(w, http.StatusOK, okResp())
}

func (s *Server) listKeyring(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRead(w, r, r.PathValue("id")) {
		return
	}
	rows, err := s.keyRotations(r.Context(), r.PathValue("id"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// ── Pairing handlers (ephemeral, instance-local) ──────────────────────────────

type pairReq struct {
	Payload string  `json:"payload"`
	TTLSecs *uint64 `json:"ttl_secs"`
}

func (s *Server) createPairing(w http.ResponseWriter, r *http.Request) {
	if !s.limitWrite(w, r) {
		return
	}
	var req pairReq
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Payload) == "" {
		http.Error(w, "empty payload", http.StatusBadRequest)
		return
	}
	if len(req.Payload) > maxPairPayload {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if msg := pairPayloadError(req.Payload); msg != "" {
		http.Error(w, msg, http.StatusUnprocessableEntity)
		return
	}
	ttl := uint64(defaultPairTTL)
	if req.TTLSecs != nil {
		ttl = *req.TTLSecs
	}
	if ttl < 30 {
		ttl = 30
	}
	if ttl > maxPairTTL {
		ttl = maxPairTTL
	}

	s.pairMu.Lock()
	s.sweepPairingsLocked(time.Now())
	// Cap live pairing codes so an attacker can't exhaust memory by spraying
	// creates (P2-12). Checked after pruning expired entries so only genuinely
	// live codes count against the cap.
	if s.maxPairings > 0 && len(s.pairings) >= s.maxPairings {
		s.pairMu.Unlock()
		countLimit(limPairings, tenantID(r.Context()))
		http.Error(w, "too many live pairings", http.StatusServiceUnavailable)
		return
	}
	// Tenancy: codes live in the caller's tenant (drawn and looked up there
	// only), and each tenant has its own cap on live codes.
	tenant := tenantID(r.Context())
	if t := tenantFrom(r.Context()); t != nil && t.limits.MaxPairings > 0 && s.pairCount[tenant] >= t.limits.MaxPairings {
		s.pairMu.Unlock()
		countLimit(limPairings, tenant)
		http.Error(w, "too many live pairings", http.StatusServiceUnavailable)
		return
	}
	if s.maxPairingBytes > 0 && s.pairBytes+int64(len(req.Payload)) > s.maxPairingBytes {
		s.pairMu.Unlock()
		countLimit(limPairings, tenant)
		http.Error(w, "too many live pairings", http.StatusServiceUnavailable)
		return
	}
	client, c48 := clientKey(r), slash48Key(r)
	if s.maxPairingsPerClient > 0 && (s.pairClient[client] >= s.maxPairingsPerClient ||
		(c48 != "" && s.pairSlash48[c48] >= s.maxPairingsPerClient*pairCodesSlash48Factor)) {
		s.pairMu.Unlock()
		countLimit(limPairings, tenant)
		refuse(w, http.StatusTooManyRequests, refPairCodes, "too many live pairing codes from this client", retryPairCodes)
		return
	}
	var code string
	for {
		code = newPairCode()
		if _, exists := s.pairings[tenantKey(r.Context(), code)]; !exists {
			break
		}
	}
	s.pairings[tenantKey(r.Context(), code)] = pairing{payload: req.Payload, expiresAt: time.Now().Add(time.Duration(ttl) * time.Second), tenant: tenant,
		client: client, slash48: c48}
	s.pairCount[tenant]++
	s.pairClient[client]++
	if c48 != "" {
		s.pairSlash48[c48]++
	}
	s.pairBytes += int64(len(req.Payload))
	s.pairMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expires_in": ttl})
}

func (s *Server) resolvePairing(w http.ResponseWriter, r *http.Request) {
	code := normalizePairCode(r.PathValue("code"))
	client := clientKey(r)
	now := time.Now()

	s.pairMu.Lock()
	if s.resolveBlockedLocked(client, now) {
		wait := s.pairAttempts[client].resetAt.Sub(now)
		s.pairMu.Unlock()
		refuse(w, http.StatusTooManyRequests, refPairLockout, "too many attempts", wait)
		return
	}
	s.sweepPairingsLocked(now)
	key := tenantKey(r.Context(), code)
	p, ok := s.pairings[key]
	if ok && !p.expiresAt.After(now) {
		ok = false // expired, not yet swept
	}
	if ok {
		// Single-use: the first successful resolve consumes the code, so a
		// code seen over a shoulder or in a log can't be replayed.
		s.deletePairingLocked(key)
	} else {
		s.noteResolveFailureLocked(client, now)
	}
	s.pairMu.Unlock()

	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"payload": p.payload})
}

// sweepPairingsLocked drops expired pairings and rolled-over failure windows,
// at most once per second: a full sweep per request would let anyone hold
// pairMu busy for O(live codes) per cheap request. Lookups check expiry
// themselves. Caller holds pairMu.
func (s *Server) sweepPairingsLocked(now time.Time) {
	if !s.pairSweptAt.IsZero() && now.Sub(s.pairSweptAt) < time.Second {
		return
	}
	s.pairSweptAt = now
	s.prunePairings()
	s.prunePairAttempts(now)
}

// prunePairings drops expired entries. Caller holds pairMu.
func (s *Server) prunePairings() {
	now := time.Now()
	for code, p := range s.pairings {
		if !p.expiresAt.After(now) {
			s.deletePairingLocked(code)
		}
	}
}

// deletePairingLocked drops one code and its tenant's count. Caller holds
// pairMu.
func (s *Server) deletePairingLocked(key string) {
	p, ok := s.pairings[key]
	if !ok {
		return
	}
	delete(s.pairings, key)
	if s.pairCount[p.tenant]--; s.pairCount[p.tenant] <= 0 {
		delete(s.pairCount, p.tenant)
	}
	if s.pairClient[p.client]--; s.pairClient[p.client] <= 0 {
		delete(s.pairClient, p.client)
	}
	if p.slash48 != "" {
		if s.pairSlash48[p.slash48]--; s.pairSlash48[p.slash48] <= 0 {
			delete(s.pairSlash48, p.slash48)
		}
	}
	s.pairBytes -= int64(len(p.payload))
}

// prunePairAttempts drops clients whose failure window has rolled over, so the
// attempt map can't grow without bound. Caller holds pairMu.
func (s *Server) prunePairAttempts(now time.Time) {
	for client, a := range s.pairAttempts {
		if now.After(a.resetAt) {
			delete(s.pairAttempts, client)
		}
	}
}

// resolveBlockedLocked reports whether client has exhausted its resolve budget
// for the current window. Caller holds pairMu.
func (s *Server) resolveBlockedLocked(client string, now time.Time) bool {
	a := s.pairAttempts[client]
	return a != nil && !now.After(a.resetAt) && a.failures >= maxResolveFailures
}

// noteResolveFailureLocked records one failed guess for client, opening a fresh
// window if none is active. Caller holds pairMu.
func (s *Server) noteResolveFailureLocked(client string, now time.Time) {
	a := s.pairAttempts[client]
	if a == nil || now.After(a.resetAt) {
		a = &pairAttempt{resetAt: now.Add(resolveWindow)}
		s.pairAttempts[client] = a
	}
	a.failures++
}

// ── Identity directory handlers ───────────────────────────────────────────────

type directoryRegisterReq struct {
	DeviceID string `json:"device_id"`
	KaPublic string `json:"ka_public"`
}

func (s *Server) directoryRegister(w http.ResponseWriter, r *http.Request) {
	var req directoryRegisterReq
	if !readJSON(w, r, &req) {
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	if storeErr(w, s.store.UpsertDirDevice(r.Context(), user.ID, user.Login, user.Name, strings.TrimSpace(req.DeviceID), strings.TrimSpace(req.KaPublic))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"githubId": user.ID, "login": user.Login})
}

func (s *Server) directoryLookup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireGitHub(w, r); !ok {
		return
	}
	acct, err := s.store.DirAccountByHandle(r.Context(), r.PathValue("handle"))
	if storeErr(w, err) {
		return
	}
	if acct == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	devices := make([]map[string]string, 0, len(acct.Devices))
	for id, pk := range acct.Devices {
		devices = append(devices, map[string]string{"deviceId": id, "kaPublic": pk})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"githubId": acct.GitHubID,
		"login":    acct.Login,
		"name":     acct.Name,
		"devices":  devices,
	})
}

// ── Account registry handlers ─────────────────────────────────────────────────

type accountRegisterReq struct {
	DeviceID string  `json:"deviceId"`
	NodeID   *string `json:"nodeId"`
	Label    *string `json:"label"`
}

func (s *Server) accountRegister(w http.ResponseWriter, r *http.Request) {
	var req accountRegisterReq
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	key, err := s.store.RegisterAccountDevice(r.Context(), user.ID, user.Login, strings.TrimSpace(req.DeviceID),
		nonEmpty(req.NodeID), nonEmpty(req.Label), nowUnix())
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accountId": key, "githubId": user.ID, "login": user.Login})
}

type accountHeartbeatReq struct {
	DeviceID string `json:"deviceId"`
}

func (s *Server) accountHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req accountHeartbeatReq
	if !readJSON(w, r, &req) {
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	known, err := s.store.HeartbeatDevice(r.Context(), user.ID, strings.TrimSpace(req.DeviceID), nowUnix())
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": known})
}

func (s *Server) accountInbox(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	rows, err := s.store.AccountInboxAfter(r.Context(), accountKey(user.ID), afterParam(r))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// workspaceInviteBody delivers a client-sealed workspace invite to another
// user's account inbox. `Invite` is opaque to the relay (the client seals the
// `hivews1:` code — which carries the workspace key — to the recipient's
// key-agreement key), so the relay stays content-blind: it only routes the
// envelope to the target account, exactly like a friend request.
type workspaceInviteBody struct {
	ToLogin string          `json:"toLogin"`
	Invite  json.RawMessage `json:"invite"`
}

func (s *Server) accountInviteCreate(w http.ResponseWriter, r *http.Request) {
	var body workspaceInviteBody
	if !readJSON(w, r, &body) {
		return
	}
	user, fromAccount, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	toLogin := strings.TrimPrefix(strings.TrimSpace(body.ToLogin), "@")
	if toLogin == "" || len(body.Invite) == 0 {
		http.Error(w, "toLogin and invite are required", http.StatusBadRequest)
		return
	}
	// Per-(sender,recipient) invite rate limit so one account can't flood another's
	// inbox with workspace invites (P1-7). Generous burst (default 10) then a slow
	// sustained rate; keyed on the verified sender + target handle.
	if rateRefused(w, s.inviteLimiter, fromAccount+"->"+lower(toLogin), refRateLimited, "too many invites to this user") {
		return
	}
	toAccount, found, err := s.store.AccountKeyForLogin(r.Context(), toLogin)
	if storeErr(w, err) {
		return
	}
	if !found {
		http.Error(w, "user hasn't joined Hive", http.StatusNotFound)
		return
	}
	// Optional stronger control (off by default to preserve open-relay behavior):
	// require an existing friend relationship before an invite is delivered, so
	// invites can only reach people the sender already knows (P1-7). Enabled via
	// LANGSTROTH_RELAY_INVITE_REQUIRE_FRIEND=1.
	if envBool("LANGSTROTH_RELAY_INVITE_REQUIRE_FRIEND") {
		if ok, err := s.store.AreFriends(r.Context(), fromAccount, toAccount); storeErr(w, err) {
			return
		} else if !ok {
			http.Error(w, "must be friends to send an invite", http.StatusForbidden)
			return
		}
	}
	event := mustJSON(map[string]any{
		"kind":      "workspaceInvite",
		"fromLogin": user.Login,
		"invite":    body.Invite,
	})
	if _, err := s.store.PushAccountEvent(r.Context(), toAccount, event); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "delivered"})
}

func (s *Server) accountDevices(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	rows, err := s.store.AccountDevices(r.Context(), accountKey(user.ID))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

type visibilityBody struct {
	AppearOffline bool `json:"appearOffline"`
}

func (s *Server) accountVisibility(w http.ResponseWriter, r *http.Request) {
	var body visibilityBody
	if !readJSON(w, r, &body) {
		return
	}
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return
	}
	if storeErr(w, s.store.SetVisibility(r.Context(), user.ID, body.AppearOffline)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"appearOffline": body.AppearOffline})
}

// ── Friend handlers ───────────────────────────────────────────────────────────

type friendRequestBody struct {
	ToLogin string `json:"toLogin"`
}

func (s *Server) friendRequestCreate(w http.ResponseWriter, r *http.Request) {
	var body friendRequestBody
	if !readJSON(w, r, &body) {
		return
	}
	user, fromAccount, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	toLogin := strings.TrimPrefix(strings.TrimSpace(body.ToLogin), "@")
	toAccount, found, err := s.store.AccountKeyForLogin(r.Context(), toLogin)
	if storeErr(w, err) {
		return
	}
	if !found {
		http.Error(w, "user hasn't joined Hive", http.StatusNotFound)
		return
	}
	req, err := s.store.CreateFriendRequest(r.Context(), fromAccount, user.Login, toAccount, toLogin, nowUnix(), s.friendCap)
	if friendErr(w, err) {
		return
	}
	if _, err := s.store.PushAccountEvent(r.Context(), toAccount, req.requestEvent()); storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"requestId": req.ID, "state": "pending"})
}

func (s *Server) friendRequestAccept(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	req, err := s.store.AcceptFriendRequest(r.Context(), r.PathValue("id"), account, s.friendCap)
	if friendErr(w, err) {
		return
	}
	ev := req.resolvedEvent()
	_, _ = s.store.PushAccountEvent(r.Context(), req.FromAccount, ev)
	_, _ = s.store.PushAccountEvent(r.Context(), req.ToAccount, ev)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": "accepted"})
}

func (s *Server) friendRequestReject(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	req, err := s.store.CloseFriendRequest(r.Context(), r.PathValue("id"), account)
	if friendErr(w, err) {
		return
	}
	ev := req.resolvedEvent()
	_, _ = s.store.PushAccountEvent(r.Context(), req.FromAccount, ev)
	_, _ = s.store.PushAccountEvent(r.Context(), req.ToAccount, ev)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) friendsList(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	friends, err := s.store.ListFriends(r.Context(), account)
	if storeErr(w, err) {
		return
	}
	out := make([]map[string]string, 0, len(friends))
	for _, f := range friends {
		out = append(out, map[string]string{"accountId": f.AccountKey, "login": f.Login})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) friendRequestsList(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	reqs, err := s.store.IncomingRequests(r.Context(), account, nowUnix())
	if storeErr(w, err) {
		return
	}
	out := make([]map[string]any, 0, len(reqs))
	for _, rq := range reqs {
		out = append(out, map[string]any{
			"requestId":   rq.ID,
			"fromAccount": rq.FromAccount,
			"fromLogin":   rq.FromLogin,
			"createdAt":   rq.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) friendsPresence(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	pres, err := s.store.FriendPresence(r.Context(), account, nowUnix())
	if storeErr(w, err) {
		return
	}
	out := make([]map[string]string, 0, len(pres))
	for _, p := range pres {
		out = append(out, map[string]string{"accountId": p.AccountKey, "login": p.Login, "presence": p.Presence})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) friendDevicesList(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	rows, friends, err := s.store.FriendDevices(r.Context(), account, r.PathValue("account"))
	if storeErr(w, err) {
		return
	}
	if !friends {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) friendRemove(w http.ResponseWriter, r *http.Request) {
	_, account, ok := s.callerAccount(w, r)
	if !ok {
		return
	}
	removed, err := s.store.RemoveFriend(r.Context(), account, r.PathValue("account"))
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": removed})
}

// ── Auth + helpers ────────────────────────────────────────────────────────────

type githubUser struct {
	ID    uint64  `json:"id"`
	Login string  `json:"login"`
	Name  *string `json:"name"`
}

// requireGitHub verifies the caller's GitHub token and returns the user, or
// writes 401.
func (s *Server) requireGitHub(w http.ResponseWriter, r *http.Request) (*githubUser, bool) {
	token := githubTokenHeader(r)
	if token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	// Per-IP limit on the GitHub-authenticated routes (directory / account /
	// friends) so a flood can't be amplified into one outbound api.github.com call
	// per request, and to throttle bulk directory / membership enumeration (P1-8,
	// P2-14). Generous (default 30/s, burst 120); env-tunable.
	if rateRefused(w, s.ghLimiter, clientKey(r), refRateLimited, "rate limit exceeded") {
		return nil, false
	}
	user, err := s.verifyCached(r.Context(), token)
	if err != nil || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return user, true
}

// verifyCached wraps s.verify with a token-hash-keyed identity cache and an
// upfront plausibility screen, so repeated (or junk) tokens don't each trigger an
// outbound verification (P1-8). Transient verify errors are surfaced (never
// cached); a verified-invalid token is cached as a short-lived negative so a
// junk-token replay still can't amplify.
func (s *Server) verifyCached(ctx context.Context, token string) (*githubUser, error) {
	if !plausibleGitHubToken(token) {
		return nil, nil // obviously-malformed → unauthorized without any outbound call
	}
	if s.ghCache == nil {
		return s.verify(ctx, token)
	}
	h := sha256hex(token)
	now := time.Now()
	if user, negative, hit := s.ghCache.get(h, now); hit {
		if negative {
			return nil, nil
		}
		return user, nil
	}
	user, err := s.verify(ctx, token)
	if err != nil {
		return nil, err // transient (network / decode) — don't cache
	}
	s.ghCache.put(h, user, now) // user may be nil → cached negative
	return user, nil
}

// callerAccount resolves the authenticated caller's identity → account key.
func (s *Server) callerAccount(w http.ResponseWriter, r *http.Request) (*githubUser, string, bool) {
	user, ok := s.requireGitHub(w, r)
	if !ok {
		return nil, "", false
	}
	return user, accountKey(user.ID), true
}

// verifyGitHub authenticates a GitHub token by fetching the user it belongs to.
func (s *Server) verifyGitHub(ctx context.Context, token string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "langstroth-relay")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}
	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	t := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if h == t { // no "Bearer " prefix was present
		return ""
	}
	return t
}

// githubTokenHeader returns the caller's GitHub token from the explicit GitHub
// token header (X-Ligus-Github-Token, or the X-Hive-Github-Token that current
// clients send). It never falls back to the Authorization bearer: that header
// carries the relay access token, which must never be forwarded to
// api.github.com. The operator of a relay can still see GitHub tokens sent in
// these headers (they're verified server-side); see docs/reference.md "GitHub social routes".
func githubTokenHeader(r *http.Request) string {
	if t := strings.TrimSpace(r.Header.Get("x-ligus-github-token")); t != "" {
		return t
	}
	return strings.TrimSpace(r.Header.Get("x-hive-github-token"))
}

func afterParam(r *http.Request) uint64 {
	n, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	return n
}

func nonEmpty(s *string) *string {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}
	return s
}

func okResp() map[string]bool { return map[string]bool{"ok": true} }

// readJSON decodes the request body, capping it at maxRequestBodyBytes so a
// hostile client can't stream a multi-GB body to exhaust memory. Over the cap →
// 413; malformed JSON → 400; either writes the response and returns false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	// Marshal before writing the status so a serialization failure becomes a
	// visible 500 — not a silent empty 200. (Streaming Encode writes the header
	// first, so an error mid-encode leaves a truncated body with a success code,
	// which is exactly how a corrupted payload can masquerade as "empty".)
	buf, err := json.Marshal(v)
	if err != nil {
		slog.Error("writeJSON: marshal failed", "error", err)
		http.Error(w, `{"error":"internal encoding error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

// storeErr writes the response for a store error (507/429 for a quota,
// else 500) and returns true if there was one.
func storeErr(w http.ResponseWriter, err error) bool {
	if status, code, msg, ok := quotaStatus(err); ok {
		refuse(w, status, code, msg, quotaRetry(code))
		return true
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}
	return false
}

// friendErr maps a friend-graph refusal to an HTTP status (CapReached → 402 so
// the client can surface an upgrade prompt). Returns true if it handled an error.
func friendErr(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrSelfRequest):
		status = http.StatusBadRequest
	case errors.Is(err, ErrAlreadyFriends), errors.Is(err, ErrNotPending):
		status = http.StatusConflict
	case errors.Is(err, ErrCapReached):
		status = http.StatusPaymentRequired
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrNotYours):
		status = http.StatusForbidden
	case errors.Is(err, ErrTooManyPending):
		status = http.StatusTooManyRequests
	}
	if status == http.StatusTooManyRequests {
		refuse(w, status, refTooManyPending, err.Error(), time.Minute)
		return true
	}
	if status == http.StatusInternalServerError {
		// Not one of the friend graph's own refusals: a store error, which may
		// carry driver or connection details. Log it; don't echo it.
		slog.Error("friend store error", "error", err)
		http.Error(w, "internal error", status)
		return true
	}
	http.Error(w, err.Error(), status)
	return true
}

func randomPairCode() string {
	var b [codeLen]byte
	randRead(b[:])
	out := make([]byte, codeLen)
	for i := range b {
		out[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(out)
}

func normalizePairCode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(b.String())
}
