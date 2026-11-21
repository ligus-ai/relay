package langstrothauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Server is a running langstroth-auth instance.
type Server struct {
	cfg       *Config
	store     Store
	key       ed25519.PrivateKey
	pubHex    string
	providers map[string]*provider
	now       func() time.Time
	audit     *auditLog
	flows     *flowState
	nonceKey  []byte

	adminTokenHash string

	publicLimit *rateLimiter
	codeLimit   *rateLimiter // device user-code attempts per IP
	scimLimit   *rateLimiter // SCIM requests per tenant+IP
	authFail    *rateLimiter // failed bearer attempts (SCIM, admin) per IP
}

// Options are the injectable parts of a Server (tests swap them).
type Options struct {
	Config *Config
	Store  Store
	Key    ed25519.PrivateKey
	// AdminToken enables the admin API; empty disables it.
	AdminToken string
	// HTTPClient talks to the IdPs (nil = 10s-timeout default).
	HTTPClient *http.Client
	// Now overrides the clock (nil = time.Now).
	Now func() time.Time
	// AuditWriter receives the JSON audit log (nil = stderr).
	AuditWriter io.Writer
}

// New builds a Server and seeds the configured grants into the store.
func New(ctx context.Context, o Options) (*Server, error) {
	if o.Config == nil || o.Store == nil || o.Key == nil {
		return nil, fmt.Errorf("langstroth-auth: config, store and key are required")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, 32)
	nonceKey := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonceKey); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:         o.Config,
		store:       o.Store,
		key:         o.Key,
		pubHex:      hex.EncodeToString(o.Key.Public().(ed25519.PublicKey)),
		providers:   map[string]*provider{},
		now:         now,
		audit:       newAuditLog(o.AuditWriter, salt),
		flows:       newFlowState(),
		nonceKey:    nonceKey,
		publicLimit: newRateLimiter(o.Config.RatePerIP, o.Config.BurstPerIP, now),
		codeLimit:   newRateLimiter(10.0/60, 10, now),
		scimLimit:   newRateLimiter(50, 200, now),
		authFail:    newRateLimiter(1, 10, now),
	}
	if o.AdminToken != "" {
		if len(o.AdminToken) < 32 {
			return nil, fmt.Errorf("langstroth-auth: the admin token must be at least 32 characters")
		}
		s.adminTokenHash = sha256Hex(o.AdminToken)
	}
	for i := range o.Config.Tenants {
		t := &o.Config.Tenants[i]
		s.providers[t.ID] = newProvider(&t.OIDC, t.clientSecret, o.Config.ClockSkew.D(), o.HTTPClient, now)
		for g, ws := range t.Grants {
			if err := s.store.SetGrant(ctx, t.ID, g, ws); err != nil {
				return nil, fmt.Errorf("seed grants for %s: %w", t.ID, err)
			}
		}
	}
	return s, nil
}

// PublicKeyHex is the issuer public key to set as LANGSTROTH_RELAY_TOKEN_PUBKEY.
func (s *Server) PublicKeyHex() string { return s.pubHex }

// Handler serves the public endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	t := func(h func(http.ResponseWriter, *http.Request, *TenantConfig)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tc := s.cfg.tenant(r.PathValue("tenant"))
			if tc == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			h(w, r, tc)
		}
	}
	mux.HandleFunc("GET /t/{tenant}/.well-known/ligus-auth", t(s.handleMetadata))
	mux.HandleFunc("GET /t/{tenant}/authorize", t(s.limited(s.handleAuthorize)))
	mux.HandleFunc("GET /t/{tenant}/callback", t(s.limited(s.handleCallback)))
	mux.HandleFunc("POST /t/{tenant}/device_authorization", t(s.limited(s.handleDeviceAuthorization)))
	mux.HandleFunc("GET /t/{tenant}/device", t(s.limited(s.handleDevicePage)))
	mux.HandleFunc("POST /t/{tenant}/device", t(s.limited(s.handleDeviceSubmit)))
	mux.HandleFunc("POST /t/{tenant}/device/confirm", t(s.limited(s.handleDeviceConfirm)))
	mux.HandleFunc("POST /t/{tenant}/token", t(s.limited(s.handleToken)))
	mux.HandleFunc("POST /t/{tenant}/revoke", t(s.limited(s.handleRevoke)))
	mux.HandleFunc("/t/{tenant}/scim/v2/{rest...}", t(s.handleSCIM))
	return securityHeaders(mux)
}

// AdminHandler serves the operator API (bind it to a private listener).
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	s.registerAdmin(mux)
	return securityHeaders(mux)
}

func (s *Server) limited(h func(http.ResponseWriter, *http.Request, *TenantConfig)) func(http.ResponseWriter, *http.Request, *TenantConfig) {
	return func(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
		if !s.publicLimit.allow(s.limitKey(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h(w, r, t)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// issuerURL is the tenant's langstroth-auth issuer (also returned as "iss" on
// redirects, RFC 9207).
func (s *Server) issuerURL(t *TenantConfig) string { return s.cfg.PublicURL + "/t/" + t.ID }

func (s *Server) callbackURL(t *TenantConfig) string { return s.issuerURL(t) + "/callback" }

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request, t *TenantConfig) {
	base := s.issuerURL(t)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                        base,
		"tenant":                        t.ID,
		"authorization_endpoint":        base + "/authorize",
		"token_endpoint":                base + "/token",
		"device_authorization_endpoint": base + "/device_authorization",
		"device_verification_uri":       base + "/device",
		"scim_base":                     base + "/scim/v2",
		"token_format":                  "hrt1",
		"token_pubkey":                  s.pubHex,
		"access_ttl":                    int(s.cfg.AccessTTL.D().Seconds()),
		"code_challenge_methods":        []string{"S256"},
		"device_proof":                  "ed25519",
		"revocation_endpoint":           base + "/revoke",
	})
}

// clientIP is the request's client address. X-Forwarded-For is read only
// from a configured trusted proxy, taking the rightmost untrusted hop.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !s.trusted(addr) {
		return addr.String()
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !s.trusted(a) {
			return a.String()
		}
	}
	return addr.String()
}

// limitKey is the rate-limit key for a request: the client address, with
// IPv6 reduced to its /64 (a host is normally handed a whole /64, so
// per-address buckets would be free to multiply), as the relay does.
func (s *Server) limitKey(r *http.Request) string {
	ip := s.clientIP(r)
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}

func (s *Server) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.cfg.trustedNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// rateLimiter is a per-key token bucket with periodic eviction of idle keys.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	now    func() time.Time
	seen   map[string]*bucket
	lastGC time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst float64, now func() time.Time) *rateLimiter {
	return &rateLimiter{rate: rate, burst: burst, now: now, seen: map[string]*bucket{}, lastGC: now()}
}

func (l *rateLimiter) allow(key string) bool {
	if l.rate <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.seen {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.seen, k)
			}
		}
		l.lastGC = now
	}
	b := l.seen[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
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

// auditLog writes one JSON line per security-relevant event. It never
// records names, emails or raw IdP subjects: users appear as their opaque
// langstroth-auth id or the hashed uid, devices and IPs as salted hashes.
type auditLog struct {
	log  *slog.Logger
	salt []byte
}

func newAuditLog(w io.Writer, salt []byte) *auditLog {
	if w == nil {
		w = osStderr()
	}
	return &auditLog{log: slog.New(slog.NewJSONHandler(w, nil)), salt: salt}
}

// event records name for tenant. attrs are key/value pairs; keys "ip" and
// "did" are hashed before writing.
func (a *auditLog) event(name, tenant string, attrs ...any) {
	out := []any{"audit", name, "tenant", tenant}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		v := attrs[i+1]
		if k == "ip" || k == "did" {
			sv, _ := v.(string)
			v = hashID(a.salt, sv)
		}
		out = append(out, k, v)
	}
	a.log.Info("langstroth-auth", out...)
}
