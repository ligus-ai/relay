package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Tenancy (docs/tenancy.md): one process serving several organisations that
// don't trust each other. Off unless LANGSTROTH_RELAY_TENANCY (normally from
// LANGSTROTH_RELAY_TENANCY_FILE) holds a tenancy config. The tenant comes
// only from a verified token; every room, contact, pairing code and tunnel
// host is kept under it.

// tenantIDRe is langstroth-auth's tenant id rule. No '/', so "<tenant>/<id>"
// storage keys split one way only.
var tenantIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// tenantAdminCap in a tenant's token admits the /v1/tenant routes.
const tenantAdminCap = "tenant_admin"

// TenantLimits are one tenant's quotas. 0 = no tenant limit.
type TenantLimits struct {
	MaxBytes         int64   `json:"max_bytes"`
	MaxRooms         int64   `json:"max_rooms"`
	RoomMaxBytes     int64   `json:"room_max_bytes"`
	RoomMaxEnvelopes int64   `json:"room_max_envelopes"`
	Rate             float64 `json:"rate"`
	Burst            float64 `json:"burst"`
	MaxPairings      int     `json:"max_pairings"`
	MaxHosts         int64   `json:"max_hosts"`
	PushPerDay       int     `json:"push_per_day"`
	BlobMaxBytes     int64   `json:"blob_max_bytes"`
	BlobMaxCount     int64   `json:"blob_max_count"`
	BlobRoomMaxBytes int64   `json:"blob_room_max_bytes"`
	BlobRoomMaxCount int64   `json:"blob_room_max_count"`
}

// overlay returns l with every non-zero field of o applied.
func (l TenantLimits) overlay(o *TenantLimits) TenantLimits {
	if o == nil {
		return l
	}
	set := func(dst *int64, v int64) {
		if v != 0 {
			*dst = v
		}
	}
	set(&l.MaxBytes, o.MaxBytes)
	set(&l.MaxRooms, o.MaxRooms)
	set(&l.RoomMaxBytes, o.RoomMaxBytes)
	set(&l.RoomMaxEnvelopes, o.RoomMaxEnvelopes)
	set(&l.MaxHosts, o.MaxHosts)
	set(&l.BlobMaxBytes, o.BlobMaxBytes)
	set(&l.BlobMaxCount, o.BlobMaxCount)
	set(&l.BlobRoomMaxBytes, o.BlobRoomMaxBytes)
	set(&l.BlobRoomMaxCount, o.BlobRoomMaxCount)
	if o.Rate != 0 {
		l.Rate = o.Rate
	}
	if o.Burst != 0 {
		l.Burst = o.Burst
	}
	if o.MaxPairings != 0 {
		l.MaxPairings = o.MaxPairings
	}
	if o.PushPerDay != 0 {
		l.PushPerDay = o.PushPerDay
	}
	return l
}

func (l TenantLimits) validate() error {
	if l.MaxBytes < 0 || l.MaxRooms < 0 || l.RoomMaxBytes < 0 || l.RoomMaxEnvelopes < 0 ||
		l.Rate < 0 || l.Burst < 0 || l.MaxPairings < 0 || l.MaxHosts < 0 || l.PushPerDay < 0 ||
		l.BlobMaxBytes < 0 || l.BlobMaxCount < 0 || l.BlobRoomMaxBytes < 0 || l.BlobRoomMaxCount < 0 {
		return errors.New("limits must not be negative")
	}
	if l.Rate > 0 && l.Burst < 1 {
		return errors.New("a rate needs a burst of at least 1")
	}
	return nil
}

type tenancyFile struct {
	Defaults TenantLimits      `json:"defaults"`
	Tenants  []tenantFileEntry `json:"tenants"`
}

type tenantFileEntry struct {
	ID               string        `json:"id"`
	IssuerPubkeys    []string      `json:"issuer_pubkeys"`
	SharedIssuer     *bool         `json:"shared_issuer"`
	AdminTokenSHA256 string        `json:"admin_token_sha256"`
	Limits           *TenantLimits `json:"limits"`
}

// tenantConf is one tenant after parsing.
type tenantConf struct {
	id           string
	keys         []ed25519.PublicKey
	sharedIssuer bool
	adminHash    string // hex sha256, "" = no static admin token
	limits       TenantLimits
	rate         *ipRateLimiter // per-tenant request rate (nil = off)
}

// tenancyConf is the parsed tenancy config.
type tenancyConf struct {
	ids     []string // configured order (metrics labels)
	tenants map[string]*tenantConf
	shared  []ed25519.PublicKey // LANGSTROTH_RELAY_TOKEN_PUBKEY(_NEXT)
}

// tenancyFromEnv parses LANGSTROTH_RELAY_TENANCY. (nil, nil) = tenancy off.
func tenancyFromEnv() (*tenancyConf, error) {
	raw := strings.TrimSpace(getenv("LANGSTROTH_RELAY_TENANCY"))
	if raw == "" {
		if _, set := lookupRelayEnv("LANGSTROTH_RELAY_TENANCY"); set {
			return nil, errors.New("LANGSTROTH_RELAY_TENANCY is set but empty")
		}
		return nil, nil
	}
	var shared []ed25519.PublicKey
	for _, name := range []string{"LANGSTROTH_RELAY_TOKEN_PUBKEY", "LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT"} {
		if v := getenv(name); v != "" {
			k, ok := parsePubkey(v)
			if !ok {
				return nil, fmt.Errorf("%s is not an Ed25519 public key", name)
			}
			shared = append(shared, k)
		}
	}
	tc, err := parseTenancy([]byte(raw), shared)
	if err != nil {
		return nil, fmt.Errorf("LANGSTROTH_RELAY_TENANCY: %w", err)
	}
	if tenantsFromEnv() != nil {
		return nil, errors.New("LANGSTROTH_RELAY_TENANTS and LANGSTROTH_RELAY_TENANCY are both set; tenancy replaces the tenant list, so remove LANGSTROTH_RELAY_TENANTS")
	}
	if getenv("LANGSTROTH_RELAY_ACCESS_TOKENS") != "" {
		return nil, errors.New("LANGSTROTH_RELAY_ACCESS_TOKENS can't be used with LANGSTROTH_RELAY_TENANCY: a static token names no tenant")
	}
	if githubRoutesFromEnv() {
		return nil, errors.New("the GitHub social routes can't be used with LANGSTROTH_RELAY_TENANCY: their namespace is global")
	}
	if strings.TrimSpace(getenv("LANGSTROTH_RELAY_METRICS_TOKEN")) == "" {
		// /metrics is public without it, and with tenancy it names every
		// tenant and its usage.
		return nil, errors.New("LANGSTROTH_RELAY_TENANCY needs LANGSTROTH_RELAY_METRICS_TOKEN: without it /metrics is public and would list every tenant and its usage")
	}
	return tc, nil
}

// tenancyConfigError is the startup check for LANGSTROTH_RELAY_TENANCY.
func tenancyConfigError() error {
	tc, err := tenancyFromEnv()
	if err != nil || tc == nil {
		return err
	}
	slog.Info("tenancy on", "tenants", len(tc.ids))
	return nil
}

// parseTenancy validates a tenancy config against the shared issuer keys.
func parseTenancy(raw []byte, shared []ed25519.PublicKey) (*tenancyConf, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f tenancyFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("not a tenancy config: %w", err)
	}
	if err := f.Defaults.validate(); err != nil {
		return nil, fmt.Errorf("defaults: %w", err)
	}
	if len(f.Tenants) == 0 {
		return nil, errors.New("no tenants")
	}
	tc := &tenancyConf{tenants: map[string]*tenantConf{}, shared: shared}
	keyOwner := map[string]string{}
	for _, k := range shared {
		keyOwner[hex.EncodeToString(k)] = "LANGSTROTH_RELAY_TOKEN_PUBKEY"
	}
	for _, e := range f.Tenants {
		if !tenantIDRe.MatchString(e.ID) {
			return nil, fmt.Errorf("tenant id %q is not [a-z0-9][a-z0-9-]{0,62}", e.ID)
		}
		if tc.tenants[e.ID] != nil {
			return nil, fmt.Errorf("tenant %q is listed twice", e.ID)
		}
		t := &tenantConf{id: e.ID, sharedIssuer: e.SharedIssuer == nil || *e.SharedIssuer}
		for _, ks := range e.IssuerPubkeys {
			k, ok := parsePubkey(ks)
			if !ok {
				return nil, fmt.Errorf("tenant %q: issuer key %q is not an Ed25519 public key", e.ID, ks)
			}
			h := hex.EncodeToString(k)
			if prev, dup := keyOwner[h]; dup {
				return nil, fmt.Errorf("tenant %q: issuer key is also %s's; each key vouches for one tenant", e.ID, prev)
			}
			keyOwner[h] = "tenant " + e.ID
			t.keys = append(t.keys, k)
		}
		if t.sharedIssuer && len(shared) == 0 {
			t.sharedIssuer = false
		}
		if len(t.keys) == 0 && !t.sharedIssuer {
			return nil, fmt.Errorf("tenant %q has no issuer: list issuer_pubkeys, or set LANGSTROTH_RELAY_TOKEN_PUBKEY and leave shared_issuer on", e.ID)
		}
		if a := strings.ToLower(strings.TrimSpace(e.AdminTokenSHA256)); a != "" {
			if len(a) != 64 || !isHex(a) {
				return nil, fmt.Errorf("tenant %q: admin_token_sha256 is not 64 hex characters", e.ID)
			}
			t.adminHash = a
		}
		if e.Limits != nil {
			if err := e.Limits.validate(); err != nil {
				return nil, fmt.Errorf("tenant %q: %w", e.ID, err)
			}
		}
		t.limits = f.Defaults.overlay(e.Limits)
		if t.limits.Rate > 0 {
			t.rate = newIPRateLimiter(t.limits.Rate, t.limits.Burst)
		}
		tc.tenants[e.ID] = t
		tc.ids = append(tc.ids, e.ID)
	}
	return tc, nil
}

// unverifiedTid reads the tid claim of an hrt1 token without checking its
// signature. It only picks which keys to verify with; the tenant is never
// taken from it unless one of that tenant's keys (or the shared key) then
// verifies the token.
func unverifiedTid(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Tid string `json:"tid"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return c.Tid
}

// tenancyVerifier is the access gate in tenancy mode (an EntitlementVerifier):
// it admits only signed tokens whose tid names a configured tenant and whose
// signature verifies under that tenant's own keys or, if it allows, the
// shared issuer key. A token signed by tenant A's key that names tenant B
// matches neither B's keys nor the shared key, so it is refused.
type tenancyVerifier struct{ tc *tenancyConf }

func (v tenancyVerifier) Allow(token string, now int64) (*TokenClaims, bool) {
	c, _, ok := v.tc.verify(token, now)
	return c, ok
}

// verify returns the claims and tenant of an admitted token.
func (tc *tenancyConf) verify(token string, now int64) (*TokenClaims, *tenantConf, bool) {
	t := tc.tenants[unverifiedTid(token)]
	if t == nil {
		return nil, nil, false
	}
	keys := t.keys
	if t.sharedIssuer {
		keys = append(append([]ed25519.PublicKey(nil), t.keys...), tc.shared...)
	}
	for _, k := range keys {
		c, ok := verifyToken(token, k)
		if !ok {
			continue
		}
		if c.IsExpired(now) || c.Tid != t.id {
			return nil, nil, false
		}
		return &c, t, true
	}
	return nil, nil, false
}

// tenantCtxKey carries the caller's verified tenant.
type tenantCtxKey struct{}

func withTenant(ctx context.Context, t *tenantConf) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, t)
}

func tenantFrom(ctx context.Context) *tenantConf {
	t, _ := ctx.Value(tenantCtxKey{}).(*tenantConf)
	return t
}

// tenantID is the caller's tenant id, "" without tenancy.
func tenantID(ctx context.Context) string {
	if t := tenantFrom(ctx); t != nil {
		return t.id
	}
	return ""
}

// tenantKey namespaces an id (workspace, contact id) under the caller's
// tenant: "<tenant>/<id>", or id itself without tenancy.
func tenantKey(ctx context.Context, id string) string {
	if t := tenantFrom(ctx); t != nil {
		return t.id + "/" + id
	}
	return id
}
