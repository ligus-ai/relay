// Package langstrothauth is langstroth-auth: an OIDC relying party that turns a sign-in
// at any compliant identity provider into short-lived relay access tokens
// (hrt1), with a small SCIM 2.0 endpoint for provisioning and deprovisioning.
//
// langstroth-auth only gates transport. A token says which workspaces a person may
// reach on the relay; it never makes anyone a workspace member. Membership
// stays in each workspace's signed roster (an Admin's signed MemberAdded).
//
// It runs as its own binary (cmd/langstroth-auth), never inside the relay process.
// The relay only needs the issuer's public key (LANGSTROTH_RELAY_TOKEN_PUBKEY).
package langstrothauth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Hard limits the configuration may not exceed.
const (
	// MaxAccessTTL is the longest an access token may live (spec E.3: exp <= 1h).
	MaxAccessTTL = time.Hour
	// MaxClockSkew bounds the configurable leeway for ID token time checks.
	MaxClockSkew = 5 * time.Minute
)

// Duration is a time.Duration that reads from JSON as a Go duration string
// ("15m", "168h").
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"15m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the langstroth-auth configuration file (JSON).
type Config struct {
	// Listen is the public listener (OIDC flows, token endpoint, SCIM).
	Listen string `json:"listen"`
	// AdminListen is the operator API listener. Empty disables the admin API.
	// Keep it on loopback or a private network.
	AdminListen string `json:"admin_listen"`
	// PublicURL is the externally visible base URL, used to build the IdP
	// redirect URI (<public_url>/t/<tenant>/callback) and the device
	// verification URL.
	PublicURL string `json:"public_url"`
	// SigningKeyFile holds the issuer Ed25519 seed (64 hex chars). See
	// LoadSigningKey for the other sources (systemd credential, env).
	SigningKeyFile string `json:"signing_key_file"`
	// Store selects persistence: {"driver":"file","path":...} or
	// {"driver":"postgres","dsn_env":"LANGSTROTH_AUTH_DATABASE_URL"}.
	Store StoreConfig `json:"store"`
	// AccessTTL is the access token lifetime (default 15m, at most 1h).
	AccessTTL Duration `json:"access_ttl"`
	// RefreshIdleTTL is how long an unused refresh token stays valid
	// (default 7 days). Each use rotates it and restarts the clock.
	RefreshIdleTTL Duration `json:"refresh_idle_ttl"`
	// SessionMaxAge is the absolute session lifetime after the IdP sign-in
	// (default 30 days). After it, the person signs in at the IdP again.
	SessionMaxAge Duration `json:"session_max_age"`
	// ClockSkew is the leeway for ID token exp/iat/nbf (default 60s, max 5m).
	ClockSkew Duration `json:"clock_skew"`
	// TrustedProxies are CIDRs whose X-Forwarded-For is believed.
	TrustedProxies []string `json:"trusted_proxies"`
	// RatePerIP and BurstPerIP bound requests per client IP on the public
	// endpoints (defaults 5/s, burst 30).
	RatePerIP  float64 `json:"rate_per_ip"`
	BurstPerIP float64 `json:"burst_per_ip"`
	// AuditLog is a file for the JSON audit log ("" = stderr).
	AuditLog string `json:"audit_log"`
	// Tenants. Each has its own IdP, SCIM token and workspaces.
	Tenants []TenantConfig `json:"tenants"`

	trustedNets []netip.Prefix
}

// StoreConfig selects the persistent store.
type StoreConfig struct {
	Driver string `json:"driver"` // "file" (default) or "postgres"
	Path   string `json:"path"`   // file driver: state file ("" = memory only)
	DSNEnv string `json:"dsn_env"`
}

// TenantConfig is one tenant: an IdP, its provisioning mode and the
// workspaces it owns.
type TenantConfig struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name"`
	OIDC        OIDCConfig `json:"oidc"`
	// Provisioning is "jit" (a first sign-in creates the user) or "scim"
	// (only users provisioned and active over SCIM may sign in).
	Provisioning string `json:"provisioning"`
	// LinkClaim is the ID token claim matched against a SCIM user's userName
	// on that user's first sign-in (default "email"). After the first
	// sign-in the user is bound to the IdP subject and the link claim is no
	// longer consulted.
	LinkClaim string `json:"link_claim"`
	// LinkAttr is the SCIM attribute LinkClaim is matched against:
	// "userName" (default) or "externalId" (for example Entra ID's oid).
	LinkAttr string `json:"link_attr"`
	// IDPGroups trusts the ID token's groups claim (captured at sign-in) in
	// addition to SCIM groups.
	IDPGroups bool `json:"idp_groups"`
	// SCIM bearer token: one of a file, an env var, or its SHA-256 (hex).
	SCIMTokenFile   string `json:"scim_token_file"`
	SCIMTokenEnv    string `json:"scim_token_env"`
	SCIMTokenSHA256 string `json:"scim_token_sha256"`
	// Device-revocation token: lets a serve box end this tenant's device
	// sessions (POST /admin/v1/tenants/{t}/devices/{d}/revoke) and nothing
	// else, so the box never holds the operator token. A file (0600) or its
	// SHA-256 (hex); never an env var.
	DeviceRevokeTokenFile   string `json:"device_revoke_token_file"`
	DeviceRevokeTokenSHA256 string `json:"device_revoke_token_sha256"`
	// Workspaces this tenant owns. Grants may only name these. ["*"] (any
	// workspace) is allowed only when this is the only tenant.
	Workspaces []string `json:"workspaces"`
	// Grants seeds group -> workspace grants into the store at startup.
	Grants map[string][]string `json:"grants"`
	// RedirectURIs are extra exact-match client redirect URIs (for example
	// the iOS app's custom scheme). Loopback http://127.0.0.1 and
	// http://[::1] redirects on any port are always allowed (RFC 8252).
	RedirectURIs []string `json:"redirect_uris"`
	// Claim fields copied into every minted token.
	Plan          string   `json:"plan"`
	Caps          []string `json:"caps"`
	Turn          bool     `json:"turn"`
	MaxMembers    *uint32  `json:"max_members"`
	RetentionDays *uint32  `json:"retention_days"`

	scimTokenHash         string
	deviceRevokeTokenHash string
	clientSecret          string
}

// OIDCConfig is the upstream identity provider for a tenant.
type OIDCConfig struct {
	Issuer           string `json:"issuer"`
	ClientID         string `json:"client_id"`
	ClientSecretFile string `json:"client_secret_file"`
	ClientSecretEnv  string `json:"client_secret_env"`
	// TokenAuth is how langstroth-auth authenticates to the IdP token endpoint:
	// "basic" (client_secret_basic, default with a secret), "post"
	// (client_secret_post) or "none" (public client, PKCE only).
	TokenAuth string   `json:"token_auth"`
	Scopes    []string `json:"scopes"`
	ClaimMap  ClaimMap `json:"claim_map"`
	// AllowedAlgs limits ID token signature algorithms. Default: RS256,
	// RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA. "none" and the
	// HMAC algorithms are never accepted.
	AllowedAlgs []string `json:"allowed_algs"`
	// AllowInsecureHTTP permits an http:// issuer and endpoints. Only for a
	// lab IdP on a trusted network or tests; never in production.
	AllowInsecureHTTP bool `json:"allow_insecure_http"`
}

// ClaimMap names the ID token claims langstroth-auth reads.
type ClaimMap struct {
	User   string `json:"user"`   // stable subject (default "sub")
	Email  string `json:"email"`  // default "email"
	Groups string `json:"groups"` // default "groups"
}

var (
	tenantIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// workspace ids are relay path segments: keep them to a safe charset.
	workspaceIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,512}$`)
)

var supportedAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "EdDSA": true,
}

// LoadConfig reads and validates a configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate applies defaults, loads referenced secrets and enforces the
// isolation rules. It never logs or returns secret values.
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = ":8090"
	}
	if c.PublicURL == "" {
		return errors.New("public_url is required")
	}
	pu, err := url.Parse(c.PublicURL)
	if err != nil || pu.Host == "" || (pu.Scheme != "https" && pu.Scheme != "http") || pu.RawQuery != "" || pu.Fragment != "" {
		return errors.New("public_url must be an absolute http(s) URL without query or fragment")
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.AccessTTL == 0 {
		c.AccessTTL = Duration(15 * time.Minute)
	}
	if c.AccessTTL.D() < time.Minute || c.AccessTTL.D() > MaxAccessTTL {
		return fmt.Errorf("access_ttl must be between 1m and %s", MaxAccessTTL)
	}
	if c.RefreshIdleTTL == 0 {
		c.RefreshIdleTTL = Duration(7 * 24 * time.Hour)
	}
	if c.SessionMaxAge == 0 {
		c.SessionMaxAge = Duration(30 * 24 * time.Hour)
	}
	if c.RefreshIdleTTL.D() < c.AccessTTL.D() || c.SessionMaxAge.D() < c.RefreshIdleTTL.D() {
		return errors.New("need access_ttl <= refresh_idle_ttl <= session_max_age")
	}
	if c.ClockSkew == 0 {
		c.ClockSkew = Duration(60 * time.Second)
	}
	if c.ClockSkew.D() < 0 || c.ClockSkew.D() > MaxClockSkew {
		return fmt.Errorf("clock_skew must be between 0 and %s", MaxClockSkew)
	}
	if c.RatePerIP == 0 {
		c.RatePerIP = 5
	}
	if c.BurstPerIP == 0 {
		c.BurstPerIP = 30
	}
	for _, p := range c.TrustedProxies {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("trusted_proxies: %q is not a CIDR", p)
		}
		c.trustedNets = append(c.trustedNets, pfx.Masked())
	}
	switch c.Store.Driver {
	case "", "file":
		c.Store.Driver = "file"
	case "postgres":
		if c.Store.DSNEnv == "" {
			c.Store.DSNEnv = "LANGSTROTH_AUTH_DATABASE_URL"
		}
	default:
		return fmt.Errorf("store.driver %q is not file or postgres", c.Store.Driver)
	}
	if len(c.Tenants) == 0 {
		return errors.New("at least one tenant is required")
	}
	seen := map[string]bool{}
	owner := map[string]string{} // workspace -> tenant
	for i := range c.Tenants {
		t := &c.Tenants[i]
		if err := t.validate(); err != nil {
			return fmt.Errorf("tenant %q: %w", t.ID, err)
		}
		if seen[t.ID] {
			return fmt.Errorf("tenant %q is listed twice", t.ID)
		}
		seen[t.ID] = true
		for _, w := range t.Workspaces {
			if w == "*" && len(c.Tenants) > 1 {
				return fmt.Errorf("tenant %q: workspaces [\"*\"] is only allowed with a single tenant", t.ID)
			}
			if prev, ok := owner[w]; ok {
				return fmt.Errorf("workspace %q is owned by both %q and %q; each workspace belongs to one tenant", w, prev, t.ID)
			}
			owner[w] = t.ID
		}
	}
	return nil
}

func (t *TenantConfig) validate() error {
	if !tenantIDRe.MatchString(t.ID) {
		return errors.New("id must match [a-z0-9][a-z0-9-]{0,62}")
	}
	o := &t.OIDC
	iu, err := url.Parse(o.Issuer)
	if err != nil || iu.Host == "" || iu.RawQuery != "" || iu.Fragment != "" {
		return errors.New("oidc.issuer must be an absolute URL")
	}
	if iu.Scheme != "https" && !(iu.Scheme == "http" && o.AllowInsecureHTTP) {
		return errors.New("oidc.issuer must be https (allow_insecure_http is for labs and tests only)")
	}
	if o.ClientID == "" {
		return errors.New("oidc.client_id is required")
	}
	secret, err := readSecret(o.ClientSecretFile, o.ClientSecretEnv)
	if err != nil {
		return fmt.Errorf("oidc client secret: %w", err)
	}
	t.clientSecret = secret
	switch o.TokenAuth {
	case "":
		if secret != "" {
			o.TokenAuth = "basic"
		} else {
			o.TokenAuth = "none"
		}
	case "basic", "post":
		if secret == "" {
			return fmt.Errorf("oidc.token_auth %q needs a client secret", o.TokenAuth)
		}
	case "none":
	default:
		return errors.New("oidc.token_auth must be basic, post or none")
	}
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "email", "profile"}
		if t.IDPGroups {
			o.Scopes = append(o.Scopes, "groups")
		}
	}
	hasOpenID := false
	for _, s := range o.Scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		return errors.New("oidc.scopes must include openid")
	}
	if o.ClaimMap.User == "" {
		o.ClaimMap.User = "sub"
	}
	if o.ClaimMap.Email == "" {
		o.ClaimMap.Email = "email"
	}
	if o.ClaimMap.Groups == "" {
		o.ClaimMap.Groups = "groups"
	}
	if len(o.AllowedAlgs) == 0 {
		for a := range supportedAlgs {
			o.AllowedAlgs = append(o.AllowedAlgs, a)
		}
		sort.Strings(o.AllowedAlgs)
	}
	for _, a := range o.AllowedAlgs {
		if !supportedAlgs[a] {
			return fmt.Errorf("oidc.allowed_algs: %q is not supported (none and HS* are never accepted)", a)
		}
	}
	switch t.Provisioning {
	case "":
		t.Provisioning = "jit"
	case "jit", "scim":
	default:
		return errors.New("provisioning must be jit or scim")
	}
	if t.LinkClaim == "" {
		t.LinkClaim = "email"
	}
	switch t.LinkAttr {
	case "":
		t.LinkAttr = "userName"
	case "userName", "externalId":
	default:
		return errors.New("link_attr must be userName or externalId")
	}
	n := 0
	for _, v := range []string{t.SCIMTokenFile, t.SCIMTokenEnv, t.SCIMTokenSHA256} {
		if v != "" {
			n++
		}
	}
	if n > 1 {
		return errors.New("set only one of scim_token_file, scim_token_env, scim_token_sha256")
	}
	switch {
	case t.SCIMTokenSHA256 != "":
		h := strings.ToLower(strings.TrimSpace(t.SCIMTokenSHA256))
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			return errors.New("scim_token_sha256 must be 64 hex chars")
		}
		t.scimTokenHash = h
	case n == 1:
		tok, err := readSecret(t.SCIMTokenFile, t.SCIMTokenEnv)
		if err != nil {
			return fmt.Errorf("scim token: %w", err)
		}
		if len(tok) < 32 {
			return errors.New("the SCIM token must be at least 32 characters")
		}
		t.scimTokenHash = sha256Hex(tok)
	}
	switch {
	case t.DeviceRevokeTokenFile != "" && t.DeviceRevokeTokenSHA256 != "":
		return errors.New("set only one of device_revoke_token_file, device_revoke_token_sha256")
	case t.DeviceRevokeTokenSHA256 != "":
		h := strings.ToLower(strings.TrimSpace(t.DeviceRevokeTokenSHA256))
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			return errors.New("device_revoke_token_sha256 must be 64 hex chars")
		}
		t.deviceRevokeTokenHash = h
	case t.DeviceRevokeTokenFile != "":
		tok, err := readSecret(t.DeviceRevokeTokenFile, "")
		if err != nil {
			return fmt.Errorf("device revoke token: %w", err)
		}
		if len(tok) < 32 {
			return errors.New("the device revoke token must be at least 32 characters")
		}
		t.deviceRevokeTokenHash = sha256Hex(tok)
	}
	if t.Provisioning == "scim" && t.scimTokenHash == "" {
		return errors.New("provisioning scim needs a SCIM token")
	}
	for _, w := range t.Workspaces {
		if w != "*" && !workspaceIDRe.MatchString(w) {
			return fmt.Errorf("workspace id %q has characters outside [A-Za-z0-9._:-]", w)
		}
	}
	for g, ws := range t.Grants {
		if g == "" {
			return errors.New("grants: empty group name")
		}
		for _, w := range ws {
			if !t.owns(w) {
				return fmt.Errorf("grants[%q]: workspace %q is not owned by this tenant", g, w)
			}
		}
	}
	for _, r := range t.RedirectURIs {
		u, err := url.Parse(r)
		if err != nil || u.Scheme == "" || u.Fragment != "" {
			return fmt.Errorf("redirect_uris: %q is not an absolute URI without a fragment", r)
		}
		if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("redirect_uris: %q uses plain http off loopback", r)
		}
		if u.Scheme == "javascript" || u.Scheme == "data" || u.Scheme == "file" {
			return fmt.Errorf("redirect_uris: scheme %q is not allowed", u.Scheme)
		}
	}
	return nil
}

// owns reports whether the tenant may grant workspace w. "*" itself is only
// grantable by a tenant that owns "*".
func (t *TenantConfig) owns(w string) bool {
	for _, o := range t.Workspaces {
		if o == w {
			return true
		}
		if o == "*" && (w == "*" || workspaceIDRe.MatchString(w)) {
			return true
		}
	}
	return false
}

// readSecret reads a secret from a file (trimmed) or an env var. Neither set
// returns "". A file that other users can read is refused.
func readSecret(file, env string) (string, error) {
	switch {
	case file != "" && env != "":
		return "", errors.New("set the file or the env var, not both")
	case file != "":
		if err := checkSecretFilePerms(file); err != nil {
			return "", err
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", filepath.Base(file), err)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", fmt.Errorf("%s is empty", filepath.Base(file))
		}
		return v, nil
	case env != "":
		v := strings.TrimSpace(authGetenv(env))
		if v == "" {
			return "", fmt.Errorf("env %s is empty", env)
		}
		return v, nil
	}
	return "", nil
}

// checkSecretFilePerms refuses a secret file that is world-readable or
// writable by anyone but its owner. Group read is allowed (Kubernetes secret
// volumes with fsGroup use 0440).
func checkSecretFilePerms(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory", filepath.Base(path))
	}
	if authGetenv("LANGSTROTH_AUTH_INSECURE_SECRET_PERMS") == "1" {
		return nil
	}
	if perm := st.Mode().Perm(); perm&0o027 != 0 {
		return fmt.Errorf("%s has mode %#o; secrets must not be world-readable or group-writable (chmod 600)", filepath.Base(path), perm)
	}
	return nil
}

func isLoopbackHost(h string) bool {
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil && a.IsLoopback()
}

// tenant returns the tenant with id, or nil.
func (c *Config) tenant(id string) *TenantConfig {
	for i := range c.Tenants {
		if c.Tenants[i].ID == id {
			return &c.Tenants[i]
		}
	}
	return nil
}
