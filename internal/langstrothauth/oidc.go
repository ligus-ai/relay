package langstrothauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Upstream OIDC: discovery, JWKS with rotation, ID token verification and the
// authorization code exchange. Hand-rolled on the standard library so the
// relay module gains no dependency; only asymmetric algorithms are accepted.

const (
	maxIdPResponse   = 1 << 20 // 1 MiB cap on any IdP response body
	discoveryTTL     = time.Hour
	jwksDefaultTTL   = time.Hour
	jwksMinTTL       = 5 * time.Minute
	jwksMaxTTL       = 24 * time.Hour
	jwksMinRefetch   = 30 * time.Second // floor between unknown-kid refetches
	maxIDTokenAge    = 10 * time.Minute // iat older than this is refused
	maxIDTokenLength = 64 << 10
	maxGroups        = 256
	maxGroupLen      = 256
	maxSubjectLen    = 255
)

// discovery is the subset of the provider metadata langstroth-auth uses.
type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// provider is one tenant's upstream IdP. Each tenant gets its own instance,
// so keys and metadata never cross tenants even if two share an issuer URL.
type provider struct {
	cfg    *OIDCConfig
	secret string
	skew   time.Duration
	http   *http.Client
	now    func() time.Time

	mu        sync.Mutex
	disc      *discovery
	discAt    time.Time
	keys      map[string]jwk // kid -> key ("" for a keyset without kids)
	keysList  []jwk
	keysAt    time.Time
	keysTTL   time.Duration
	lastFetch time.Time
}

func newProvider(cfg *OIDCConfig, secret string, skew time.Duration, client *http.Client, now func() time.Time) *provider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// Never follow redirects from the IdP's metadata, JWKS or token
	// endpoints: a redirect could move a confidential request elsewhere.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &provider{cfg: cfg, secret: secret, skew: skew, http: &c, now: now}
}

func (p *provider) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("IdP metadata has an invalid URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && p.cfg.AllowInsecureHTTP) {
		return fmt.Errorf("IdP metadata URL is not https")
	}
	return nil
}

// discover returns cached metadata, fetching it when stale.
func (p *provider) discover(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	if p.disc != nil && p.now().Sub(p.discAt) < discoveryTTL {
		d := p.disc
		p.mu.Unlock()
		return d, nil
	}
	p.mu.Unlock()
	wellKnown := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	var d discovery
	if err := p.getJSON(ctx, wellKnown, &d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// The metadata must name exactly the configured issuer (OIDC Discovery
	// 4.3); otherwise an attacker-controlled document could point ID token
	// validation at another issuer.
	if d.Issuer != p.cfg.Issuer {
		return nil, errors.New("discovery: issuer in metadata does not match the configured issuer")
	}
	for _, u := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if err := p.checkURL(u); err != nil {
			return nil, err
		}
	}
	if len(d.CodeChallengeMethods) > 0 && !contains(d.CodeChallengeMethods, "S256") {
		return nil, errors.New("discovery: the IdP does not support PKCE S256")
	}
	p.mu.Lock()
	p.disc, p.discAt = &d, p.now()
	p.mu.Unlock()
	return &d, nil
}

func (p *provider) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponse+1))
	if err != nil {
		return err
	}
	if len(body) > maxIdPResponse {
		return errors.New("response too large")
	}
	return json.Unmarshal(body, v)
}

// jwk is one JSON Web Key (only the fields langstroth-auth needs).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	pub crypto.PublicKey
}

// refreshKeys fetches the JWKS. force skips the cache but still honours the
// minimum refetch interval, so a flood of unknown-kid tokens cannot turn
// langstroth-auth into a request amplifier against the IdP.
func (p *provider) refreshKeys(ctx context.Context, force bool) error {
	p.mu.Lock()
	haveKeys := p.keys != nil
	fresh := haveKeys && p.now().Sub(p.keysAt) < p.keysTTL
	recent := !p.lastFetch.IsZero() && p.now().Sub(p.lastFetch) < jwksMinRefetch
	if fresh && !force {
		p.mu.Unlock()
		return nil
	}
	if recent {
		p.mu.Unlock()
		if haveKeys {
			return nil // keep using the cached set until the floor passes
		}
		return errors.New("jwks: unavailable, retrying shortly")
	}
	p.lastFetch = p.now()
	p.mu.Unlock()
	d, err := p.discover(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponse+1))
	if err != nil || len(body) > maxIdPResponse {
		return errors.New("jwks: unreadable or too large")
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]jwk{}
	var list []jwk
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue // skip keys we can't use; never fail the whole set
		}
		k.pub = pub
		if _, dup := keys[k.Kid]; dup {
			continue
		}
		keys[k.Kid] = k
		list = append(list, k)
	}
	if len(list) == 0 {
		return errors.New("jwks: no usable signing keys")
	}
	ttl := cacheTTL(resp.Header.Get("Cache-Control"))
	p.mu.Lock()
	// Replace the whole set: a key the IdP retired stops verifying at the
	// next refresh.
	p.keys, p.keysList, p.keysAt, p.keysTTL = keys, list, p.now(), ttl
	p.mu.Unlock()
	return nil
}

func cacheTTL(cc string) time.Duration {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			var n int64
			if _, err := fmt.Sscan(v, &n); err == nil {
				d := time.Duration(n) * time.Second
				if d < jwksMinTTL {
					return jwksMinTTL
				}
				if d > jwksMaxTTL {
					return jwksMaxTTL
				}
				return d
			}
		}
	}
	return jwksDefaultTTL
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA key")
		}
		var ev int
		for _, b := range e {
			ev = ev<<8 | int(b)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ev}
		if pub.N.BitLen() < 2048 || ev < 3 || ev%2 == 0 {
			return nil, errors.New("weak RSA key")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, errors.New("unsupported curve")
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(x) != size || len(y) != size {
			return nil, errors.New("bad EC key size")
		}
		// Reject points that are not on the curve (invalid-curve attacks).
		raw := append([]byte{4}, append(x, y...)...)
		pk, err := ecdsa.ParseUncompressedPublicKey(curve, raw)
		if err != nil {
			return nil, errors.New("EC point not on curve")
		}
		return pk, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, errors.New("unsupported OKP curve")
		}
		x, err := b64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errors.New("unsupported key type")
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// IDClaims are the verified ID token claims langstroth-auth acts on.
type IDClaims struct {
	Subject       string
	Email         string
	EmailVerified *bool
	Groups        []string
	Raw           map[string]any
}

var (
	errIDToken = errors.New("id token rejected")
)

// verifyIDToken checks the signature, algorithm, issuer, audience, authorized
// party, time claims and nonce, in that order. Any failure is errIDToken
// wrapped with a short reason (safe to log; it never contains the token).
func (p *provider) verifyIDToken(ctx context.Context, raw, wantNonce string) (*IDClaims, error) {
	fail := func(why string) (*IDClaims, error) { return nil, fmt.Errorf("%w: %s", errIDToken, why) }
	if len(raw) > maxIDTokenLength {
		return fail("too long")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return fail("not a compact JWS")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return fail("bad header")
	}
	var hdr struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
		Jku  string          `json:"jku"`
		Jwk  json.RawMessage `json:"jwk"`
		X5u  string          `json:"x5u"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return fail("bad header")
	}
	if len(hdr.Crit) > 0 {
		return fail("crit header not supported")
	}
	// Keys come only from the IdP's own JWKS; embedded or remote key hints
	// in the header are attacker-controlled and are refused outright.
	if hdr.Jku != "" || len(hdr.Jwk) > 0 || hdr.X5u != "" {
		return fail("embedded or remote key reference in header")
	}
	if !contains(p.cfg.AllowedAlgs, hdr.Alg) {
		return fail("algorithm not allowed: " + sanitize(hdr.Alg))
	}
	sig, err := b64(parts[2])
	if err != nil {
		return fail("bad signature encoding")
	}
	key, err := p.keyFor(ctx, hdr.Kid, hdr.Alg)
	if err != nil {
		return fail(err.Error())
	}
	if err := verifyJWS(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return fail("signature")
	}
	pb, err := b64(parts[1])
	if err != nil {
		return fail("bad payload")
	}
	var c map[string]any
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return fail("bad payload")
	}
	if s, _ := c["iss"].(string); s != p.cfg.Issuer {
		return fail("issuer")
	}
	auds := audiences(c["aud"])
	if !contains(auds, p.cfg.ClientID) {
		return fail("audience")
	}
	azp, hasAzp := c["azp"].(string)
	if (len(auds) > 1 || hasAzp) && azp != p.cfg.ClientID {
		return fail("authorized party")
	}
	now := p.now()
	exp, ok := numClaim(c["exp"])
	if !ok || now.After(time.Unix(exp, 0).Add(p.skew)) {
		return fail("expired")
	}
	iat, ok := numClaim(c["iat"])
	if !ok || time.Unix(iat, 0).After(now.Add(p.skew)) || now.Sub(time.Unix(iat, 0)) > maxIDTokenAge+p.skew {
		return fail("issued-at")
	}
	if nbf, ok := numClaim(c["nbf"]); ok && time.Unix(nbf, 0).After(now.Add(p.skew)) {
		return fail("not yet valid")
	}
	if n, _ := c["nonce"].(string); wantNonce == "" || !constEq(n, wantNonce) {
		return fail("nonce")
	}
	out := &IDClaims{Raw: c}
	out.Subject, _ = c[p.cfg.ClaimMap.User].(string)
	if out.Subject == "" || len(out.Subject) > maxSubjectLen {
		return fail("missing or oversized subject claim")
	}
	out.Email, _ = c[p.cfg.ClaimMap.Email].(string)
	if v, ok := c["email_verified"].(bool); ok {
		out.EmailVerified = &v
	}
	out.Groups = stringList(c[p.cfg.ClaimMap.Groups])
	return out, nil
}

// keyFor picks the verification key for kid and alg, refetching the JWKS
// once (rate limited) on an unknown kid so IdP key rotation just works.
func (p *provider) keyFor(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	if err := p.refreshKeys(ctx, false); err != nil {
		return nil, err
	}
	if k, ok := p.lookupKey(kid, alg); ok {
		return k, nil
	}
	if err := p.refreshKeys(ctx, true); err != nil {
		return nil, err
	}
	if k, ok := p.lookupKey(kid, alg); ok {
		return k, nil
	}
	return nil, errors.New("no matching key in the IdP's JWKS")
}

func (p *provider) lookupKey(kid, alg string) (crypto.PublicKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	match := func(k jwk) bool {
		if k.Alg != "" && k.Alg != alg {
			return false
		}
		return keyFitsAlg(k.pub, alg)
	}
	if kid != "" {
		k, ok := p.keys[kid]
		if ok && match(k) {
			return k.pub, true
		}
		return nil, false
	}
	// No kid: only unambiguous when exactly one key fits the algorithm.
	var found []jwk
	for _, k := range p.keysList {
		if match(k) {
			found = append(found, k)
		}
	}
	if len(found) == 1 {
		return found[0].pub, true
	}
	return nil, false
}

func keyFitsAlg(pub crypto.PublicKey, alg string) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		return (alg == "ES256" && k.Curve == elliptic.P256()) || (alg == "ES384" && k.Curve == elliptic.P384())
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

func verifyJWS(alg string, key crypto.PublicKey, signed, sig []byte) error {
	hashFor := func(h crypto.Hash) []byte {
		switch h {
		case crypto.SHA384:
			s := sha512.Sum384(signed)
			return s[:]
		case crypto.SHA512:
			s := sha512.Sum512(signed)
			return s[:]
		}
		s := sha256.Sum256(signed)
		return s[:]
	}
	var h crypto.Hash
	switch alg {
	case "RS256", "PS256", "ES256":
		h = crypto.SHA256
	case "RS384", "PS384", "ES384":
		h = crypto.SHA384
	case "RS512", "PS512":
		h = crypto.SHA512
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(k, h, hashFor(h), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
		}
		return rsa.VerifyPKCS1v15(k, h, hashFor(h), sig)
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("bad ECDSA signature length")
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, hashFor(h), r, s) {
			return errors.New("bad ECDSA signature")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, signed, sig) {
			return errors.New("bad EdDSA signature")
		}
		return nil
	}
	return errors.New("unsupported key")
}

// exchangeCode redeems an authorization code at the IdP's token endpoint and
// returns the raw ID token.
func (p *provider) exchangeCode(ctx context.Context, code, redirectURI, verifier string) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	switch p.cfg.TokenAuth {
	case "post":
		form.Set("client_id", p.cfg.ClientID)
		form.Set("client_secret", p.secret)
	case "none":
		form.Set("client_id", p.cfg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.TokenAuth == "basic" {
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.secret))
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPResponse+1))
	if err != nil || len(body) > maxIdPResponse {
		return "", errors.New("token endpoint: unreadable or too large")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return "", errors.New("token endpoint: no id_token in response")
	}
	return tr.IDToken, nil
}

// authURL builds the IdP authorization request.
func (p *provider) authURL(ctx context.Context, redirectURI, state, nonce, challenge string) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func audiences(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		var out []string
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func numClaim(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	if i, err := n.Int64(); err == nil {
		return i, true
	}
	f, err := n.Float64()
	if err != nil {
		return 0, false
	}
	return int64(f), true
}

// stringList reads a groups-style claim (an array of strings, or one string),
// capped in count and length.
func stringList(v any) []string {
	var out []string
	add := func(s string) {
		if s != "" && len(s) <= maxGroupLen && len(out) < maxGroups {
			out = append(out, s)
		}
	}
	switch a := v.(type) {
	case string:
		add(a)
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				add(s)
			}
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// sanitize keeps a short, printable prefix of an untrusted value for logs.
func sanitize(s string) string {
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}
