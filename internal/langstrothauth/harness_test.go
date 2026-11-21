package langstrothauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── clock ────────────────────────────────────────────────────────────────────

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_900_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ── mock OIDC provider ───────────────────────────────────────────────────────

// mockKey is one signing key the mock IdP can publish and sign with.
type mockKey struct {
	kid  string
	alg  string
	priv crypto.Signer
	jwk  map[string]any
}

var (
	rsaOnce sync.Once
	rsaKeys []*rsa.PrivateKey
)

// testRSA returns cached 2048-bit keys (generation is slow).
func testRSA(i int) *rsa.PrivateKey {
	rsaOnce.Do(func() {
		for j := 0; j < 3; j++ {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaKeys = append(rsaKeys, k)
		}
	})
	return rsaKeys[i]
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaMockKey(kid string, i int) mockKey {
	k := testRSA(i)
	return mockKey{kid: kid, alg: "RS256", priv: k, jwk: map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64u(k.N.Bytes()), "e": b64u(big.NewInt(int64(k.E)).Bytes()),
	}}
}

func ecMockKey(kid string) mockKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pt, _ := k.PublicKey.Bytes()
	return mockKey{kid: kid, alg: "ES256", priv: k, jwk: map[string]any{
		"kty": "EC", "kid": kid, "crv": "P-256", "x": b64u(pt[1:33]), "y": b64u(pt[33:]),
	}}
}

func edMockKey(kid string) mockKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return mockKey{kid: kid, alg: "EdDSA", priv: priv, jwk: map[string]any{"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": b64u(pub)}}
}

// signJWT signs claims with k (header may be tampered by the caller).
func signJWT(k mockKey, hdr map[string]any, claims map[string]any) string {
	if hdr == nil {
		hdr = map[string]any{"alg": k.alg, "kid": k.kid, "typ": "JWT"}
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signing := b64u(hb) + "." + b64u(cb)
	var sig []byte
	switch p := k.priv.(type) {
	case *rsa.PrivateKey:
		h := sha256.Sum256([]byte(signing))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, p, crypto.SHA256, h[:])
	case *ecdsa.PrivateKey:
		h := sha256.Sum256([]byte(signing))
		r, s, _ := ecdsa.Sign(rand.Reader, p, h[:])
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(p, []byte(signing))
	}
	return signing + "." + b64u(sig)
}

type idpUser struct {
	sub           string
	email         string
	emailVerified *bool
	groups        []string
}

type pendingCode struct {
	nonce, challenge, redirect string
	user                       idpUser
}

// mockIdP is a small, deliberately configurable OIDC provider. Its knobs let
// a test turn it malicious.
type mockIdP struct {
	t        *testing.T
	srv      *httptest.Server
	clock    *fakeClock
	clientID string
	secret   string

	mu         sync.Mutex
	published  []mockKey // JWKS contents
	signer     mockKey   // signs ID tokens
	user       idpUser
	codes      map[string]pendingCode
	jwksHits   int
	discIssuer string                             // overrides "issuer" in discovery
	mutate     func(claims map[string]any)        // edits claims before signing
	header     func(k mockKey) map[string]any     // replaces the JWS header
	rawToken   func(claims map[string]any) string // replaces the whole id_token
	callbackQ  func(q url.Values)                 // edits the redirect back
}

func newMockIdP(t *testing.T, clock *fakeClock) *mockIdP {
	m := &mockIdP{t: t, clock: clock, clientID: "langstroth-auth", secret: "s3cret-s3cret-s3cret-s3cret-s3cret", codes: map[string]pendingCode{}}
	k := rsaMockKey("k1", 0)
	m.published, m.signer = []mockKey{k}, k
	m.user = idpUser{sub: "alice-sub", email: "alice@example.com", emailVerified: boolp(true)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		iss := m.discIssuer
		m.mu.Unlock()
		if iss == "" {
			iss = m.srv.URL
		}
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": m.srv.URL + "/authorize", "token_endpoint": m.srv.URL + "/token",
			"jwks_uri": m.srv.URL + "/jwks", "code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.jwksHits++
		var keys []map[string]any
		for _, k := range m.published {
			keys = append(keys, k.jwk)
		}
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != m.clientID || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
			http.Error(w, "bad authorize request", 400)
			return
		}
		code := randToken(16)
		m.mu.Lock()
		m.codes[code] = pendingCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), user: m.user}
		edit := m.callbackQ
		m.mu.Unlock()
		back := url.Values{"code": {code}, "state": {q.Get("state")}}
		if edit != nil {
			edit(back)
		}
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+back.Encode(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, sec, ok := r.BasicAuth()
		if !ok || id != m.clientID || sec != m.secret {
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		}
		m.mu.Lock()
		pc, found := m.codes[r.PostForm.Get("code")]
		delete(m.codes, r.PostForm.Get("code"))
		m.mu.Unlock()
		if !found || pkceChallenge(r.PostForm.Get("code_verifier")) != pc.challenge || r.PostForm.Get("redirect_uri") != pc.redirect {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		now := m.clock.Now().Unix()
		claims := map[string]any{"iss": m.srv.URL, "aud": m.clientID, "sub": pc.user.sub, "exp": now + 300, "iat": now, "nonce": pc.nonce}
		if pc.user.email != "" {
			claims["email"] = pc.user.email
		}
		if pc.user.emailVerified != nil {
			claims["email_verified"] = *pc.user.emailVerified
		}
		if pc.user.groups != nil {
			claims["groups"] = pc.user.groups
		}
		m.mu.Lock()
		mutate, header, raw, signer := m.mutate, m.header, m.rawToken, m.signer
		m.mu.Unlock()
		if mutate != nil {
			mutate(claims)
		}
		var tok string
		switch {
		case raw != nil:
			tok = raw(claims)
		case header != nil:
			tok = signJWT(signer, header(signer), claims)
		default:
			tok = signJWT(signer, nil, claims)
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "idp-at", "token_type": "Bearer", "id_token": tok})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func boolp(b bool) *bool { return &b }

func (m *mockIdP) set(f func(m *mockIdP)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

// ── langstroth-auth harness ───────────────────────────────────────────────────────

type harness struct {
	t     *testing.T
	srv   *Server
	ts    *httptest.Server
	cfg   *Config
	clock *fakeClock
	store Store
	audit *bytes.Buffer
	idps  map[string]*mockIdP
}

const testSCIMToken = "scim-token-for-tests-0123456789abcdef"

type tenantSpec struct {
	id           string
	idp          *mockIdP
	workspaces   []string
	grants       map[string][]string
	provisioning string
	idpGroups    bool
	scimToken    string
	redirects    []string
	// deviceRevokeToken: the tenant's device-revocation token (its SHA-256 goes in the config).
	deviceRevokeToken string
}

func newHarness(t *testing.T, clock *fakeClock, specs ...tenantSpec) *harness {
	t.Helper()
	h := &harness{t: t, clock: clock, audit: &bytes.Buffer{}, idps: map[string]*mockIdP{}}
	var handler http.Handler
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.ts.Close)
	cfg := &Config{PublicURL: h.ts.URL, RatePerIP: 1000, BurstPerIP: 1000}
	for _, sp := range specs {
		tc := TenantConfig{
			ID: sp.id, Workspaces: sp.workspaces, Grants: sp.grants, Provisioning: sp.provisioning, IDPGroups: sp.idpGroups,
			RedirectURIs: sp.redirects,
			OIDC:         OIDCConfig{Issuer: sp.idp.srv.URL, ClientID: sp.idp.clientID, ClientSecretEnv: "TEST_IDP_SECRET_" + strings.ToUpper(strings.ReplaceAll(sp.id, "-", "_")), AllowInsecureHTTP: true},
		}
		t.Setenv(tc.OIDC.ClientSecretEnv, sp.idp.secret)
		if sp.scimToken != "" {
			tc.SCIMTokenSHA256 = sha256Hex(sp.scimToken)
		}
		if sp.deviceRevokeToken != "" {
			tc.DeviceRevokeTokenSHA256 = sha256Hex(sp.deviceRevokeToken)
		}
		cfg.Tenants = append(cfg.Tenants, tc)
		h.idps[sp.id] = sp.idp
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.cfg = cfg
	h.store, _ = NewFileStore("")
	seed := bytes.Repeat([]byte{42}, 32)
	srv, err := New(context.Background(), Options{Config: cfg, Store: h.store, Key: ed25519.NewKeyFromSeed(seed), AdminToken: "admin-token-for-tests-0123456789abcdef", Now: clock.Now, AuditWriter: h.audit})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	handler = srv.Handler()
	return h
}

func (h *harness) url(tenant, path string) string { return h.ts.URL + "/t/" + tenant + path }

// browser is a cookie-keeping client that never follows redirects.
func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func mustGet(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func body(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

// device is a test client device key.
type device struct {
	id   string
	priv ed25519.PrivateKey
}

func newDevice(id string) device {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return device{id: id, priv: priv}
}

func (d device) keyB64() string { return b64u(d.priv.Public().(ed25519.PublicKey)) }

type tokenResp struct {
	status     int
	Access     string   `json:"access_token"`
	Refresh    string   `json:"refresh_token"`
	ExpiresIn  int      `json:"expires_in"`
	Nonce      string   `json:"device_nonce"`
	Error      string   `json:"error"`
	Desc       string   `json:"error_description"`
	Workspaces []string `json:"workspaces"`
	Sub        string   `json:"sub"`
}

func (h *harness) postToken(tenant string, form url.Values) tokenResp {
	h.t.Helper()
	resp, err := http.PostForm(h.url(tenant, "/token"), form)
	if err != nil {
		h.t.Fatal(err)
	}
	var tr tokenResp
	json.NewDecoder(resp.Body).Decode(&tr)
	resp.Body.Close()
	tr.status = resp.StatusCode
	return tr
}

// redeem runs the token request with the device proof, fetching a nonce
// first when the server asks for one. credKey is the form field holding the
// grant credential.
func (h *harness) redeem(tenant string, form url.Values, credKey string, d device) tokenResp {
	h.t.Helper()
	tr := h.postToken(tenant, form)
	if tr.Error != "use_device_nonce" {
		return tr
	}
	signed := url.Values{}
	for k, v := range form {
		signed[k] = v
	}
	signed.Set("device_id", d.id)
	signed.Set("device_key", d.keyB64())
	signed.Set("device_nonce", tr.Nonce)
	signed.Set("device_sig", b64u(ed25519.Sign(d.priv, DeviceProofMessage(tenant, form.Get("grant_type"), tr.Nonce, d.id, form.Get(credKey)))))
	return h.postToken(tenant, signed)
}

// refresh uses a nonce the client already holds (from the last response).
func (h *harness) refresh(tenant, refreshTok, nonce string, d device) tokenResp {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshTok}}
	if nonce == "" {
		return h.redeem(tenant, form, "refresh_token", d)
	}
	form.Set("device_id", d.id)
	form.Set("device_key", d.keyB64())
	form.Set("device_nonce", nonce)
	form.Set("device_sig", b64u(ed25519.Sign(d.priv, DeviceProofMessage(tenant, "refresh_token", nonce, d.id, refreshTok))))
	tr := h.postToken(tenant, form)
	if tr.Error == "use_device_nonce" && retryStaleNonce {
		return h.refresh(tenant, refreshTok, tr.Nonce, d)
	}
	return tr
}

// retryStaleNonce makes refresh behave like a real client: a nonce the
// server no longer accepts is replaced by the one it offers.
var retryStaleNonce = true

const loopback = "http://127.0.0.1:53682/callback"

// browserLogin drives the authorization code + PKCE flow through the mock
// IdP and returns the code delivered to the loopback redirect (or the
// redirect query on error).
func (h *harness) browserLogin(tenant string) (url.Values, string) {
	h.t.Helper()
	c := browser()
	verifier := randToken(32)
	q := url.Values{
		"response_type": {"code"}, "client_id": {"ligus-desktop"}, "redirect_uri": {loopback},
		"state": {"client-state-1"}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	resp := mustGet(h.t, c, h.url(tenant, "/authorize?"+q.Encode()))
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("authorize: %d %s", resp.StatusCode, body(resp))
	}
	toIdP := resp.Header.Get("Location")
	resp.Body.Close()
	resp = mustGet(h.t, c, toIdP)
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("idp authorize: %d %s", resp.StatusCode, body(resp))
	}
	cb := resp.Header.Get("Location")
	resp.Body.Close()
	resp = mustGet(h.t, c, cb)
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, loopback) {
		h.t.Fatalf("callback: %d -> %q", resp.StatusCode, loc)
	}
	u, _ := url.Parse(loc)
	return u.Query(), verifier
}

func (h *harness) loginTokens(tenant string, d device) tokenResp {
	h.t.Helper()
	q, verifier := h.browserLogin(tenant)
	if q.Get("error") != "" {
		h.t.Fatalf("login error %q", q.Get("error"))
	}
	return h.redeem(tenant, url.Values{
		"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "client_id": {"ligus-desktop"},
		"redirect_uri": {loopback}, "code_verifier": {verifier},
	}, "code", d)
}

var confirmIDRe = regexp.MustCompile(`name="confirm_id" value="([^"]+)"`)

// deviceLogin runs RFC 8628 through the verification page and returns the
// device code; approve chooses the button on the confirmation page.
func (h *harness) deviceLogin(tenant string, approve bool) string {
	h.t.Helper()
	resp, err := http.PostForm(h.url(tenant, "/device_authorization"), url.Values{"client_id": {"ligus-cli"}, "device_label": {"serve box"}})
	if err != nil {
		h.t.Fatal(err)
	}
	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	json.NewDecoder(resp.Body).Decode(&da)
	resp.Body.Close()
	c := browser()
	resp, err = c.PostForm(h.url(tenant, "/device"), url.Values{"user_code": {strings.ToLower(da.UserCode)}})
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("device submit: %v %d", err, resp.StatusCode)
	}
	toIdP := resp.Header.Get("Location")
	resp.Body.Close()
	resp = mustGet(h.t, c, toIdP)
	cb := resp.Header.Get("Location")
	resp.Body.Close()
	resp = mustGet(h.t, c, cb)
	page := body(resp)
	m := confirmIDRe.FindStringSubmatch(page)
	if m == nil {
		h.t.Fatalf("no confirmation form: %d %s", resp.StatusCode, page)
	}
	action := "deny"
	if approve {
		action = "approve"
	}
	resp, err = c.PostForm(h.url(tenant, "/device/confirm"), url.Values{"confirm_id": {m[1]}, "action": {action}})
	if err != nil || resp.StatusCode != http.StatusOK {
		h.t.Fatalf("confirm: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()
	return da.DeviceCode
}

func (h *harness) scim(tenant, token, method, path string, v any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if v != nil {
		b, _ := json.Marshal(v)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.url(tenant, "/scim/v2"+path), rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp.StatusCode, out
}

func (h *harness) scimUser(tenant, userName string) string {
	h.t.Helper()
	code, out := h.scim(tenant, testSCIMToken, "POST", "/Users", map[string]any{"schemas": []string{scimUserSchema}, "userName": userName, "active": true})
	if code != http.StatusCreated {
		h.t.Fatalf("scim create user: %d %v", code, out)
	}
	return out["id"].(string)
}

func (h *harness) scimGroup(tenant, name string, members ...string) string {
	h.t.Helper()
	var ms []map[string]string
	for _, m := range members {
		ms = append(ms, map[string]string{"value": m})
	}
	code, out := h.scim(tenant, testSCIMToken, "POST", "/Groups", map[string]any{"schemas": []string{scimGroupSchema}, "displayName": name, "members": ms})
	if code != http.StatusCreated {
		h.t.Fatalf("scim create group: %d %v", code, out)
	}
	return out["id"].(string)
}

func fmtStatus(tr tokenResp) string { return fmt.Sprintf("%d %s %s", tr.status, tr.Error, tr.Desc) }
