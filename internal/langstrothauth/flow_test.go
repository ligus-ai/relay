package langstrothauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/langstroth-ai/langstroth-relay/internal/relay"
)

func homeHarness(t *testing.T) (*harness, *mockIdP) {
	clock := newClock()
	idp := newMockIdP(t, clock)
	h := newHarness(t, clock, tenantSpec{id: "home", idp: idp, workspaces: []string{"ws-home"}, grants: map[string][]string{"family": {"ws-home"}}, scimToken: testSCIMToken})
	return h, idp
}

// grantJIT gives a just-in-time user relay access by putting them in the
// "family" group over SCIM after their first sign-in created them.
func grantJIT(t *testing.T, h *harness, tenant string) {
	t.Helper()
	users, _ := h.store.ListUsers(t.Context(), tenant)
	var ids []string
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	h.scimGroup(tenant, "family", ids...)
}

func pub(h *harness) ed25519.PublicKey { return h.srv.key.Public().(ed25519.PublicKey) }

func TestAuthCodeFlowMintsRelayToken(t *testing.T) {
	h, _ := homeHarness(t)
	d := newDevice("dev-mac-1")
	// First sign-in creates the user (jit) but there is no grant yet: no
	// token is minted, rather than one without a workspaces claim.
	if tr := h.loginTokens("home", d); tr.status != http.StatusForbidden || tr.Error != "access_denied" {
		t.Fatalf("no grants must refuse: %s", fmtStatus(tr))
	}
	grantJIT(t, h, "home")
	tr := h.loginTokens("home", d)
	if tr.status != 200 || tr.Access == "" || tr.Refresh == "" {
		t.Fatalf("login: %s", fmtStatus(tr))
	}
	claims, ok := relay.VerifyToken(tr.Access, pub(h))
	if !ok {
		t.Fatal("minted token must verify with the relay verifier")
	}
	users, _ := h.store.ListUsers(t.Context(), "home")
	if len(users) != 1 {
		t.Fatalf("want one user, got %d", len(users))
	}
	u := users[0]
	if claims.Sub != "home:"+u.ID || claims.Tid != "home" || claims.Did != "dev-mac-1" {
		t.Fatalf("claims: %+v", claims)
	}
	if claims.Uid != subjectHash(h.idps["home"].srv.URL, "alice-sub") || strings.Contains(claims.Uid, "alice") {
		t.Fatalf("uid must be the subject hash: %q", claims.Uid)
	}
	if len(claims.Workspaces) != 1 || claims.Workspaces[0] != "ws-home" {
		t.Fatalf("workspaces: %v", claims.Workspaces)
	}
	ttl := int64(claims.Exp) - h.clock.Now().Unix()
	if ttl <= 0 || ttl > int64(MaxAccessTTL.Seconds()) || tr.ExpiresIn != int(ttl) {
		t.Fatalf("access ttl %d (expires_in %d)", ttl, tr.ExpiresIn)
	}
	if claims.IsExpired(h.clock.Now().Unix()) || !claims.IsExpired(h.clock.Now().Add(time.Hour).Unix()) {
		t.Fatal("exp must be within the hour")
	}
}

func TestPKCEAndCodeRules(t *testing.T) {
	h, _ := homeHarness(t)
	grantJIT(t, h, "home") // empty group; user gets created on first login below
	d := newDevice("dev-1")

	// Wrong verifier burns the code.
	q, verifier := h.browserLogin("home")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "client_id": {"ligus-desktop"}, "redirect_uri": {loopback}, "code_verifier": {"wrong-" + verifier}}
	if tr := h.redeem("home", form, "code", d); tr.Error != "invalid_grant" {
		t.Fatalf("wrong verifier: %s", fmtStatus(tr))
	}
	form.Set("code_verifier", verifier)
	if tr := h.redeem("home", form, "code", d); tr.Error != "invalid_grant" {
		t.Fatalf("code must be burned after a bad verifier: %s", fmtStatus(tr))
	}

	// The callback carries iss (RFC 9207) and the client's state.
	if q.Get("iss") != h.url("home", "") || q.Get("state") != "client-state-1" {
		t.Fatalf("redirect params: %v", q)
	}

	// Redirect URI mismatch at redemption.
	q, verifier = h.browserLogin("home")
	form = url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "client_id": {"ligus-desktop"}, "redirect_uri": {"http://127.0.0.1:1/other"}, "code_verifier": {verifier}}
	if tr := h.redeem("home", form, "code", d); tr.Error != "invalid_grant" {
		t.Fatalf("redirect mismatch: %s", fmtStatus(tr))
	}

	c := browser()
	bad := func(q url.Values) *http.Response {
		return mustGet(t, c, h.url("home", "/authorize?"+q.Encode()))
	}
	base := func() url.Values {
		return url.Values{"response_type": {"code"}, "client_id": {"ligus-desktop"}, "redirect_uri": {loopback}, "state": {"s"},
			"code_challenge": {pkceChallenge("v")}, "code_challenge_method": {"S256"}}
	}
	// Non-loopback and localhost redirects are refused without redirecting.
	for _, r := range []string{"https://evil.example/cb", "http://localhost:1234/cb", "http://127.0.0.1/cb", "http://10.0.0.1:80/cb", "javascript:alert(1)"} {
		q := base()
		q.Set("redirect_uri", r)
		resp := bad(q)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("redirect %q: want 400 without redirect, got %d %q", r, resp.StatusCode, resp.Header.Get("Location"))
		}
		resp.Body.Close()
	}
	// Missing PKCE or plain PKCE: error redirect to the (valid) client.
	for name, edit := range map[string]func(url.Values){
		"no challenge":   func(q url.Values) { q.Del("code_challenge") },
		"plain":          func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"no state":       func(q url.Values) { q.Del("state") },
		"token response": func(q url.Values) { q.Set("response_type", "token") },
	} {
		q := base()
		edit(q)
		resp := bad(q)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || loc == nil || loc.Query().Get("error") == "" || !strings.HasPrefix(loc.String(), loopback) {
			t.Errorf("%s: want error redirect, got %d %v", name, resp.StatusCode, loc)
		}
	}
}

func TestDeviceFlow(t *testing.T) {
	h, _ := homeHarness(t)
	d := newDevice("serve-box")
	// Create the user and grant, then run the device flow.
	h.loginTokens("home", d)
	grantJIT(t, h, "home")

	resp, _ := http.PostForm(h.url("home", "/device_authorization"), url.Values{"client_id": {"ligus-cli"}})
	resp.Body.Close()

	dc := h.deviceLogin("home", true)
	form := url.Values{"grant_type": {grantDevice}, "device_code": {dc}, "client_id": {"ligus-cli"}}
	tr := h.redeem("home", form, "device_code", d)
	if tr.status != 200 || tr.Access == "" {
		t.Fatalf("device token: %s", fmtStatus(tr))
	}
	claims, ok := relay.VerifyToken(tr.Access, pub(h))
	if !ok || claims.Did != "serve-box" || claims.Tid != "home" {
		t.Fatalf("claims %+v", claims)
	}
	// The device code is single use.
	if tr := h.postToken("home", form); tr.Error != "invalid_grant" {
		t.Fatalf("device code reuse: %s", fmtStatus(tr))
	}
}

func TestDeviceFlowPendingSlowDownDeny(t *testing.T) {
	h, _ := homeHarness(t)
	resp, _ := http.PostForm(h.url("home", "/device_authorization"), url.Values{"client_id": {"ligus-cli"}})
	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		Interval   int    `json:"interval"`
	}
	decodeJSON(t, resp, &da)
	if len(da.UserCode) != 9 || da.Interval != 5 {
		t.Fatalf("device authorization: %+v", da)
	}
	form := url.Values{"grant_type": {grantDevice}, "device_code": {da.DeviceCode}, "client_id": {"ligus-cli"}}
	if tr := h.postToken("home", form); tr.Error != "authorization_pending" {
		t.Fatalf("want pending: %s", fmtStatus(tr))
	}
	if tr := h.postToken("home", form); tr.Error != "slow_down" {
		t.Fatalf("want slow_down: %s", fmtStatus(tr))
	}
	h.clock.Advance(11 * time.Second)
	if tr := h.postToken("home", form); tr.Error != "authorization_pending" {
		t.Fatalf("want pending after waiting: %s", fmtStatus(tr))
	}
	// Another client id cannot poll this code.
	h.clock.Advance(11 * time.Second)
	other := url.Values{"grant_type": {grantDevice}, "device_code": {da.DeviceCode}, "client_id": {"ligus-desktop"}}
	if tr := h.postToken("home", other); tr.Error != "invalid_grant" {
		t.Fatalf("other client: %s", fmtStatus(tr))
	}
	// Expiry.
	h.clock.Advance(11 * time.Minute)
	if tr := h.postToken("home", form); tr.Error != "invalid_grant" && tr.Error != "expired_token" {
		t.Fatalf("want expired: %s", fmtStatus(tr))
	}

	// Deny on the confirmation page.
	h.clock.Advance(time.Minute)
	dc := h.deviceLogin("home", false)
	h.clock.Advance(10 * time.Second)
	if tr := h.postToken("home", url.Values{"grant_type": {grantDevice}, "device_code": {dc}, "client_id": {"ligus-cli"}}); tr.Error != "access_denied" {
		t.Fatalf("want access_denied: %s", fmtStatus(tr))
	}
}

// The confirmation page is bound to the browser that signed in: a confirm_id
// alone (for example phished out of the page) cannot approve the device.
func TestDeviceConfirmNeedsTheSigningBrowser(t *testing.T) {
	h, _ := homeHarness(t)
	resp, _ := http.PostForm(h.url("home", "/device_authorization"), url.Values{"client_id": {"ligus-cli"}})
	var da struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	decodeJSON(t, resp, &da)
	c := browser()
	resp, _ = c.PostForm(h.url("home", "/device"), url.Values{"user_code": {da.UserCode}})
	toIdP := resp.Header.Get("Location")
	resp.Body.Close()
	resp = mustGet(t, c, toIdP)
	cb := resp.Header.Get("Location")
	resp.Body.Close()
	page := body(mustGet(t, c, cb))
	m := confirmIDRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no confirmation form")
	}
	// A different browser (no cookie) posts the confirm id.
	resp, _ = browser().PostForm(h.url("home", "/device/confirm"), url.Values{"confirm_id": {m[1]}, "action": {"approve"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("confirm without the cookie: want 400, got %d", resp.StatusCode)
	}
	h.clock.Advance(10 * time.Second)
	if tr := h.postToken("home", url.Values{"grant_type": {grantDevice}, "device_code": {da.DeviceCode}, "client_id": {"ligus-cli"}}); tr.Error != "authorization_pending" {
		t.Fatalf("device must still be pending: %s", fmtStatus(tr))
	}
}

func TestWrongUserCodeIsRateLimited(t *testing.T) {
	h, _ := homeHarness(t)
	c := browser()
	got429 := false
	for i := 0; i < 15; i++ {
		resp, _ := c.PostForm(h.url("home", "/device"), url.Values{"user_code": {"BCDF-GHJK"}})
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unknown code: want 400, got %d", resp.StatusCode)
		}
	}
	if !got429 {
		t.Fatal("guessing user codes must be rate limited")
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	h, _ := homeHarness(t)
	d := newDevice("dev-1")
	h.loginTokens("home", d)
	grantJIT(t, h, "home")
	first := h.loginTokens("home", d)
	if first.status != 200 {
		t.Fatalf("login: %s", fmtStatus(first))
	}
	h.clock.Advance(10 * time.Minute)
	second := h.refresh("home", first.Refresh, first.Nonce, d)
	if second.status != 200 || second.Refresh == first.Refresh {
		t.Fatalf("refresh: %s", fmtStatus(second))
	}
	c, ok := relay.VerifyToken(second.Access, pub(h))
	if !ok || c.IsExpired(h.clock.Now().Unix()) {
		t.Fatal("refreshed access token must verify and be fresh")
	}
	// The nonce is single use.
	retryStaleNonce = false
	tr := h.refresh("home", second.Refresh, first.Nonce, d)
	retryStaleNonce = true
	if tr.Error != "use_device_nonce" {
		t.Fatalf("nonce reuse must ask for a fresh nonce: %s", fmtStatus(tr))
	}
	// Replaying the rotated token is detected and kills the whole family.
	if tr := h.refresh("home", first.Refresh, "", d); tr.Error != "invalid_grant" {
		t.Fatalf("reuse: %s", fmtStatus(tr))
	}
	if tr := h.refresh("home", second.Refresh, "", d); tr.Error != "invalid_grant" {
		t.Fatalf("family must be revoked after reuse: %s", fmtStatus(tr))
	}
	if !strings.Contains(h.audit.String(), "refresh_reuse_detected") {
		t.Fatal("reuse must be audited")
	}
}

func TestRefreshIsBoundToTheDevice(t *testing.T) {
	h, _ := homeHarness(t)
	owner := newDevice("dev-owner")
	h.loginTokens("home", owner)
	grantJIT(t, h, "home")
	tr := h.loginTokens("home", owner)
	thief := newDevice("dev-thief")
	if r := h.refresh("home", tr.Refresh, "", thief); r.Error != "invalid_grant" {
		t.Fatalf("a stolen refresh token used from another device: %s", fmtStatus(r))
	}
	// Claiming the owner's device id with the thief's key fails too.
	impostor := device{id: owner.id, priv: thief.priv}
	if r := h.refresh("home", tr.Refresh, "", impostor); r.Error != "invalid_grant" {
		t.Fatalf("same device id, other key: %s", fmtStatus(r))
	}
	// A signature over a different credential does not verify.
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.Refresh}, "device_id": {owner.id}, "device_key": {owner.keyB64()}, "device_nonce": {tr.Nonce},
		"device_sig": {b64u(ed25519.Sign(owner.priv, DeviceProofMessage("home", "refresh_token", tr.Nonce, owner.id, "some-other-token")))}}
	if r := h.postToken("home", form); r.Error != "invalid_grant" {
		t.Fatalf("proof over another credential: %s", fmtStatus(r))
	}
	// The owner still refreshes (the failed attempts did not burn anything).
	if r := h.refresh("home", tr.Refresh, "", owner); r.status != 200 {
		t.Fatalf("owner refresh: %s", fmtStatus(r))
	}
}

func TestSessionMaxAgeForcesSignIn(t *testing.T) {
	h, _ := homeHarness(t)
	d := newDevice("dev-1")
	h.loginTokens("home", d)
	grantJIT(t, h, "home")
	tr := h.loginTokens("home", d)
	for i := 0; i < 6; i++ { // keep it fresh every 6 days: idle TTL never lapses
		h.clock.Advance(6 * 24 * time.Hour)
		tr = h.refresh("home", tr.Refresh, tr.Nonce, d)
		if tr.status != 200 {
			if i < 4 {
				t.Fatalf("refresh %d: %s", i, fmtStatus(tr))
			}
			return // past the 30-day session: refused, as intended
		}
	}
	t.Fatal("refresh kept working past session_max_age")
}

func TestRefreshIdleExpiry(t *testing.T) {
	h, _ := homeHarness(t)
	d := newDevice("dev-1")
	h.loginTokens("home", d)
	grantJIT(t, h, "home")
	tr := h.loginTokens("home", d)
	h.clock.Advance(8 * 24 * time.Hour)
	if r := h.refresh("home", tr.Refresh, "", d); r.Error != "invalid_grant" {
		t.Fatalf("idle refresh token must expire: %s", fmtStatus(r))
	}
}

func TestNonceIsTenantBoundAndExpires(t *testing.T) {
	clock := newClock()
	h := newHarness(t, clock,
		tenantSpec{id: "a", idp: newMockIdP(t, clock), workspaces: []string{"wa"}},
		tenantSpec{id: "b", idp: newMockIdP(t, clock), workspaces: []string{"wb"}})
	na := h.srv.newNonce("a")
	if _, ok := h.srv.checkNonce("b", na); ok {
		t.Fatal("a nonce minted for tenant a must not validate for b")
	}
	if _, ok := h.srv.checkNonce("a", na); !ok {
		t.Fatal("nonce must validate for its tenant")
	}
	clock.Advance(nonceTTL + time.Second)
	if _, ok := h.srv.checkNonce("a", na); ok {
		t.Fatal("expired nonce")
	}
	raw := []byte(na)
	raw[5] ^= 1
	if _, ok := h.srv.checkNonce("a", string(raw)); ok {
		t.Fatal("tampered nonce")
	}
}

func TestPublicRateLimit(t *testing.T) {
	h, _ := homeHarness(t)
	h.srv.publicLimit = newRateLimiter(1, 3, h.clock.Now)
	limited := false
	for i := 0; i < 6; i++ {
		resp, _ := http.PostForm(h.url("home", "/token"), url.Values{"grant_type": {"refresh_token"}})
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("public endpoints must be rate limited per IP")
	}
}

func TestMetadata(t *testing.T) {
	h, _ := homeHarness(t)
	resp, _ := http.Get(h.url("home", "/.well-known/ligus-auth"))
	var m map[string]any
	decodeJSON(t, resp, &m)
	if m["token_pubkey"] != h.srv.PublicKeyHex() || m["token_format"] != "hrt1" || m["tenant"] != "home" {
		t.Fatalf("metadata: %v", m)
	}
	resp, _ = http.Get(h.url("nope", "/.well-known/ligus-auth"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal("unknown tenant must 404")
	}
}

func TestRevokeEndsTheSession(t *testing.T) {
	h, _ := homeHarness(t)
	d := newDevice("d1")
	h.loginTokens("home", d)
	grantJIT(t, h, "home")
	tr := h.loginTokens("home", d)
	other := h.loginTokens("home", d) // a second, independent session
	// Revoking at another tenant's endpoint does nothing.
	resp, _ := http.PostForm(h.url("nope", "/revoke"), url.Values{"token": {tr.Refresh}})
	resp.Body.Close()
	resp, _ = http.PostForm(h.url("home", "/revoke"), url.Values{"token": {tr.Refresh}, "token_type_hint": {"refresh_token"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if r := h.refresh("home", tr.Refresh, tr.Nonce, d); r.Error != "invalid_grant" {
		t.Fatalf("refresh after revoke: %s", fmtStatus(r))
	}
	if r := h.refresh("home", other.Refresh, other.Nonce, d); r.status != 200 {
		t.Fatalf("the other session must survive: %s", fmtStatus(r))
	}
	resp, _ = http.PostForm(h.url("home", "/revoke"), url.Values{"token": {"unknown"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("unknown tokens answer 200 too")
	}
}

// Cross-language vector shared with the Ligus client
// (crates/ligus-runtime/src/ligus_auth.rs, device_proof_matches_ligus_auth).
func TestDeviceProofVectorFrozen(t *testing.T) {
	m := DeviceProofMessage("home", "refresh_token", "bm9uY2U", "5d0b7c1e-2f43-4a8e-9a51-0c6f3d2e1b07", "rt-123")
	const wantMsg = "6c696775732d617574682d6465766963652d70726f6f662d763100686f6d6500726566726573685f746f6b656e00626d39755932550035643062376331652d326634332d346138652d396135312d3063366633643265316230370032383165366439643761623363653837376635653361633862343334363461316130353564323533313564623364313839313466666334333133303736396539"
	if hex.EncodeToString(m) != wantMsg {
		t.Fatalf("device proof bytes drifted: %x", m)
	}
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if got := hex.EncodeToString(ed25519.Sign(k, m)); got != "fa484b92be85148eda71fa2535fa96ec6455f6ea271a802639c134a2600100dcf7191b061e7a28aff546558d293e24a6906b4d25c7dc713d7a155f00d50a830c" {
		t.Fatalf("signature drifted: %s", got)
	}
	if hex.EncodeToString([]byte(DeviceProofContext)) != "6c696775732d617574682d6465766963652d70726f6f662d763100" {
		t.Fatal("context drifted")
	}
}
