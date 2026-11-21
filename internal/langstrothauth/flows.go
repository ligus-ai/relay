package langstrothauth

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/langstroth-ai/langstroth-relay/internal/relay"
)

// DeviceProofContext is the domain-separation prefix of the device proof a
// client signs with its device Ed25519 key on every token request. It is
// listed in PHASE0-SPECS section 0.1. Frozen: never change it.
const DeviceProofContext = "ligus-auth-device-proof-v1\x00"

const (
	loginTTL      = 10 * time.Minute
	codeTTL       = time.Minute
	deviceTTL     = 10 * time.Minute
	confirmTTL    = 5 * time.Minute
	nonceTTL      = 5 * time.Minute
	pollInterval  = 5 * time.Second
	maxPending    = 10000 // cap on each in-memory flow table
	maxFormBytes  = 64 << 10
	userCodeChars = "BCDFGHJKLMNPQRSTVWXZ" // no vowels: no accidental words
	grantDevice   = "urn:ietf:params:oauth:grant-type:device_code"
)

var (
	clientIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	deviceIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	b64urlRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// loginTxn is one pending IdP sign-in, keyed by the hash of the upstream
// state. It is bound to its tenant.
type loginTxn struct {
	tenant   string
	nonce    string
	verifier string
	expires  time.Time
	// kind "authorize": the client's PKCE request to finish.
	clientID, redirectURI, clientState, challenge string
	// kind "device": the device code (hash) to approve.
	deviceHash string
}

// authCode is a langstroth-auth authorization code handed to the client's
// redirect URI; redeemable once, with the PKCE verifier.
type authCode struct {
	tenant, clientID, redirectURI, challenge string
	user                                     User
	idpGroups                                []string
	expires                                  time.Time
}

type deviceGrant struct {
	tenant   string
	clientID string
	label    string
	userCode string
	expires  time.Time
	interval time.Duration
	lastPoll time.Time
	status   string // pending | approved | denied
	user     User
	groups   []string
}

type deviceConfirm struct {
	tenant     string
	secretHash string
	deviceHash string
	user       User
	groups     []string
	expires    time.Time
}

// flowState holds the short-lived, per-process flow tables.
type flowState struct {
	mu        sync.Mutex
	logins    map[string]*loginTxn
	codes     map[string]*authCode
	devices   map[string]*deviceGrant
	userCodes map[string]string // normalized user code -> device hash
	confirms  map[string]*deviceConfirm
	nonces    map[string]time.Time // used device-proof nonces until expiry
}

func newFlowState() *flowState {
	return &flowState{
		logins: map[string]*loginTxn{}, codes: map[string]*authCode{}, devices: map[string]*deviceGrant{},
		userCodes: map[string]string{}, confirms: map[string]*deviceConfirm{}, nonces: map[string]time.Time{},
	}
}

// gc drops expired entries. Caller holds mu.
func (f *flowState) gc(now time.Time) {
	for k, v := range f.logins {
		if now.After(v.expires) {
			delete(f.logins, k)
		}
	}
	for k, v := range f.codes {
		if now.After(v.expires) {
			delete(f.codes, k)
		}
	}
	for k, v := range f.devices {
		if now.After(v.expires) {
			delete(f.userCodes, v.userCode)
			delete(f.devices, k)
		}
	}
	for k, v := range f.confirms {
		if now.After(v.expires) {
			delete(f.confirms, k)
		}
	}
	for k, exp := range f.nonces {
		if now.After(exp) {
			delete(f.nonces, k)
		}
	}
}

var errBusy = errors.New("too many pending sign-ins; try again shortly")

// ── Browser flow: authorization code + PKCE ─────────────────────────────────

// allowedRedirect reports whether a client redirect URI is acceptable:
// loopback http on any port (RFC 8252 7.3), or an exact configured URI.
func allowedRedirect(t *TenantConfig, raw string) bool {
	if len(raw) > 2048 {
		return false
	}
	for _, r := range t.RedirectURIs {
		if r == raw {
			return true
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	return (h == "127.0.0.1" || h == "::1") && u.Port() != ""
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	clientID := q.Get("client_id")
	// Until the redirect URI is known good, errors are shown here and never
	// redirected (no open redirector).
	if !clientIDRe.MatchString(clientID) {
		s.page(w, http.StatusBadRequest, "Sign-in failed", "Unknown client.")
		return
	}
	if !allowedRedirect(t, redirect) {
		s.page(w, http.StatusBadRequest, "Sign-in failed", "This redirect address is not allowed.")
		return
	}
	state := q.Get("state")
	fail := func(code string) {
		u, _ := url.Parse(redirect)
		v := u.Query()
		v.Set("error", code)
		if state != "" {
			v.Set("state", state)
		}
		v.Set("iss", s.issuerURL(t))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	challenge := q.Get("code_challenge")
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type")
		return
	case q.Get("code_challenge_method") != "S256" || len(challenge) != 43 || !b64urlRe.MatchString(challenge):
		fail("invalid_request") // PKCE S256 is mandatory
		return
	case state == "" || len(state) > 512:
		fail("invalid_request")
		return
	}
	upState, nonce, verifier := randToken(32), randToken(32), randToken(32)
	now := s.now()
	f := s.flows
	f.mu.Lock()
	f.gc(now)
	if len(f.logins) >= maxPending {
		f.mu.Unlock()
		fail("temporarily_unavailable")
		return
	}
	f.logins[sha256Hex(upState)] = &loginTxn{
		tenant: t.ID, nonce: nonce, verifier: verifier, expires: now.Add(loginTTL),
		clientID: clientID, redirectURI: redirect, clientState: state, challenge: challenge,
	}
	f.mu.Unlock()
	dest, err := s.providers[t.ID].authURL(r.Context(), s.callbackURL(t), upState, nonce, pkceChallenge(verifier))
	if err != nil {
		s.audit.event("idp_unavailable", t.ID, "reason", err.Error())
		fail("temporarily_unavailable")
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// handleCallback finishes the IdP sign-in for both flows.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	q := r.URL.Query()
	st := q.Get("state")
	now := s.now()
	f := s.flows
	f.mu.Lock()
	txn := f.logins[sha256Hex(st)]
	delete(f.logins, sha256Hex(st)) // single use, whatever happens next
	f.mu.Unlock()
	if st == "" || txn == nil || now.After(txn.expires) || txn.tenant != t.ID {
		// A state minted for another tenant is treated as unknown.
		s.audit.event("login_refused", t.ID, "reason", "unknown_state", "ip", s.clientIP(r))
		s.page(w, http.StatusBadRequest, "Sign-in failed", "This sign-in link has expired or was already used. Start again from the app.")
		return
	}
	finishErr := func(code, msg string) {
		if txn.deviceHash != "" {
			f.mu.Lock()
			if d := f.devices[txn.deviceHash]; d != nil && d.tenant == t.ID {
				d.status = "denied"
			}
			f.mu.Unlock()
			s.page(w, http.StatusForbidden, "Sign-in refused", msg)
			return
		}
		u, _ := url.Parse(txn.redirectURI)
		v := u.Query()
		v.Set("error", code)
		v.Set("state", txn.clientState)
		v.Set("iss", s.issuerURL(t))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	// RFC 9207: if the IdP names itself, it must be this tenant's IdP.
	if iss := q.Get("iss"); iss != "" && iss != t.OIDC.Issuer {
		s.audit.event("login_refused", t.ID, "reason", "issuer_mixup", "ip", s.clientIP(r))
		finishErr("access_denied", "The identity provider response came from an unexpected issuer.")
		return
	}
	if e := q.Get("error"); e != "" {
		s.audit.event("login_refused", t.ID, "reason", "idp_error", "idp_error", sanitize(e))
		finishErr("access_denied", "The identity provider did not sign you in.")
		return
	}
	code := q.Get("code")
	if code == "" {
		finishErr("invalid_request", "The identity provider returned no code.")
		return
	}
	p := s.providers[t.ID]
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rawID, err := p.exchangeCode(ctx, code, s.callbackURL(t), txn.verifier)
	if err != nil {
		s.audit.event("login_refused", t.ID, "reason", "code_exchange", "detail", err.Error())
		finishErr("server_error", "Could not complete the sign-in with the identity provider.")
		return
	}
	idc, err := p.verifyIDToken(ctx, rawID, txn.nonce)
	if err != nil {
		s.audit.event("login_refused", t.ID, "reason", "id_token", "detail", err.Error(), "ip", s.clientIP(r))
		finishErr("access_denied", "The identity provider's response could not be verified.")
		return
	}
	user, err := s.resolveUser(ctx, t, idc)
	if err != nil {
		s.audit.event("login_refused", t.ID, "reason", err.Error(), "uid", subjectHash(t.OIDC.Issuer, idc.Subject))
		finishErr("access_denied", "This account may not use this relay. Ask your administrator.")
		return
	}
	var groups []string
	if t.IDPGroups {
		groups = idc.Groups
	}
	s.audit.event("login_ok", t.ID, "user", user.ID, "uid", user.Subject, "ip", s.clientIP(r))

	if txn.deviceHash != "" {
		s.showDeviceConfirm(w, r, t, txn.deviceHash, user, groups)
		return
	}
	ourCode := randToken(32)
	f.mu.Lock()
	f.gc(now)
	if len(f.codes) >= maxPending {
		f.mu.Unlock()
		finishErr("temporarily_unavailable", "")
		return
	}
	f.codes[sha256Hex(ourCode)] = &authCode{
		tenant: t.ID, clientID: txn.clientID, redirectURI: txn.redirectURI, challenge: txn.challenge,
		user: user, idpGroups: groups, expires: now.Add(codeTTL),
	}
	f.mu.Unlock()
	u, _ := url.Parse(txn.redirectURI)
	v := u.Query()
	v.Set("code", ourCode)
	v.Set("state", txn.clientState)
	v.Set("iss", s.issuerURL(t))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// resolveUser maps verified ID token claims to a user in tenant t. It never
// looks outside t: the same IdP subject in two tenants is two users.
func (s *Server) resolveUser(ctx context.Context, t *TenantConfig, idc *IDClaims) (User, error) {
	uid := subjectHash(t.OIDC.Issuer, idc.Subject)
	u, err := s.store.FindUser(ctx, t.ID, "subject", uid)
	if err == nil {
		if !u.Active {
			return User{}, errors.New("user_inactive")
		}
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return User{}, errors.New("store_error")
	}
	link, _ := idc.Raw[t.LinkClaim].(string)
	if link != "" {
		existing, err := s.store.FindUser(ctx, t.ID, t.LinkAttr, link)
		if err == nil {
			// An account already bound to another IdP subject is never
			// re-bound (an email address reassigned at the IdP must not
			// inherit someone else's access).
			if existing.Subject != "" {
				return User{}, errors.New("bound_to_other_subject")
			}
			if t.LinkClaim == t.OIDC.ClaimMap.Email && (idc.EmailVerified == nil || !*idc.EmailVerified) {
				return User{}, errors.New("email_not_verified")
			}
			if !existing.Active {
				return User{}, errors.New("user_inactive")
			}
			existing.Subject = uid
			existing.Modified = s.now().Unix()
			if err := s.store.UpdateUser(ctx, existing); err != nil {
				return User{}, errors.New("store_error")
			}
			s.audit.event("user_linked", t.ID, "user", existing.ID, "uid", uid)
			return existing, nil
		}
	}
	if t.Provisioning == "scim" {
		return User{}, errors.New("not_provisioned")
	}
	if t.LinkClaim == t.OIDC.ClaimMap.Email && (idc.EmailVerified == nil || !*idc.EmailVerified) {
		// An unverified address is not this person's to claim. Recording it
		// as the new user's userName (or externalId) would squat the real
		// owner's name: their sign-in would then be refused, and a SCIM
		// client that looks users up by userName before adding them to
		// groups would link the squatter's record instead.
		link = ""
	}
	name := link
	if name == "" {
		name = uid
	}
	now := s.now().Unix()
	nu := User{Tenant: t.ID, ID: "u" + randToken(15), UserName: name, Active: true, Subject: uid, Created: now, Modified: now}
	if t.LinkAttr == "externalId" {
		nu.ExternalID = link
	}
	if err := s.store.CreateUser(ctx, nu); err != nil {
		if errors.Is(err, ErrConflict) {
			return User{}, errors.New("user_name_taken")
		}
		return User{}, errors.New("store_error")
	}
	s.audit.event("user_created_jit", t.ID, "user", nu.ID, "uid", uid)
	return nu, nil
}

// ── Device authorization grant (RFC 8628) ───────────────────────────────────

func normalizeUserCode(c string) string {
	c = strings.ToUpper(c)
	var b strings.Builder
	for _, r := range c {
		if strings.ContainsRune(userCodeChars, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func newUserCode() string {
	raw := make([]byte, 8)
	for i := range raw {
		// Rejection sampling for a uniform choice over 20 letters.
		for {
			b := randBytes(1)[0]
			if int(b) < 240 {
				raw[i] = userCodeChars[int(b)%len(userCodeChars)]
				break
			}
		}
	}
	return string(raw)
}

func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	if !parseForm(w, r) {
		return
	}
	clientID := r.PostForm.Get("client_id")
	if !clientIDRe.MatchString(clientID) {
		oauthErr(w, http.StatusBadRequest, "invalid_client", "")
		return
	}
	label := sanitize(r.PostForm.Get("device_label"))
	deviceCode := randToken(32)
	now := s.now()
	f := s.flows
	f.mu.Lock()
	f.gc(now)
	if len(f.devices) >= maxPending {
		f.mu.Unlock()
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", errBusy.Error())
		return
	}
	var uc string
	for {
		uc = newUserCode()
		if _, clash := f.userCodes[uc]; !clash {
			break
		}
	}
	h := sha256Hex(deviceCode)
	f.devices[h] = &deviceGrant{tenant: t.ID, clientID: clientID, label: label, userCode: uc, expires: now.Add(deviceTTL), interval: pollInterval, status: "pending"}
	f.userCodes[uc] = h
	f.mu.Unlock()
	display := uc[:4] + "-" + uc[4:]
	verify := s.issuerURL(t) + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 display,
		"verification_uri":          verify,
		"verification_uri_complete": verify + "?user_code=" + display,
		"expires_in":                int(deviceTTL.Seconds()),
		"interval":                  int(pollInterval.Seconds()),
	})
	s.audit.event("device_code_issued", t.ID, "client", clientID, "ip", s.clientIP(r))
}

func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	s.render(w, http.StatusOK, devicePageTmpl, map[string]any{
		"Tenant": tenantName(t), "Action": s.issuerURL(t) + "/device", "UserCode": sanitize(r.URL.Query().Get("user_code")),
	}, originOf(t.OIDC.Issuer))
}

func (s *Server) handleDeviceSubmit(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	ip := s.clientIP(r)
	if !s.codeLimit.allow(t.ID + "|" + s.limitKey(r)) {
		s.page(w, http.StatusTooManyRequests, "Too many attempts", "Wait a minute, then try the code again.")
		return
	}
	if !parseForm(w, r) {
		return
	}
	uc := normalizeUserCode(r.PostForm.Get("user_code"))
	now := s.now()
	f := s.flows
	f.mu.Lock()
	h := f.userCodes[uc]
	d := f.devices[h]
	ok := len(uc) == 8 && d != nil && d.tenant == t.ID && d.status == "pending" && now.Before(d.expires)
	f.mu.Unlock()
	if !ok {
		s.audit.event("device_code_rejected", t.ID, "ip", ip)
		s.page(w, http.StatusBadRequest, "Code not recognised", "Check the code shown on your device and try again.")
		return
	}
	upState, nonce, verifier := randToken(32), randToken(32), randToken(32)
	f.mu.Lock()
	f.gc(now)
	if len(f.logins) >= maxPending {
		f.mu.Unlock()
		s.page(w, http.StatusServiceUnavailable, "Busy", errBusy.Error())
		return
	}
	f.logins[sha256Hex(upState)] = &loginTxn{tenant: t.ID, nonce: nonce, verifier: verifier, expires: now.Add(loginTTL), deviceHash: h}
	f.mu.Unlock()
	dest, err := s.providers[t.ID].authURL(r.Context(), s.callbackURL(t), upState, nonce, pkceChallenge(verifier))
	if err != nil {
		s.audit.event("idp_unavailable", t.ID, "reason", err.Error())
		s.page(w, http.StatusBadGateway, "Identity provider unavailable", "Try again in a moment.")
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

const confirmCookie = "ligus_auth_confirm"

// showDeviceConfirm asks the person, after the IdP sign-in, to approve the
// specific device. The confirmation is bound to this browser by a cookie.
func (s *Server) showDeviceConfirm(w http.ResponseWriter, r *http.Request, t *TenantConfig, deviceHash string, user User, groups []string) {
	now := s.now()
	f := s.flows
	f.mu.Lock()
	d := f.devices[deviceHash]
	if d == nil || d.tenant != t.ID || d.status != "pending" || now.After(d.expires) {
		f.mu.Unlock()
		s.page(w, http.StatusBadRequest, "Code expired", "Start the sign-in again on your device.")
		return
	}
	label := d.label
	userCode := d.userCode
	f.gc(now)
	if len(f.confirms) >= maxPending {
		f.mu.Unlock()
		s.page(w, http.StatusServiceUnavailable, "Busy", errBusy.Error())
		return
	}
	id, secret := randToken(16), randToken(32)
	f.confirms[id] = &deviceConfirm{tenant: t.ID, secretHash: sha256Hex(secret), deviceHash: deviceHash, user: user, groups: groups, expires: now.Add(confirmTTL)}
	f.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: confirmCookie, Value: secret, Path: "/t/" + t.ID + "/device",
		HttpOnly: true, Secure: strings.HasPrefix(s.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteStrictMode, MaxAge: int(confirmTTL.Seconds()),
	})
	if label == "" {
		label = "a device"
	}
	s.render(w, http.StatusOK, confirmPageTmpl, map[string]any{
		"Tenant": tenantName(t), "Action": s.issuerURL(t) + "/device/confirm", "ID": id,
		"Label": label, "Code": userCode[:4] + "-" + userCode[4:],
	}, "")
}

func (s *Server) handleDeviceConfirm(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	if !parseForm(w, r) {
		return
	}
	id := r.PostForm.Get("confirm_id")
	cookie, _ := r.Cookie(confirmCookie)
	now := s.now()
	f := s.flows
	f.mu.Lock()
	c := f.confirms[id]
	delete(f.confirms, id)
	if c == nil || c.tenant != t.ID || now.After(c.expires) || cookie == nil || !constEq(sha256Hex(cookie.Value), c.secretHash) {
		f.mu.Unlock()
		s.page(w, http.StatusBadRequest, "Confirmation expired", "Start the sign-in again on your device.")
		return
	}
	d := f.devices[c.deviceHash]
	if d == nil || d.tenant != t.ID || d.status != "pending" || now.After(d.expires) {
		f.mu.Unlock()
		s.page(w, http.StatusBadRequest, "Code expired", "Start the sign-in again on your device.")
		return
	}
	approve := r.PostForm.Get("action") == "approve"
	if approve {
		d.status, d.user, d.groups = "approved", c.user, c.groups
	} else {
		d.status = "denied"
	}
	f.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: confirmCookie, Value: "", Path: "/t/" + t.ID + "/device", MaxAge: -1})
	if approve {
		s.audit.event("device_approved", t.ID, "user", c.user.ID)
		s.page(w, http.StatusOK, "Device approved", "You can close this window and return to your device.")
		return
	}
	s.audit.event("device_denied", t.ID, "user", c.user.ID)
	s.page(w, http.StatusOK, "Sign-in denied", "The device was not signed in.")
}

// ── Token endpoint ───────────────────────────────────────────────────────────

// deviceProof is the client's proof of possession of its device key.
type deviceProof struct {
	id, key, nonce, sig string
}

func proofFrom(r *http.Request) deviceProof {
	return deviceProof{id: r.PostForm.Get("device_id"), key: r.PostForm.Get("device_key"), nonce: r.PostForm.Get("device_nonce"), sig: r.PostForm.Get("device_sig")}
}

// DeviceProofMessage is the exact byte string a client signs: the context,
// then tenant, grant type, nonce, device id and the hex SHA-256 of the grant
// credential (code, device code or refresh token), NUL-separated.
func DeviceProofMessage(tenant, grantType, nonce, deviceID, credential string) []byte {
	var b strings.Builder
	b.WriteString(DeviceProofContext)
	for i, p := range []string{tenant, grantType, nonce, deviceID, sha256Hex(credential)} {
		if i > 0 {
			b.WriteByte(0)
		}
		b.WriteString(p)
	}
	return []byte(b.String())
}

// newNonce mints a stateless device-proof nonce: expiry, randomness and an
// HMAC binding both to the tenant. Single use is enforced on redemption.
func (s *Server) newNonce(tenant string) string { return s.newNonceTTL(tenant, nonceTTL) }

// newNonceTTL mints a nonce valid for ttl. Token responses hand the client a
// nonce for its next refresh, so that one lives a little past the access
// token; single use and the rotating refresh token keep it from replaying.
func (s *Server) newNonceTTL(tenant string, ttl time.Duration) string {
	buf := make([]byte, 8, 8+16+16)
	binary.BigEndian.PutUint64(buf, uint64(s.now().Add(ttl).Unix()))
	buf = append(buf, randBytes(16)...)
	m := hmac.New(sha256.New, s.nonceKey)
	m.Write([]byte(tenant))
	m.Write([]byte{0})
	m.Write(buf)
	buf = append(buf, m.Sum(nil)[:16]...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// checkNonce validates a nonce for tenant without consuming it.
func (s *Server) checkNonce(tenant, n string) (time.Time, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil || len(raw) != 40 {
		return time.Time{}, false
	}
	m := hmac.New(sha256.New, s.nonceKey)
	m.Write([]byte(tenant))
	m.Write([]byte{0})
	m.Write(raw[:24])
	if !hmac.Equal(m.Sum(nil)[:16], raw[24:]) {
		return time.Time{}, false
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	if s.now().After(exp) {
		return time.Time{}, false
	}
	s.flows.mu.Lock()
	_, used := s.flows.nonces[n]
	s.flows.mu.Unlock()
	return exp, !used
}

// verifyProof checks the device proof. It returns ok=false with
// needNonce=true when the client should retry with a fresh nonce.
func (s *Server) verifyProof(t *TenantConfig, grantType, credential string, p deviceProof) (ok, needNonce bool) {
	if p.nonce == "" {
		return false, true
	}
	exp, fresh := s.checkNonce(t.ID, p.nonce)
	if !fresh {
		return false, true
	}
	if !deviceIDRe.MatchString(p.id) {
		return false, false
	}
	key, err := base64.RawURLEncoding.DecodeString(p.key)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(p.sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, false
	}
	if !ed25519.Verify(ed25519.PublicKey(key), DeviceProofMessage(t.ID, grantType, p.nonce, p.id, credential), sig) {
		return false, false
	}
	// Consume the nonce only on a valid proof, so junk cannot burn a
	// legitimate client's nonce.
	s.flows.mu.Lock()
	defer s.flows.mu.Unlock()
	if _, used := s.flows.nonces[p.nonce]; used {
		return false, true
	}
	if len(s.flows.nonces) >= 10*maxPending {
		s.flows.gc(s.now())
	}
	s.flows.nonces[p.nonce] = exp
	return true, false
}

func (s *Server) needNonce(w http.ResponseWriter, t *TenantConfig) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":             "use_device_nonce",
		"error_description": "sign the token request with your device key over this nonce",
		"device_nonce":      s.newNonce(t.ID),
	})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	if !parseForm(w, r) {
		return
	}
	switch gt := r.PostForm.Get("grant_type"); gt {
	case "authorization_code":
		s.tokenFromCode(w, r, t)
	case grantDevice:
		s.tokenFromDevice(w, r, t)
	case "refresh_token":
		s.tokenFromRefresh(w, r, t)
	default:
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	code := r.PostForm.Get("code")
	h := sha256Hex(code)
	now := s.now()
	f := s.flows
	f.mu.Lock()
	c := f.codes[h]
	f.mu.Unlock()
	if code == "" || c == nil || c.tenant != t.ID || now.After(c.expires) {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if r.PostForm.Get("client_id") != c.clientID || r.PostForm.Get("redirect_uri") != c.redirectURI ||
		!constEq(pkceChallenge(r.PostForm.Get("code_verifier")), c.challenge) {
		// A wrong verifier burns the code: it may be an interception attempt.
		f.mu.Lock()
		delete(f.codes, h)
		f.mu.Unlock()
		s.audit.event("token_refused", t.ID, "reason", "pkce_or_client_mismatch", "ip", s.clientIP(r))
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	p := proofFrom(r)
	if ok, need := s.verifyProof(t, "authorization_code", code, p); !ok {
		if need {
			s.needNonce(w, t)
			return
		}
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "device proof failed")
		return
	}
	f.mu.Lock()
	c, still := f.codes[h]
	delete(f.codes, h)
	f.mu.Unlock()
	if !still {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	s.issue(w, r, t, c.user, c.clientID, p, c.idpGroups, now.Unix(), "", "")
}

func (s *Server) tokenFromDevice(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	dc := r.PostForm.Get("device_code")
	h := sha256Hex(dc)
	now := s.now()
	f := s.flows
	f.mu.Lock()
	d := f.devices[h]
	if dc == "" || d == nil || d.tenant != t.ID || d.clientID != r.PostForm.Get("client_id") {
		f.mu.Unlock()
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if now.After(d.expires) {
		f.mu.Unlock()
		oauthErr(w, http.StatusBadRequest, "expired_token", "")
		return
	}
	if !d.lastPoll.IsZero() && now.Sub(d.lastPoll) < d.interval {
		d.interval += 5 * time.Second
		d.lastPoll = now
		f.mu.Unlock()
		oauthErr(w, http.StatusBadRequest, "slow_down", "")
		return
	}
	d.lastPoll = now
	status := d.status
	f.mu.Unlock()
	switch status {
	case "pending":
		oauthErr(w, http.StatusBadRequest, "authorization_pending", "")
		return
	case "denied":
		oauthErr(w, http.StatusBadRequest, "access_denied", "")
		return
	}
	p := proofFrom(r)
	if ok, need := s.verifyProof(t, grantDevice, dc, p); !ok {
		if need {
			// The nonce round trip is not a poll: let the client retry now.
			f.mu.Lock()
			d.lastPoll = time.Time{}
			f.mu.Unlock()
			s.needNonce(w, t)
			return
		}
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "device proof failed")
		return
	}
	f.mu.Lock()
	d, still := f.devices[h]
	if still {
		delete(f.userCodes, d.userCode)
		delete(f.devices, h)
	}
	f.mu.Unlock()
	if !still || d.status != "approved" {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	s.issue(w, r, t, d.user, d.clientID, p, d.groups, now.Unix(), "", "")
}

func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	raw := r.PostForm.Get("refresh_token")
	ctx := r.Context()
	now := s.now()
	rt, err := s.store.GetRefresh(ctx, sha256Hex(raw))
	if raw == "" || err != nil || rt.Tenant != t.ID {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if rt.Revoked {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if rt.Used {
		// A rotated token came back: someone holds a copy. Kill the family.
		_ = s.store.RevokeFamily(ctx, t.ID, rt.FamilyID)
		s.audit.event("refresh_reuse_detected", t.ID, "user", rt.UserID, "did", rt.DeviceID, "ip", s.clientIP(r))
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if now.Unix() >= rt.ExpiresAt || now.Sub(time.Unix(rt.SessionStart, 0)) >= s.cfg.SessionMaxAge.D() {
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "session expired; sign in again")
		return
	}
	p := proofFrom(r)
	if p.id != rt.DeviceID || p.key != rt.DeviceKey {
		if p.nonce == "" && p.id == "" {
			s.needNonce(w, t)
			return
		}
		s.audit.event("token_refused", t.ID, "reason", "refresh_device_mismatch", "user", rt.UserID, "ip", s.clientIP(r))
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "refresh token is bound to another device")
		return
	}
	if ok, need := s.verifyProof(t, "refresh_token", raw, p); !ok {
		if need {
			s.needNonce(w, t)
			return
		}
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "device proof failed")
		return
	}
	user, err := s.store.GetUser(ctx, t.ID, rt.UserID)
	if err != nil || !user.Active {
		_ = s.store.RevokeFamily(ctx, t.ID, rt.FamilyID)
		s.audit.event("token_refused", t.ID, "reason", "user_inactive", "user", rt.UserID)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	s.issue(w, r, t, user, rt.ClientID, p, rt.IdPGroups, rt.SessionStart, rt.Hash, rt.FamilyID)
}

// effectiveWorkspaces is the union of the workspaces granted to the user's
// SCIM groups (and IdP groups when trusted), limited to what the tenant
// owns. Ownership is re-checked here, at mint time, so a stale or tampered
// grant row can never reach another tenant's workspace.
func (s *Server) effectiveWorkspaces(ctx context.Context, t *TenantConfig, user User, idpGroups []string) ([]string, error) {
	groups, err := s.store.UserGroupNames(ctx, t.ID, user.ID)
	if err != nil {
		return nil, err
	}
	if t.IDPGroups {
		groups = append(groups, idpGroups...)
	}
	grants, err := s.store.ListGrants(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	var ws []string
	for _, g := range sortedUnique(groups) {
		for _, w := range grants[g] {
			if t.owns(w) {
				ws = append(ws, w)
			}
		}
	}
	ws = sortedUnique(ws)
	if contains(ws, "*") {
		ws = []string{"*"}
	}
	return ws, nil
}

// issue mints an access token and a refresh token. oldHash/family are set on
// a refresh (rotation); empty starts a new family.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, t *TenantConfig, user User, clientID string, p deviceProof, idpGroups []string, sessionStart int64, oldHash, family string) {
	ctx := r.Context()
	now := s.now()
	ws, err := s.effectiveWorkspaces(ctx, t, user, idpGroups)
	if err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if len(ws) == 0 {
		// Never mint a token without a workspaces claim: on a relay in
		// "claims" scope mode that would mean every workspace.
		s.audit.event("token_refused", t.ID, "reason", "no_workspace_grants", "user", user.ID)
		oauthErr(w, http.StatusForbidden, "access_denied", "no workspace is granted to this account")
		return
	}
	newRaw := randToken(32)
	rt := RefreshToken{
		Hash: sha256Hex(newRaw), Tenant: t.ID, UserID: user.ID, ClientID: clientID,
		DeviceID: p.id, DeviceKey: p.key, IdPGroups: idpGroups, SessionStart: sessionStart,
		ExpiresAt: now.Add(s.cfg.RefreshIdleTTL.D()).Unix(), CreatedAt: now.Unix(),
	}
	if maxEnd := sessionStart + int64(s.cfg.SessionMaxAge.D().Seconds()); rt.ExpiresAt > maxEnd {
		rt.ExpiresAt = maxEnd
	}
	if oldHash != "" {
		rt.FamilyID = family
		if err := s.store.RotateRefresh(ctx, oldHash, rt); err != nil {
			if errors.Is(err, ErrRefreshReused) {
				s.audit.event("refresh_reuse_detected", t.ID, "user", user.ID, "did", p.id)
			}
			oauthErr(w, http.StatusBadRequest, "invalid_grant", "")
			return
		}
	} else {
		rt.FamilyID = randToken(16)
		if err := s.store.PutRefresh(ctx, rt); err != nil {
			oauthErr(w, http.StatusInternalServerError, "server_error", "")
			return
		}
	}
	caps := append([]string{}, t.Caps...)
	claims := relay.TokenClaims{
		Sub: t.ID + ":" + user.ID, Plan: t.Plan, Exp: uint64(now.Add(s.cfg.AccessTTL.D()).Unix()),
		MaxMembers: t.MaxMembers, RetentionDays: t.RetentionDays, Turn: t.Turn, Caps: caps,
		Workspaces: ws, Tid: t.ID, Uid: user.Subject, Did: p.id,
	}
	access := relay.IssueToken(s.key, claims)
	event := "token_minted"
	if oldHash != "" {
		event = "token_refreshed"
	}
	s.audit.event(event, t.ID, "user", user.ID, "uid", user.Subject, "did", p.id, "workspaces", len(ws), "ip", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       access,
		"token_type":         "Bearer",
		"expires_in":         int(s.cfg.AccessTTL.D().Seconds()),
		"refresh_token":      newRaw,
		"refresh_expires_in": rt.ExpiresAt - now.Unix(),
		"device_nonce":       s.newNonceTTL(t.ID, s.cfg.AccessTTL.D()+nonceTTL),
		"sub":                claims.Sub,
		"tid":                t.ID,
		"workspaces":         ws,
	})
}

// handleRevoke implements RFC 7009 for refresh tokens (sign-out). Holding
// the refresh token is enough to revoke its whole session; the answer is
// 200 whether or not the token was known, so it reveals nothing.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	if !parseForm(w, r) {
		return
	}
	if raw := r.PostForm.Get("token"); raw != "" {
		if rt, err := s.store.GetRefresh(r.Context(), sha256Hex(raw)); err == nil && rt.Tenant == t.ID {
			if err := s.store.RevokeFamily(r.Context(), t.ID, rt.FamilyID); err != nil {
				oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
				return
			}
			s.audit.event("session_revoked", t.ID, "user", rt.UserID, "did", rt.DeviceID)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "")
		return false
	}
	return true
}

func oauthErr(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

// originOf returns scheme://host[:port] of a URL ("" if it does not parse).
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func tenantName(t *TenantConfig) string {
	if t.DisplayName != "" {
		return t.DisplayName
	}
	return t.ID
}

// ── pages ────────────────────────────────────────────────────────────────────

const pageHead = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ligus sign-in</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#1d1d1f;background:#fbfaf7}
h1{font-size:1.4rem}input{font:inherit;font-size:1.3rem;letter-spacing:.15em;padding:.4rem;width:100%;box-sizing:border-box;text-transform:uppercase}
button{font:inherit;padding:.5rem 1rem;margin:.75rem .5rem 0 0}code{font-size:1.2rem}
@media (prefers-color-scheme:dark){body{background:#151513;color:#eee}}</style></head><body>`

var (
	devicePageTmpl = template.Must(template.New("device").Parse(pageHead + `<h1>Sign in a device to {{.Tenant}}</h1>
<p>Enter the code shown on your device.</p>
<form method="post" action="{{.Action}}"><input name="user_code" value="{{.UserCode}}" autocomplete="off" autofocus required>
<button type="submit">Continue</button></form></body></html>`))
	confirmPageTmpl = template.Must(template.New("confirm").Parse(pageHead + `<h1>Approve this sign-in?</h1>
<p>{{.Label}} is asking to use {{.Tenant}} as you. It showed the code <code>{{.Code}}</code>.</p>
<p>Only approve if you started this on your own device and the code matches.</p>
<form method="post" action="{{.Action}}"><input type="hidden" name="confirm_id" value="{{.ID}}">
<button type="submit" name="action" value="approve">Approve</button><button type="submit" name="action" value="deny">Deny</button></form></body></html>`))
	messagePageTmpl = template.Must(template.New("msg").Parse(pageHead + `<h1>{{.Title}}</h1><p>{{.Msg}}</p></body></html>`))
)

func (s *Server) page(w http.ResponseWriter, status int, title, msg string) {
	s.render(w, status, messagePageTmpl, map[string]string{"Title": title, "Msg": msg}, "")
}

func (s *Server) render(w http.ResponseWriter, status int, tmpl *template.Template, data any, formTarget string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// form-action must also allow the IdP: browsers apply it to the redirect
	// that follows the device-code form post.
	formAction := "'self'"
	if formTarget != "" {
		formAction += " " + formTarget
	}
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_ = tmpl.Execute(w, data)
}
