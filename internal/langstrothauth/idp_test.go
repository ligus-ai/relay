package langstrothauth

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

// loginOutcome runs the browser flow and reports the error code the client
// received ("" on success).
func loginOutcome(t *testing.T, h *harness, tenant string) string {
	t.Helper()
	q, _ := h.browserLogin(tenant)
	if q.Get("code") != "" && q.Get("error") == "" {
		return ""
	}
	return q.Get("error")
}

// A malicious or broken IdP: every variation must be refused at the callback,
// before any user is resolved or token minted.
func maliciousCases() map[string]func(m *mockIdP) {
	return map[string]func(m *mockIdP){
		"alg none": func(m *mockIdP) {
			m.rawToken = func(c map[string]any) string {
				hb, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
				cb, _ := json.Marshal(c)
				return b64u(hb) + "." + b64u(cb) + "."
			}
		},
		"HS256 keyed with the public key": func(m *mockIdP) {
			m.rawToken = func(c map[string]any) string {
				hb, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": "k1"})
				cb, _ := json.Marshal(c)
				signing := b64u(hb) + "." + b64u(cb)
				der := x509.MarshalPKCS1PublicKey(&testRSA(0).PublicKey)
				mac := hmac.New(sha256.New, der)
				mac.Write([]byte(signing))
				return signing + "." + b64u(mac.Sum(nil))
			}
		},
		"signed by a key not in the JWKS": func(m *mockIdP) { m.signer = rsaMockKey("k1", 1) },
		"unknown kid":                     func(m *mockIdP) { m.signer = rsaMockKey("k-unknown", 1) },
		"wrong issuer": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["iss"] = "https://other-idp.example" }
		},
		"wrong audience": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["aud"] = "someone-else" }
		},
		"multiple audiences without azp": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["aud"] = []string{m.clientID, "other"} }
		},
		"azp for another client": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["azp"] = "other" }
		},
		"expired": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["exp"] = m.clock.Now().Add(-2 * time.Minute).Unix() }
		},
		"issued in the future": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["iat"] = m.clock.Now().Add(5 * time.Minute).Unix() }
		},
		"issued long ago": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["iat"] = m.clock.Now().Add(-2 * time.Hour).Unix() }
		},
		"not yet valid": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["nbf"] = m.clock.Now().Add(10 * time.Minute).Unix() }
		},
		"nonce replaced": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { c["nonce"] = "attacker-nonce" }
		},
		"nonce missing": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { delete(c, "nonce") }
		},
		"subject missing": func(m *mockIdP) {
			m.mutate = func(c map[string]any) { delete(c, "sub") }
		},
		"embedded jwk header": func(m *mockIdP) {
			m.header = func(k mockKey) map[string]any {
				return map[string]any{"alg": k.alg, "kid": k.kid, "jwk": k.jwk}
			}
		},
		"jku header": func(m *mockIdP) {
			m.header = func(k mockKey) map[string]any {
				return map[string]any{"alg": k.alg, "kid": k.kid, "jku": "https://evil.example/jwks"}
			}
		},
		"crit header": func(m *mockIdP) {
			m.header = func(k mockKey) map[string]any {
				return map[string]any{"alg": k.alg, "kid": k.kid, "crit": []string{"exp"}}
			}
		},
		"alg header mismatches key": func(m *mockIdP) {
			m.header = func(k mockKey) map[string]any { return map[string]any{"alg": "ES256", "kid": k.kid} }
		},
		"payload swapped after signing": func(m *mockIdP) {
			m.rawToken = func(c map[string]any) string {
				tok := signJWT(m.signer, nil, c)
				parts := strings.Split(tok, ".")
				c["sub"] = "admin"
				cb, _ := json.Marshal(c)
				return parts[0] + "." + b64u(cb) + "." + parts[2]
			}
		},
		"callback names another issuer (mix-up)": func(m *mockIdP) {
			m.callbackQ = func(q url.Values) { q.Set("iss", "https://other-idp.example") }
		},
		"idp error": func(m *mockIdP) {
			m.callbackQ = func(q url.Values) { q.Del("code"); q.Set("error", "access_denied") }
		},
	}
}

// wantRefusal is the audited reason each malicious case must be refused for
// (so a case cannot pass by failing somewhere unrelated).
var wantRefusal = map[string]string{
	"alg none": "algorithm not allowed: none", "HS256 keyed with the public key": "algorithm not allowed: HS256",
	"signed by a key not in the JWKS": "rejected: signature", "unknown kid": "no matching key",
	"wrong issuer": "rejected: issuer", "wrong audience": "rejected: audience",
	"multiple audiences without azp": "authorized party", "azp for another client": "authorized party",
	"expired": "rejected: expired", "issued in the future": "issued-at", "issued long ago": "issued-at",
	"not yet valid": "not yet valid", "nonce replaced": "rejected: nonce", "nonce missing": "rejected: nonce",
	"subject missing": "subject claim", "embedded jwk header": "embedded or remote key", "jku header": "embedded or remote key",
	"crit header": "crit header", "alg header mismatches key": "no matching key", "payload swapped after signing": "rejected: signature",
	"callback names another issuer (mix-up)": "issuer_mixup", "idp error": "idp_error",
}

func TestMaliciousIdPTokensAreRefused(t *testing.T) {
	for name, setup := range maliciousCases() {
		t.Run(name, func(t *testing.T) {
			h, idp := homeHarness(t)
			idp.set(setup)
			if got := loginOutcome(t, h, "home"); got == "" {
				t.Fatal("login must be refused")
			}
			want, ok := wantRefusal[name]
			if !ok || !strings.Contains(h.audit.String(), want) {
				t.Fatalf("refused for the wrong reason (want %q): %s", want, h.audit.String())
			}
			users, _ := h.store.ListUsers(t.Context(), "home")
			if len(users) != 0 {
				t.Fatal("no user may be created from a refused ID token")
			}
		})
	}
}

func TestClockSkewWithinLeewayIsAccepted(t *testing.T) {
	h, idp := homeHarness(t)
	idp.set(func(m *mockIdP) {
		m.mutate = func(c map[string]any) {
			c["iat"] = m.clock.Now().Add(30 * time.Second).Unix() // IdP clock 30s ahead
			c["exp"] = m.clock.Now().Add(-30 * time.Second).Unix()
		}
	})
	if got := loginOutcome(t, h, "home"); got != "" {
		t.Fatalf("30s of skew is inside the 60s leeway, got %q", got)
	}
}

func TestOtherAlgorithmsVerify(t *testing.T) {
	for _, k := range []mockKey{ecMockKey("ec1"), edMockKey("ed1")} {
		t.Run(k.alg, func(t *testing.T) {
			h, idp := homeHarness(t)
			idp.set(func(m *mockIdP) { m.published, m.signer = []mockKey{k}, k })
			if got := loginOutcome(t, h, "home"); got != "" {
				t.Fatalf("%s login: %q", k.alg, got)
			}
		})
	}
}

func TestAllowedAlgsAreEnforced(t *testing.T) {
	h, idp := homeHarness(t)
	h.cfg.Tenants[0].OIDC.AllowedAlgs = []string{"ES256"}
	_ = idp
	if got := loginOutcome(t, h, "home"); got == "" {
		t.Fatal("RS256 must be refused when only ES256 is allowed")
	}
}

func TestDiscoveryIssuerMismatchIsRefused(t *testing.T) {
	h, idp := homeHarness(t)
	idp.set(func(m *mockIdP) { m.discIssuer = "https://impostor.example" })
	c := browser()
	q := url.Values{"response_type": {"code"}, "client_id": {"ligus-desktop"}, "redirect_uri": {loopback}, "state": {"s"},
		"code_challenge": {pkceChallenge("v")}, "code_challenge_method": {"S256"}}
	resp := mustGet(t, c, h.url("home", "/authorize?"+q.Encode()))
	loc, _ := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if loc == nil || loc.Query().Get("error") != "temporarily_unavailable" {
		t.Fatalf("discovery with a foreign issuer must not be used: %v", loc)
	}
}

func TestWeakAndOffCurveKeysAreIgnored(t *testing.T) {
	weak := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}
	if _, err := (jwk{Kty: "RSA", N: b64u(weak.N.Bytes()), E: b64u([]byte{1, 0, 1})}).publicKey(); err == nil {
		t.Fatal("a 1024-bit RSA key must be refused")
	}
	bad := jwk{Kty: "EC", Crv: "P-256", X: b64u(make([]byte, 32)), Y: b64u(append(make([]byte, 31), 1))}
	if _, err := bad.publicKey(); err == nil {
		t.Fatal("an EC point off the curve must be refused")
	}
}

func TestJWKSRotation(t *testing.T) {
	h, idp := homeHarness(t)
	if got := loginOutcome(t, h, "home"); got != "" {
		t.Fatalf("initial login: %q", got)
	}
	// The IdP rotates: publishes k2 next to k1 and signs with k2. langstroth-auth
	// sees an unknown kid and refetches.
	k2 := rsaMockKey("k2", 2)
	idp.set(func(m *mockIdP) { m.published = append(m.published, k2); m.signer = k2 })
	h.clock.Advance(jwksMinRefetch + time.Second)
	if got := loginOutcome(t, h, "home"); got != "" {
		t.Fatalf("login after rotation: %q", got)
	}
	// k1 is retired. Once the cached set expires, k1 signatures fail.
	idp.set(func(m *mockIdP) { m.published = []mockKey{k2}; m.signer = rsaMockKey("k1", 0) })
	h.clock.Advance(jwksDefaultTTL + time.Second)
	if got := loginOutcome(t, h, "home"); got == "" {
		t.Fatal("a retired key must stop verifying after the JWKS refresh")
	}
}

func TestUnknownKidFloodIsBounded(t *testing.T) {
	h, idp := homeHarness(t)
	loginOutcome(t, h, "home")
	idp.set(func(m *mockIdP) { m.signer = rsaMockKey("never-published", 1); m.jwksHits = 0 })
	for i := 0; i < 10; i++ {
		loginOutcome(t, h, "home")
	}
	idp.mu.Lock()
	hits := idp.jwksHits
	idp.mu.Unlock()
	if hits > 1 {
		t.Fatalf("unknown kids must not trigger a JWKS fetch each time: %d fetches", hits)
	}
}

func TestEmailLinkingRules(t *testing.T) {
	clock := newClock()
	idp := newMockIdP(t, clock)
	h := newHarness(t, clock, tenantSpec{id: "corp", idp: idp, workspaces: []string{"w1"}, grants: map[string][]string{"eng": {"w1"}}, provisioning: "scim", scimToken: testSCIMToken})
	uid := h.scimUser("corp", "alice@example.com")
	h.scimGroup("corp", "eng", uid)

	// Unverified email cannot claim the provisioned account.
	idp.set(func(m *mockIdP) { m.user.emailVerified = boolp(false) })
	if got := loginOutcome(t, h, "corp"); got != "access_denied" {
		t.Fatalf("unverified email: %q", got)
	}
	idp.set(func(m *mockIdP) { m.user.emailVerified = nil })
	if got := loginOutcome(t, h, "corp"); got != "access_denied" {
		t.Fatalf("missing email_verified: %q", got)
	}
	// Verified: linked and bound to the IdP subject.
	idp.set(func(m *mockIdP) { m.user.emailVerified = boolp(true) })
	d := newDevice("d1")
	if tr := h.loginTokens("corp", d); tr.status != 200 {
		t.Fatalf("verified login: %s", fmtStatus(tr))
	}
	// Someone else at the IdP later gets the same email: refused.
	idp.set(func(m *mockIdP) { m.user.sub = "mallory-sub" })
	if got := loginOutcome(t, h, "corp"); got != "access_denied" {
		t.Fatalf("a different subject with the same email: %q", got)
	}
	// SCIM mode: an unprovisioned person is refused.
	idp.set(func(m *mockIdP) {
		m.user = idpUser{sub: "bob-sub", email: "bob@example.com", emailVerified: boolp(true)}
	})
	if got := loginOutcome(t, h, "corp"); got != "access_denied" {
		t.Fatalf("unprovisioned user in scim mode: %q", got)
	}
}
