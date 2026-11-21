package relay

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Frozen hrt1 vectors: tokens minted before the langstroth-auth claims (tid, uid,
// did) existed. Adding the optional claims must leave these bytes unchanged.
const (
	frozenHrt1Team  = "hrt1.eyJzdWIiOiJvcmdfYWNtZSIsInBsYW4iOiJ0ZWFtIiwiZXhwIjoxODkzNDU2MDAwLCJtYXhfbWVtYmVycyI6NTAsInJldGVudGlvbl9kYXlzIjpudWxsLCJ0dXJuIjp0cnVlLCJjYXBzIjpbInJlbW92ZV9tZW1iZXIiXX0.rh_sCYEkkaVTwN7M3MErF5k5Ys7c7s2UhqNFiUeFvte4vpvnIrdDiCwyVNZv9Jl-MGrbMfmraTvQNeQBAfowDw"
	frozenHrt1Scope = "hrt1.eyJzdWIiOiJnaXRodWI6MSIsInBsYW4iOiIiLCJleHAiOjAsIm1heF9tZW1iZXJzIjpudWxsLCJyZXRlbnRpb25fZGF5cyI6bnVsbCwidHVybiI6ZmFsc2UsImNhcHMiOltdLCJ3b3Jrc3BhY2VzIjpbIndzQSJdfQ.RMLSmPxiHjTn27VYBqlgfK1LDxZve95HOePMH8Ah3GX0GW7H1qnh6sJkf9qiN96T1S4BqWa672_tALRvN71iAg"
)

func TestFrozenHrt1VectorsUnchanged(t *testing.T) {
	sk := testKey(t)
	m := uint32(50)
	if got := issueToken(sk, TokenClaims{Sub: "org_acme", Plan: "team", Exp: 1893456000, MaxMembers: &m, Turn: true, Caps: []string{"remove_member"}}); got != frozenHrt1Team {
		t.Fatalf("hrt1 bytes changed:\n got %s\nwant %s", got, frozenHrt1Team)
	}
	if got := issueToken(sk, TokenClaims{Sub: "github:1", Caps: []string{}, Workspaces: []string{"wsA"}}); got != frozenHrt1Scope {
		t.Fatalf("hrt1 bytes changed:\n got %s\nwant %s", got, frozenHrt1Scope)
	}
	for _, v := range []string{frozenHrt1Team, frozenHrt1Scope} {
		if _, ok := VerifyToken(v, sk.Public().(ed25519.PublicKey)); !ok {
			t.Fatal("frozen vector must verify")
		}
	}
}

// The langstroth-auth claims serialize after the existing ones, in a fixed order.
func TestLigusAuthClaimsJSONOrder(t *testing.T) {
	got := string(mustJSON(TokenClaims{Sub: "home:u1", Exp: 5, Caps: []string{}, Workspaces: []string{"w"}, Tid: "home", Uid: "ab", Did: "d1"}))
	want := `{"sub":"home:u1","plan":"","exp":5,"max_members":null,"retention_days":null,"turn":false,"caps":[],"workspaces":["w"],"tid":"home","uid":"ab","did":"d1"}`
	if got != want {
		t.Fatalf("claims JSON:\n got %s\nwant %s", got, want)
	}
}

func TestTenantConfinementOffByDefault(t *testing.T) {
	sk := testKey(t)
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(sk))
	p := entitlementFromEnv()
	if p.tenants != nil {
		t.Fatal("tenant confinement must be off unless LANGSTROTH_RELAY_TENANTS is set")
	}
	if _, ok := p.Allow(issueToken(sk, TokenClaims{Sub: "x", Tid: "other"}), 0); !ok {
		t.Fatal("off: any tid admitted")
	}
	if _, ok := p.Allow(issueToken(sk, TokenClaims{Sub: "x"}), 0); !ok {
		t.Fatal("off: no tid admitted")
	}
}

func TestTenantConfinement(t *testing.T) {
	sk := testKey(t)
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(sk))
	t.Setenv("LANGSTROTH_RELAY_TENANTS", "acme, home")
	t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", "strict")
	if err := entitlementConfigError(); err != nil {
		t.Fatal(err)
	}
	p := entitlementFromEnv()
	cases := []struct {
		tid  string
		want bool
	}{{"acme", true}, {"home", true}, {"evil", false}, {"", false}, {"acme,home", false}}
	for _, c := range cases {
		if _, ok := p.Allow(issueToken(sk, TokenClaims{Sub: "x", Tid: c.tid}), 0); ok != c.want {
			t.Errorf("tid %q: admitted=%v want %v", c.tid, ok, c.want)
		}
	}
	// End to end: a token from another tenant gets 401 on a workspace route.
	srv := New(Options{Store: newMemoryStore(), Entitlement: p})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsA/envelopes", issueToken(sk, TokenClaims{Sub: "evil:u", Tid: "evil"}), nil); code != http.StatusUnauthorized {
		t.Errorf("foreign tenant: want 401, got %d", code)
	}
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsA/envelopes", issueToken(sk, TokenClaims{Sub: "acme:u", Tid: "acme", Workspaces: []string{"wsA"}}), nil); code != http.StatusOK {
		t.Errorf("own tenant: want 200, got %d", code)
	}
}

func TestTenantConfigErrors(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_TENANTS", "acme")
	if entitlementConfigError() == nil {
		t.Fatal("LANGSTROTH_RELAY_TENANTS without a pubkey must refuse to start")
	}
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(testKey(t)))
	t.Setenv("LANGSTROTH_RELAY_TENANTS", " , ")
	if entitlementConfigError() == nil {
		t.Fatal("an empty tenant list must refuse to start")
	}
}

func TestPubkeyNextAcceptedDuringRotation(t *testing.T) {
	cur := testKey(t)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 11
	}
	next := ed25519.NewKeyFromSeed(seed)
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(cur))
	p := entitlementFromEnv()
	if _, ok := p.Allow(issueToken(next, TokenClaims{Sub: "x"}), 0); ok {
		t.Fatal("next key must not verify until configured")
	}
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT", pubHex(next))
	if err := entitlementConfigError(); err != nil {
		t.Fatal(err)
	}
	p = entitlementFromEnv()
	for _, k := range []ed25519.PrivateKey{cur, next} {
		if _, ok := p.Allow(issueToken(k, TokenClaims{Sub: "x"}), 0); !ok {
			t.Fatal("both keys verify during rotation")
		}
	}
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY_NEXT", "garbage")
	if entitlementConfigError() == nil {
		t.Fatal("bad next key must refuse to start")
	}
	if entitlementFromEnv().kind != entDeny {
		t.Fatal("bad next key fails closed")
	}
}

func pubHex(sk ed25519.PrivateKey) string {
	const hexd = "0123456789abcdef"
	pub := sk.Public().(ed25519.PublicKey)
	out := make([]byte, 0, 64)
	for _, b := range pub {
		out = append(out, hexd[b>>4], hexd[b&15])
	}
	return string(out)
}
