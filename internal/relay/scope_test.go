package relay

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
)

func scopeServer(t *testing.T, mode string) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", mode)
	sk := testKey(t)
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entSigned, pubkey: sk.Public().(ed25519.PublicKey)}})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sk
}

// F-05 (deferred item: per-workspace read authorization). The token gate is
// coarse: a token minted for one workspace reads and writes every other
// workspace, including its keyring, presence and SSE stream. With
// LANGSTROTH_RELAY_WORKSPACE_SCOPE=claims a token carrying a "workspaces" claim is
// confined to those ids.
func TestWorkspaceScopeClaims(t *testing.T) {
	ts, sk := scopeServer(t, "claims")
	scoped := issueToken(sk, TokenClaims{Sub: "github:1", Workspaces: []string{"wsA"}})
	coarse := issueToken(sk, TokenClaims{Sub: "github:2"})

	for _, p := range []string{"envelopes", "keyring", "presence", "candidates"} {
		if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsA/"+p, scoped, nil); code != http.StatusOK {
			t.Errorf("scoped token reading its own workspace %s: want 200, got %d", p, code)
		}
		if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsB/"+p, scoped, nil); code != http.StatusForbidden {
			t.Errorf("scoped token reading another workspace %s: want 403, got %d", p, code)
		}
	}
	if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/wsB/envelopes", scoped, map[string]string{"x": "y"}); code != http.StatusForbidden {
		t.Errorf("scoped token writing another workspace: want 403, got %d", code)
	}
	if code, _ := req(t, "POST", ts.URL+"/v1/workspaces/wsA/envelopes", scoped, map[string]string{"x": "y"}); code != http.StatusOK {
		t.Errorf("scoped token writing its workspace: want 200, got %d", code)
	}
	r, _ := http.NewRequest("GET", ts.URL+"/v1/workspaces/wsB/events", nil)
	r.Header.Set("Authorization", "Bearer "+scoped)
	if resp, err := http.DefaultClient.Do(r); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("scoped token streaming another workspace: want 403, got %v %v", resp.StatusCode, err)
	} else {
		resp.Body.Close()
	}
	// A token without the claim keeps the coarse behavior in "claims" mode.
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsB/envelopes", coarse, nil); code != http.StatusOK {
		t.Errorf("unscoped token in claims mode: want 200, got %d", code)
	}
}

func TestWorkspaceScopeStrict(t *testing.T) {
	ts, sk := scopeServer(t, "strict")
	coarse := issueToken(sk, TokenClaims{Sub: "github:2"})
	any := issueToken(sk, TokenClaims{Sub: "ops", Workspaces: []string{"*"}})
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsB/envelopes", coarse, nil); code != http.StatusForbidden {
		t.Errorf("strict mode, token without workspaces: want 403, got %d", code)
	}
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsB/envelopes", any, nil); code != http.StatusOK {
		t.Errorf("strict mode, wildcard token: want 200, got %d", code)
	}
}

// Off (the default) leaves the coarse gate unchanged, and a token's
// workspaces claim is ignored.
func TestWorkspaceScopeOffByDefault(t *testing.T) {
	ts, sk := scopeServer(t, "")
	scoped := issueToken(sk, TokenClaims{Sub: "github:1", Workspaces: []string{"wsA"}})
	if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/wsB/envelopes", scoped, nil); code != http.StatusOK {
		t.Errorf("scope off: want 200, got %d", code)
	}
}

// Adding the optional claim must not change tokens minted without it (hrt1
// bytes stay identical to the Rust issuer's output).
func TestTokenClaimsWithoutWorkspacesUnchanged(t *testing.T) {
	got := string(mustJSON(TokenClaims{Sub: "s", Plan: "team", Caps: []string{}}))
	want := `{"sub":"s","plan":"team","exp":0,"max_members":null,"retention_days":null,"turn":false,"caps":[]}`
	if got != want {
		t.Fatalf("claims JSON changed:\n got %s\nwant %s", got, want)
	}
}

func TestWorkspaceScopeTypoFailsClosed(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", "claim")
	if got := workspaceScopeFromEnv(); got != scopeStrict {
		t.Fatalf("an unrecognized scope must fail closed to strict, got %q", got)
	}
}
