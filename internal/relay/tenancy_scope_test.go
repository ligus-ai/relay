package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// E-2: tenant confinement must also confine workspaces. With
// LANGSTROTH_RELAY_TENANTS listing two tenants and the workspace scope left at
// its default (off) or at "claims", a valid token from tenant acme reached
// tenant home's workspace. Setting tenants makes the relay refuse to start
// unless the scope is strict, and a tenant-confined gate is always strict.
func TestTenantConfinementForcesStrictWorkspaceScope(t *testing.T) {
	sk := testKey(t)
	t.Setenv("LANGSTROTH_RELAY_TOKEN_PUBKEY", pubHex(sk))
	t.Setenv("LANGSTROTH_RELAY_TENANTS", "acme,home")
	for _, scope := range []string{"", "off", "claims"} {
		t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", scope)
		if entitlementConfigError() == nil {
			t.Errorf("scope %q: LANGSTROTH_RELAY_TENANTS without strict workspace scope must refuse to start", scope)
		}
		srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementFromEnv()})
		ts := httptest.NewServer(srv.Handler())
		acmeOwn := issueToken(sk, TokenClaims{Sub: "acme:u", Tid: "acme", Workspaces: []string{"ws-acme"}})
		if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/ws-home/envelopes", acmeOwn, nil); code != http.StatusForbidden {
			t.Errorf("scope %q: acme token read home's workspace: %d", scope, code)
		}
		noClaim := issueToken(sk, TokenClaims{Sub: "acme:u", Tid: "acme"})
		if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/ws-home/envelopes", noClaim, nil); code != http.StatusForbidden {
			t.Errorf("scope %q: a tenant token without a workspaces claim got coarse access: %d", scope, code)
		}
		if code, _ := req(t, "GET", ts.URL+"/v1/workspaces/ws-acme/envelopes", acmeOwn, nil); code != http.StatusOK {
			t.Errorf("scope %q: own workspace: %d", scope, code)
		}
		ts.Close()
	}
	t.Setenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE", "strict")
	if err := entitlementConfigError(); err != nil {
		t.Fatal(err)
	}
}
