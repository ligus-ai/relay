package langstrothauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func adminJSON(t *testing.T, base, tok, method, path string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, bytes.NewReader(nil))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// Revoking one device's sessions ends exactly that device's refresh tokens
// (its sign-in session), leaves the person's other devices signed in, is
// idempotent, and needs the admin token.
func TestAdminRevokeDeviceEndsOnlyThatDevicesSession(t *testing.T) {
	h, _ := homeHarness(t)
	phone, laptop := newDevice("4d1b6c1e-0000-4000-8000-000000000001"), newDevice("dev-mac-1")
	h.loginTokens("home", phone) // jit-create the user
	grantJIT(t, h, "home")
	pt := h.loginTokens("home", phone)
	lt := h.loginTokens("home", laptop)
	if pt.status != 200 || lt.status != 200 {
		t.Fatalf("logins: %s / %s", fmtStatus(pt), fmtStatus(lt))
	}
	admin := httptestAdmin(t, h)
	path := "/admin/v1/tenants/home/devices/" + phone.id + "/revoke"

	if code, _ := adminJSON(t, admin, "", "POST", path); code != http.StatusUnauthorized {
		t.Fatalf("no admin token: %d", code)
	}
	if code, _ := adminJSON(t, admin, "wrong-token-0123456789abcdef0123456789", "POST", path); code != http.StatusUnauthorized {
		t.Fatalf("wrong admin token: %d", code)
	}
	if code, _ := adminJSON(t, admin, "admin-token-for-tests-0123456789abcdef", "POST", "/admin/v1/tenants/nope/devices/"+phone.id+"/revoke"); code != http.StatusNotFound {
		t.Fatalf("unknown tenant: %d", code)
	}
	if code, _ := adminJSON(t, admin, "admin-token-for-tests-0123456789abcdef", "POST", "/admin/v1/tenants/home/devices/bad%20id/revoke"); code != http.StatusBadRequest {
		t.Fatalf("bad device id: %d", code)
	}
	code, m := adminJSON(t, admin, "admin-token-for-tests-0123456789abcdef", "POST", path)
	if code != http.StatusOK || m["revoked"] != float64(1) {
		t.Fatalf("revoke device: %d %v", code, m)
	}
	// The phone's refresh is refused; the laptop's still works.
	if tr := h.refresh("home", pt.Refresh, pt.Nonce, phone); tr.status == 200 {
		t.Fatalf("revoked device refreshed: %s", fmtStatus(tr))
	}
	if tr := h.refresh("home", lt.Refresh, lt.Nonce, laptop); tr.status != 200 {
		t.Fatalf("other device lost its session: %s", fmtStatus(tr))
	}
	// Idempotent.
	code, m = adminJSON(t, admin, "admin-token-for-tests-0123456789abcdef", "POST", path)
	if code != http.StatusOK || m["revoked"] != float64(0) {
		t.Fatalf("second revoke: %d %v", code, m)
	}
}

// A serve box needs only to end its own tenant's device sessions, so it is
// given that tenant's device-revocation token, never the operator token. The
// token works on that tenant's device route alone: not on another tenant's
// (tenant confusion) and not on any other admin route.
func TestDeviceRevokeTokenIsTenantAndRouteScoped(t *testing.T) {
	clock := newClock()
	homeIdP, workIdP := newMockIdP(t, clock), newMockIdP(t, clock)
	const homeTok = "home-device-revoke-token-0123456789abcdef"
	const workTok = "work-device-revoke-token-0123456789abcdef"
	h := newHarness(t, clock,
		tenantSpec{id: "home", idp: homeIdP, workspaces: []string{"ws-home"}, grants: map[string][]string{"family": {"ws-home"}}, scimToken: testSCIMToken, deviceRevokeToken: homeTok},
		tenantSpec{id: "work", idp: workIdP, workspaces: []string{"ws-work"}, grants: map[string][]string{"family": {"ws-work"}}, scimToken: testSCIMToken, deviceRevokeToken: workTok},
	)
	phone := newDevice("4d1b6c1e-0000-4000-8000-000000000002")
	h.loginTokens("home", phone)
	grantJIT(t, h, "home")
	pt := h.loginTokens("home", phone)
	if pt.status != 200 {
		t.Fatalf("login: %s", fmtStatus(pt))
	}
	admin := httptestAdmin(t, h)
	home := "/admin/v1/tenants/home/devices/" + phone.id + "/revoke"
	work := "/admin/v1/tenants/work/devices/" + phone.id + "/revoke"

	// Another tenant's token, and this tenant's token on another tenant.
	if code, _ := adminJSON(t, admin, workTok, "POST", home); code != http.StatusUnauthorized {
		t.Fatalf("work token on home: %d", code)
	}
	if code, _ := adminJSON(t, admin, homeTok, "POST", work); code != http.StatusUnauthorized {
		t.Fatalf("home token on work: %d", code)
	}
	// Any other admin route.
	for _, r := range [][2]string{{"GET", "/admin/v1/tenants"}, {"GET", "/admin/v1/tenants/home/users"}, {"GET", "/admin/v1/tenants/home/grants"}, {"POST", "/admin/v1/tenants/home/users/x/revoke"}} {
		if code, _ := adminJSON(t, admin, homeTok, r[0], r[1]); code != http.StatusUnauthorized {
			t.Fatalf("device token on %s %s: %d", r[0], r[1], code)
		}
	}
	// Its own route works.
	code, m := adminJSON(t, admin, homeTok, "POST", home)
	if code != http.StatusOK || m["revoked"] != float64(1) {
		t.Fatalf("own tenant: %d %v", code, m)
	}
	if tr := h.refresh("home", pt.Refresh, pt.Nonce, phone); tr.status == 200 {
		t.Fatalf("revoked device refreshed: %s", fmtStatus(tr))
	}
}
