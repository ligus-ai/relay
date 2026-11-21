package langstrothauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/langstroth-ai/langstroth-relay/internal/relay"
)

func httptestServer(t *testing.T, h http.Handler) string {
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts.URL
}

func httptestAdmin(t *testing.T, h *harness) string { return httptestServer(t, h.srv.AdminHandler()) }

func adminDo(t *testing.T, base, method, path string, v any) int {
	return adminDoTok(t, base, "admin-token-for-tests-0123456789abcdef", method, path, v)
}

func adminDoTok(t *testing.T, base, tok, method, path string, v any) int {
	t.Helper()
	var b []byte
	if v != nil {
		b, _ = json.Marshal(v)
	}
	req, _ := http.NewRequest(method, base+path, bytes.NewReader(b))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func scimHarness(t *testing.T) (*harness, *mockIdP) {
	clock := newClock()
	idp := newMockIdP(t, clock)
	h := newHarness(t, clock, tenantSpec{id: "corp", idp: idp, workspaces: []string{"w1", "w2"},
		grants: map[string][]string{"eng": {"w1"}, "ops": {"w2"}}, provisioning: "scim", scimToken: testSCIMToken})
	return h, idp
}

func TestScimDeactivateRevokesRefresh(t *testing.T) {
	h, _ := scimHarness(t)
	uid := h.scimUser("corp", "alice@example.com")
	h.scimGroup("corp", "eng", uid)
	d := newDevice("d1")
	tr := h.loginTokens("corp", d)
	if tr.status != 200 {
		t.Fatalf("login: %s", fmtStatus(tr))
	}
	// Entra-style PATCH with a string boolean.
	code, _ := h.scim("corp", testSCIMToken, "PATCH", "/Users/"+uid, map[string]any{
		"schemas": []string{scimPatchSchema}, "Operations": []map[string]any{{"op": "Replace", "path": "active", "value": "False"}}})
	if code != http.StatusOK {
		t.Fatalf("deactivate: %d", code)
	}
	if r := h.refresh("corp", tr.Refresh, tr.Nonce, d); r.Error != "invalid_grant" {
		t.Fatalf("refresh after deactivation must fail at once: %s", fmtStatus(r))
	}
	if got := loginOutcome(t, h, "corp"); got != "access_denied" {
		t.Fatalf("sign-in after deactivation: %q", got)
	}
	// The access token already issued lapses within the access TTL.
	c, _ := relay.VerifyToken(tr.Access, pub(h))
	if !c.IsExpired(h.clock.Now().Add(h.cfg.AccessTTL.D()).Unix()) {
		t.Fatal("access token must lapse within access_ttl")
	}
	if !strings.Contains(h.audit.String(), "scim_user_deactivated") {
		t.Fatal("deactivation must be audited")
	}
}

func TestScimDeleteRevokesRefresh(t *testing.T) {
	h, _ := scimHarness(t)
	uid := h.scimUser("corp", "alice@example.com")
	h.scimGroup("corp", "eng", uid)
	d := newDevice("d1")
	tr := h.loginTokens("corp", d)
	if code, _ := h.scim("corp", testSCIMToken, "DELETE", "/Users/"+uid, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if r := h.refresh("corp", tr.Refresh, tr.Nonce, d); r.Error != "invalid_grant" {
		t.Fatalf("refresh after delete: %s", fmtStatus(r))
	}
}

func TestScimGroupsDriveWorkspaces(t *testing.T) {
	h, _ := scimHarness(t)
	uid := h.scimUser("corp", "alice@example.com")
	gEng := h.scimGroup("corp", "eng", uid)
	d := newDevice("d1")
	tr := h.loginTokens("corp", d)
	c, _ := relay.VerifyToken(tr.Access, pub(h))
	if strings.Join(c.Workspaces, ",") != "w1" {
		t.Fatalf("eng: %v", c.Workspaces)
	}
	// Add to ops: next refresh carries both.
	gOps := h.scimGroup("corp", "ops")
	code, _ := h.scim("corp", testSCIMToken, "PATCH", "/Groups/"+gOps, map[string]any{"schemas": []string{scimPatchSchema},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]string{{"value": uid}}}}})
	if code != http.StatusNoContent {
		t.Fatalf("add member: %d", code)
	}
	tr = h.refresh("corp", tr.Refresh, tr.Nonce, d)
	c, _ = relay.VerifyToken(tr.Access, pub(h))
	if strings.Join(c.Workspaces, ",") != "w1,w2" {
		t.Fatalf("eng+ops: %v", c.Workspaces)
	}
	// Remove from both: refresh is refused (no claim-less token).
	for _, g := range []string{gEng, gOps} {
		code, _ := h.scim("corp", testSCIMToken, "PATCH", "/Groups/"+g, map[string]any{"schemas": []string{scimPatchSchema},
			"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + uid + `"]`}}})
		if code != http.StatusNoContent {
			t.Fatalf("remove member: %d", code)
		}
	}
	if r := h.refresh("corp", tr.Refresh, tr.Nonce, d); r.Error != "access_denied" {
		t.Fatalf("no groups left: %s", fmtStatus(r))
	}
}

func TestScimAuthAndCrossTenant(t *testing.T) {
	h, _, _ := twoTenants(t)
	ua := h.scimUser("acme", "alice@acme.example")
	// No token, wrong token, the other tenant's token.
	for _, tok := range []string{"", "nope", scimTokenB} {
		if code, _ := h.scim("acme", tok, "GET", "/Users", nil); code != http.StatusUnauthorized {
			t.Fatalf("token %q: want 401, got %d", tok, code)
		}
	}
	// globex's SCIM client cannot see or touch acme's user, even by id.
	if code, _ := h.scim("globex", scimTokenB, "GET", "/Users/"+ua, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant read: %d", code)
	}
	if code, _ := h.scim("globex", scimTokenB, "PATCH", "/Users/"+ua, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}); code != http.StatusNotFound {
		t.Fatalf("cross-tenant patch: %d", code)
	}
	if code, _ := h.scim("globex", scimTokenB, "DELETE", "/Users/"+ua, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete: %d", code)
	}
	// ...nor pull it into a globex group.
	code, _ := h.scim("globex", scimTokenB, "POST", "/Groups", map[string]any{"displayName": "eng", "members": []map[string]string{{"value": ua}}})
	if code != http.StatusBadRequest {
		t.Fatalf("cross-tenant member: want 400, got %d", code)
	}
	code, list := h.scim("globex", scimTokenB, "GET", "/Users", nil)
	if code != 200 || list["totalResults"].(float64) != 0 {
		t.Fatalf("globex sees acme users: %v", list)
	}
	u, _ := h.store.GetUser(t.Context(), "acme", ua)
	if !u.Active {
		t.Fatal("acme user changed by globex")
	}
}

func TestScimFailedAuthIsRateLimited(t *testing.T) {
	h, _ := scimHarness(t)
	limited := false
	for i := 0; i < 20; i++ {
		if code, _ := h.scim("corp", "wrong", "GET", "/Users", nil); code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("failed SCIM auth must be rate limited")
	}
}

func TestScimCRUD(t *testing.T) {
	h, _ := scimHarness(t)
	uid := h.scimUser("corp", "Alice@Example.com")
	if code, _ := h.scim("corp", testSCIMToken, "POST", "/Users", map[string]any{"userName": "alice@example.com"}); code != http.StatusConflict {
		t.Fatalf("duplicate userName (case-insensitive): %d", code)
	}
	code, list := h.scim("corp", testSCIMToken, "GET", `/Users?filter=userName%20eq%20%22alice@example.com%22`, nil)
	if code != 200 || list["totalResults"].(float64) != 1 {
		t.Fatalf("filter: %d %v", code, list)
	}
	if code, _ := h.scim("corp", testSCIMToken, "GET", `/Users?filter=emails%20co%20%22x%22`, nil); code != http.StatusBadRequest {
		t.Fatalf("unsupported filter: %d", code)
	}
	code, u := h.scim("corp", testSCIMToken, "PUT", "/Users/"+uid, map[string]any{"userName": "alice@example.com", "displayName": "Alice", "active": true, "emails": []any{map[string]any{"value": "a@x"}}})
	if code != 200 || u["displayName"] != "Alice" {
		t.Fatalf("put: %d %v", code, u)
	}
	if _, has := u["emails"]; has {
		t.Fatal("langstroth-auth must not store or echo emails")
	}
	gid := h.scimGroup("corp", "eng", uid)
	code, g := h.scim("corp", testSCIMToken, "GET", "/Groups/"+gid, nil)
	if code != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("group: %d %v", code, g)
	}
	code, _ = h.scim("corp", testSCIMToken, "PATCH", "/Groups/"+gid, map[string]any{"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"displayName": "engineering"}}}})
	if code != http.StatusNoContent {
		t.Fatalf("rename: %d", code)
	}
	if code, _ := h.scim("corp", testSCIMToken, "DELETE", "/Groups/"+gid, nil); code != http.StatusNoContent {
		t.Fatalf("delete group: %d", code)
	}
	if code, _ := h.scim("corp", testSCIMToken, "GET", "/ServiceProviderConfig", nil); code != 200 {
		t.Fatal("ServiceProviderConfig")
	}
	if code, _ := h.scim("corp", testSCIMToken, "POST", "/Users", map[string]any{"userName": "bad\nname"}); code != http.StatusBadRequest {
		t.Fatal("control characters must be refused")
	}
}

// The audit log records events by opaque or hashed ids only.
func TestAuditLogHasNoPII(t *testing.T) {
	h, idp := scimHarness(t)
	idp.set(func(m *mockIdP) { m.user.sub = "subject-value-xyz" })
	uid := h.scimUser("corp", "alice@example.com")
	h.scimGroup("corp", "eng", uid)
	d := newDevice("device-id-123")
	tr := h.loginTokens("corp", d)
	h.refresh("corp", tr.Refresh, tr.Nonce, d)
	h.scim("corp", testSCIMToken, "PATCH", "/Users/"+uid, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}})
	log := h.audit.String()
	for _, pii := range []string{"alice@example.com", "subject-value-xyz", "127.0.0.1", "device-id-123", tr.Refresh, tr.Access, testSCIMToken} {
		if strings.Contains(log, pii) {
			t.Fatalf("audit log contains %q", pii)
		}
	}
	for _, ev := range []string{"login_ok", "token_minted", "token_refreshed", "scim_user_deactivated", "user_linked"} {
		if !strings.Contains(log, ev) {
			t.Fatalf("audit log lacks %s", ev)
		}
	}
}

func TestSigningKeyHandling(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	pubHex, err := WriteNewSigningKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteNewSigningKey(p); err == nil {
		t.Fatal("keygen must never overwrite a key")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %#o", st.Mode().Perm())
	}
	k, src, err := LoadSigningKey(p)
	if err != nil || src != "file" {
		t.Fatal(err)
	}
	if relay.IssueToken(k, relay.TokenClaims{Sub: "x"}) == "" || pubHex == "" {
		t.Fatal("key unusable")
	}
	seed, _ := os.ReadFile(p)
	os.Chmod(p, 0o644)
	_, _, err = LoadSigningKey(p)
	if err == nil {
		t.Fatal("a world-readable key file must be refused")
	}
	if strings.Contains(err.Error(), strings.TrimSpace(string(seed))) {
		t.Fatal("errors must not contain the key")
	}
	os.WriteFile(p, []byte("not-a-key"), 0o600)
	os.Chmod(p, 0o600)
	if _, _, err := LoadSigningKey(p); err == nil || strings.Contains(err.Error(), "not-a-key") {
		t.Fatalf("bad key: %v", err)
	}
	// systemd credential.
	cred := t.TempDir()
	os.WriteFile(filepath.Join(cred, credentialName), seed, 0o600)
	t.Setenv("CREDENTIALS_DIRECTORY", cred)
	t.Setenv("LANGSTROTH_AUTH_SIGNING_KEY_FILE", "")
	if _, src, err := LoadSigningKey(""); err != nil || src != "file" {
		t.Fatalf("systemd credential: %v %s", err, src)
	}
}

func TestFileStorePersistsAndIsPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s, err := NewFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	now := time.Now().Unix()
	if err := s.CreateUser(ctx, User{Tenant: "a", ID: "u1", UserName: "x", Active: true, Created: now}); err != nil {
		t.Fatal(err)
	}
	s.PutRefresh(ctx, RefreshToken{Hash: "hx", Tenant: "a", FamilyID: "f", UserID: "u1", ExpiresAt: now + 100})
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %#o", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "refresh-raw") {
		t.Fatal("raw refresh tokens must never be stored")
	}
	s2, err := NewFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.GetUser(ctx, "a", "u1"); err != nil {
		t.Fatal("state must survive reopen")
	}
	storeSuite(t, s2)
}
