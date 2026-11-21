package langstrothauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Operator API, served only on the admin listener and only when an admin
// token is configured:
//
//	GET    /admin/v1/tenants
//	GET    /admin/v1/tenants/{t}/grants
//	PUT    /admin/v1/tenants/{t}/grants/{group}     {"workspaces":[...]}
//	DELETE /admin/v1/tenants/{t}/grants/{group}
//	GET    /admin/v1/tenants/{t}/users
//	POST   /admin/v1/tenants/{t}/users/{id}/active  {"active":false}
//	POST   /admin/v1/tenants/{t}/users/{id}/revoke
//	POST   /admin/v1/tenants/{t}/devices/{device}/revoke
//
// The device route also accepts the tenant's own device-revocation token
// (config "device_revoke_token_file" / "device_revoke_token_sha256"), and
// only for that tenant: a serve box ending a revoked phone's session holds
// that token, never the operator token.
//
// A grant can name only workspaces the tenant owns (config "workspaces").
// Nothing here touches workspace membership: that is the signed roster's job.

func (s *Server) registerAdmin(mux *http.ServeMux) {
	a := func(h func(http.ResponseWriter, *http.Request, *TenantConfig)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !s.adminAuthorized(w, r) {
				return
			}
			var t *TenantConfig
			if id := r.PathValue("tenant"); id != "" {
				if t = s.cfg.tenant(id); t == nil {
					http.Error(w, "unknown tenant", http.StatusNotFound)
					return
				}
			}
			h(w, r, t)
		}
	}
	mux.HandleFunc("GET /admin/v1/tenants", a(s.adminTenants))
	mux.HandleFunc("GET /admin/v1/tenants/{tenant}/grants", a(s.adminListGrants))
	mux.HandleFunc("PUT /admin/v1/tenants/{tenant}/grants/{group}", a(s.adminSetGrant))
	mux.HandleFunc("DELETE /admin/v1/tenants/{tenant}/grants/{group}", a(s.adminDeleteGrant))
	mux.HandleFunc("GET /admin/v1/tenants/{tenant}/users", a(s.adminUsers))
	mux.HandleFunc("POST /admin/v1/tenants/{tenant}/users/{id}/active", a(s.adminSetActive))
	mux.HandleFunc("POST /admin/v1/tenants/{tenant}/users/{id}/revoke", a(s.adminRevoke))
	// The operator token, or that tenant's device-revocation token (a serve
	// box's; it opens this route of its own tenant only).
	mux.HandleFunc("POST /admin/v1/tenants/{tenant}/devices/{device}/revoke", func(w http.ResponseWriter, r *http.Request) {
		t := s.cfg.tenant(r.PathValue("tenant"))
		if !s.deviceRevokeAuthorized(w, r, t) {
			return
		}
		if t == nil {
			http.Error(w, "unknown tenant", http.StatusNotFound)
			return
		}
		s.adminRevokeDevice(w, r, t)
	})
}

// deviceRevokeAuthorized accepts the operator token, or t's own
// device-revocation token (never another tenant's).
func (s *Server) deviceRevokeAuthorized(w http.ResponseWriter, r *http.Request, t *TenantConfig) bool {
	if t != nil && t.deviceRevokeTokenHash != "" {
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && constEq(sha256Hex(strings.TrimSpace(tok)), t.deviceRevokeTokenHash) {
			return true
		}
	}
	return s.adminAuthorized(w, r)
}

func (s *Server) adminAuthorized(w http.ResponseWriter, r *http.Request) bool {
	if s.adminTokenHash == "" {
		http.NotFound(w, r)
		return false
	}
	ip := s.clientIP(r)
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !constEq(sha256Hex(strings.TrimSpace(tok)), s.adminTokenHash) {
		if !s.authFail.allow("admin|" + s.limitKey(r)) {
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return false
		}
		s.audit.event("admin_auth_failed", "", "ip", ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) adminTenants(w http.ResponseWriter, _ *http.Request, _ *TenantConfig) {
	out := []map[string]any{}
	for _, t := range s.cfg.Tenants {
		out = append(out, map[string]any{
			"id": t.ID, "display_name": t.DisplayName, "issuer": t.OIDC.Issuer, "provisioning": t.Provisioning,
			"workspaces": t.Workspaces, "scim": t.scimTokenHash != "", "idp_groups": t.IDPGroups,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminListGrants(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	g, err := s.store.ListGrants(r.Context(), t.ID)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) adminSetGrant(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	var body struct {
		Workspaces []string `json:"workspaces"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	group := r.PathValue("group")
	if group == "" || !validField(group) {
		http.Error(w, "invalid group", http.StatusBadRequest)
		return
	}
	for _, ws := range body.Workspaces {
		if !t.owns(ws) {
			s.audit.event("admin_grant_refused", t.ID, "group_hash", sha256Hex(group)[:16], "reason", "workspace_not_owned")
			http.Error(w, "workspace "+sanitize(ws)+" is not owned by this tenant", http.StatusForbidden)
			return
		}
	}
	if err := s.store.SetGrant(r.Context(), t.ID, group, body.Workspaces); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	s.audit.event("admin_grant_set", t.ID, "group_hash", sha256Hex(group)[:16], "workspaces", len(body.Workspaces))
	writeJSON(w, http.StatusOK, map[string]any{"group": group, "workspaces": sortedUnique(body.Workspaces)})
}

func (s *Server) adminDeleteGrant(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	if err := s.store.SetGrant(r.Context(), t.ID, r.PathValue("group"), nil); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	s.audit.event("admin_grant_deleted", t.ID, "group_hash", sha256Hex(r.PathValue("group"))[:16])
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	users, err := s.store.ListUsers(r.Context(), t.ID)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []User{}
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) adminSetActive(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	var body struct {
		Active *bool `json:"active"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Active == nil {
		http.Error(w, `body must be {"active": true|false}`, http.StatusBadRequest)
		return
	}
	u, err := s.store.GetUser(r.Context(), t.ID, r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	u.Active = *body.Active
	u.Modified = s.now().Unix()
	if err := s.store.UpdateUser(r.Context(), u); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	n := 0
	if !u.Active {
		n, _ = s.store.RevokeUser(r.Context(), t.ID, u.ID)
	}
	s.audit.event("admin_user_active", t.ID, "user", u.ID, "active", u.Active, "refresh_revoked", n)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	n, err := s.store.RevokeUser(r.Context(), t.ID, r.PathValue("id"))
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	s.audit.event("admin_sessions_revoked", t.ID, "user", r.PathValue("id"), "refresh_revoked", n)
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// adminRevokeDevice ends one device's sign-in session: every refresh token
// bound to that device id (a revoked phone or a lost laptop), leaving the
// person's other devices signed in. Idempotent ({"revoked": 0} the second
// time). Access tokens already minted for the device stay valid until they
// expire (at most an hour); the relay doesn't look them up.
func (s *Server) adminRevokeDevice(w http.ResponseWriter, r *http.Request, t *TenantConfig) {
	device := r.PathValue("device")
	if !deviceIDRe.MatchString(device) {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return
	}
	n, err := s.store.RevokeDevice(r.Context(), t.ID, device)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	s.audit.event("admin_device_revoked", t.ID, "did", device, "refresh_revoked", n)
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}
