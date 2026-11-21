package relay

import (
	"net/http"
	"strconv"
	"strings"
)

// Tenant admin scope (docs/tenancy.md): /v1/tenant routes, registered only
// in tenancy mode. A caller is admitted for exactly one tenant, by a token of
// that tenant carrying the tenant_admin cap, or by the tenant's static admin
// token (admin_token_sha256).

const maxTenantRoomPage = 1000

func (s *Server) registerTenantAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/tenant", s.tenantAdmin(s.tenantInfo))
	mux.HandleFunc("GET /v1/tenant/rooms", s.tenantAdmin(s.tenantRooms))
	mux.HandleFunc("DELETE /v1/tenant/rooms/{id}", s.tenantAdmin(s.tenantPurgeRoom))
}

// tenantAdminOf returns the tenant a bearer administers, or nil.
func (s *Server) tenantAdminOf(r *http.Request) *tenantConf {
	tok := bearerToken(r)
	if tok == "" {
		return nil
	}
	if c, t, ok := s.tenancy.verify(tok, nowUnix()); ok {
		if c.HasCap(tenantAdminCap) {
			return t
		}
		return nil
	}
	// Static admin tokens: compare against every tenant's hash, without an
	// early exit, so timing doesn't say which tenant (if any) matched.
	h := sha256hex(tok)
	var found *tenantConf
	for _, id := range s.tenancy.ids {
		t := s.tenancy.tenants[id]
		if t.adminHash != "" && constantTimeEq(h, t.adminHash) {
			found = t
		}
	}
	return found
}

func (s *Server) tenantAdmin(h func(http.ResponseWriter, *http.Request, *tenantConf)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t := s.tenantAdminOf(r)
		if t == nil {
			http.Error(w, "tenant admin credential required", http.StatusUnauthorized)
			return
		}
		if t.rate != nil {
			if ok, wait := t.rate.allowWait(t.id); !ok {
				tooMany(w, limTenantRate, t.id, wait, "tenant rate limit exceeded")
				return
			}
		}
		countTenantRequest(t.id)
		if _, ok := s.store.(roomStore); !ok {
			http.Error(w, "this store has no room accounting", http.StatusNotImplemented)
			return
		}
		h(w, r.WithContext(withTenant(r.Context(), t)), t)
	}
}

func (s *Server) tenantInfo(w http.ResponseWriter, r *http.Request, t *tenantConf) {
	bytes, rooms, err := s.store.(roomStore).TenantUsage(r.Context(), t.id)
	if storeErr(w, err) {
		return
	}
	var hosts int64
	if hc, ok := s.store.(tenantHostCounter); ok {
		if hosts, err = hc.TunnelHostsOfTenant(r.Context(), t.id); storeErr(w, err) {
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": t.id,
		"usage":  map[string]int64{"bytes": bytes, "rooms": rooms, "hosts": hosts},
		"limits": t.limits,
	})
}

type tenantRoomRow struct {
	ID        string `json:"id"`
	Bytes     int64  `json:"bytes"`
	Envelopes int64  `json:"envelopes"`
	LastWrite int64  `json:"lastWrite"`
}

func (s *Server) tenantRooms(w http.ResponseWriter, r *http.Request, t *tenantConf) {
	limit := maxTenantRoomPage
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v < limit {
		limit = v
	}
	prefix := tenantRoomPrefix(t.id)
	after := r.URL.Query().Get("after")
	if len(after) > maxWorkspaceIDLen {
		http.Error(w, "after too long", http.StatusBadRequest)
		return
	}
	// The store filters by tenant in its query; the prefix check below is a
	// second fence, never the only one.
	rows, err := s.store.(roomStore).ListRooms(r.Context(), t.id, prefix+after, limit)
	if storeErr(w, err) {
		return
	}
	out := make([]tenantRoomRow, 0, len(rows))
	for _, ru := range rows {
		if ru.Tenant != t.id || !strings.HasPrefix(ru.Room, prefix) {
			continue
		}
		out = append(out, tenantRoomRow{ID: strings.TrimPrefix(ru.Room, prefix), Bytes: ru.Bytes, Envelopes: ru.Envelopes, LastWrite: ru.LastWrite})
	}
	next := ""
	if len(rows) == limit && len(out) > 0 {
		next = out[len(out)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"rooms": out, "next": next})
}

func (s *Server) tenantPurgeRoom(w http.ResponseWriter, r *http.Request, t *tenantConf) {
	id := r.PathValue("id")
	if len(id) > maxWorkspaceIDLen {
		http.Error(w, "workspace id too long", http.StatusBadRequest)
		return
	}
	ok, err := s.store.(roomStore).PurgeRoom(r.Context(), tenantRoomPrefix(t.id)+id)
	if storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "existed": ok})
}
