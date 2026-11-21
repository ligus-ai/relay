package relay

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Per-workspace token scope (opt-in).
//
// The access gate is coarse: any admitted token reads and writes every
// workspace. LANGSTROTH_RELAY_WORKSPACE_SCOPE narrows that with an optional
// "workspaces" claim in signed hrt1 tokens:
//
//	off (default)  the claim is ignored; behavior is unchanged.
//	claims         a token that carries "workspaces" may only use those ids;
//	               a token without the claim keeps coarse access.
//	strict         every workspace route requires a token whose "workspaces"
//	               claim lists the id (or "*"). Callers without signed claims
//	               (open policy, static allowlist) get 403 on workspace routes.
//
// It applies to every /v1/workspaces/{id}/... route (envelopes, events,
// keyring, presence, candidates and, in membership mode, members, invites and
// join), before the handler runs. The claim travels inside the signed claims
// JSON, so the hrt1 format is unchanged; a relay without this setting (or an
// older relay) ignores the claim, so a scoped token is only confined where the
// operator turns this on.
const (
	scopeOff    = "off"
	scopeClaims = "claims"
	scopeStrict = "strict"
)

func workspaceScopeFromEnv() string {
	switch v := strings.ToLower(strings.TrimSpace(getenv("LANGSTROTH_RELAY_WORKSPACE_SCOPE"))); v {
	case "", scopeOff:
		return scopeOff
	case scopeClaims, scopeStrict:
		return v
	default:
		// Fail closed on a typo: the operator asked for some scoping.
		fmt.Fprintf(os.Stderr, "langstroth-relay: LANGSTROTH_RELAY_WORKSPACE_SCOPE=%q is not off|claims|strict; using strict\n", v)
		return scopeStrict
	}
}

// scopeAllows reports whether claims may use workspace under mode.
func scopeAllows(mode string, claims *TokenClaims, workspace string) bool {
	switch mode {
	case scopeClaims, scopeStrict:
	default:
		return true
	}
	if claims == nil || claims.Workspaces == nil {
		return mode == scopeClaims
	}
	for _, w := range claims.Workspaces {
		if w == "*" || w == workspace {
			return true
		}
	}
	return false
}

// Identifier bounds. Workspace and device ids are map and table keys that the
// store byte budget doesn't count; real ones are short (UUIDs, hashes, room
// names).
const (
	maxWorkspaceIDLen = 512
	maxDeviceIDLen    = 256
)

// scoped wraps every /v1/workspaces/{id}/... handler: it bounds the id length
// and applies the workspace scope check. It runs after the access gate,
// which put the verified claims in the context.
func (s *Server) scoped(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(r.PathValue("id")) > maxWorkspaceIDLen {
			http.Error(w, "workspace id too long", http.StatusBadRequest)
			return
		}
		if s.wsScope != scopeOff && !scopeAllows(s.wsScope, claimsFrom(r.Context()), r.PathValue("id")) {
			http.Error(w, "this access token is not scoped to this workspace", http.StatusForbidden)
			return
		}
		// From here on the id is the storage key: "<tenant>/<id>" in tenancy
		// mode (the scope check above used the id the client sent).
		room := tenantKey(r.Context(), r.PathValue("id"))
		r.SetPathValue("id", room)
		if s.lim.room != nil {
			if ok, wait := s.lim.room.allowWait(room); !ok {
				tooMany(w, limRoomRate, tenantID(r.Context()), wait, "room rate limit exceeded")
				return
			}
		}
		h(w, r.WithContext(withQuota(r.Context(), s.quotaFor(r))))
	}
}
