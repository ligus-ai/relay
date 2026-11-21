package relay

import "net/http"

// The GitHub social routes (directory, account, friends; keyed by
// github:<id>) need the relay to see the caller's GitHub token. Ligus 2.0
// doesn't use them: discovery is links, QR codes, co-members and contacts
// (/v1/contacts/). Since v0.3 they are registered only when
// LANGSTROTH_RELAY_GITHUB_ROUTES=on (the spec's name
// LANGSTROTH_RELAY_GITHUB_SOCIAL=1 is accepted too) for older clients, and every
// response carries a deprecation notice. v0.4 removes the handlers, their
// tables and the GitHub verifier.

// githubRoutesDeprecatedAt is 2026-11-14T00:00:00Z, the v0.3 deprecation date
// (RFC 9745 Deprecation header: "@" + unix seconds).
const githubRoutesDeprecatedAt = "@1794614400"

const githubRoutesDeprecationLink = `<https://github.com/langstroth-ai/langstroth-relay/blob/main/CHANGELOG.md>; rel="deprecation"`

func githubRoutesFromEnv() bool {
	return envBool("LANGSTROTH_RELAY_GITHUB_ROUTES") || envBool("LANGSTROTH_RELAY_GITHUB_SOCIAL")
}

// deprecated marks a response as coming from a deprecated route.
func deprecated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Deprecation", githubRoutesDeprecatedAt)
		hd.Set("Link", githubRoutesDeprecationLink)
		h(w, r)
	}
}

func (s *Server) registerGitHubRoutes(mux *http.ServeMux) {
	if !s.githubRoutes {
		return
	}
	for _, rt := range []struct {
		pattern string
		h       http.HandlerFunc
	}{
		{"POST /v1/directory/register", s.directoryRegister},
		{"GET /v1/directory/{handle}", s.directoryLookup},

		{"POST /v1/account/register", s.accountRegister},
		{"POST /v1/account/heartbeat", s.accountHeartbeat},
		{"GET /v1/account/inbox", s.accountInbox},
		{"GET /v1/account/devices", s.accountDevices},
		{"POST /v1/account/visibility", s.accountVisibility},
		{"POST /v1/account/invites", s.accountInviteCreate},

		{"GET /v1/friends", s.friendsList},
		{"GET /v1/friends/presence", s.friendsPresence},
		{"GET /v1/friends/{account}/devices", s.friendDevicesList},
		{"DELETE /v1/friends/{account}", s.friendRemove},
		{"POST /v1/friends/requests", s.friendRequestCreate},
		{"GET /v1/friends/requests", s.friendRequestsList},
		{"POST /v1/friends/requests/{id}/accept", s.friendRequestAccept},
		{"POST /v1/friends/requests/{id}/reject", s.friendRequestReject},
	} {
		mux.HandleFunc(rt.pattern, deprecated(rt.h))
	}
}
