package relay

import (
	"fmt"
	"net/http"
	"strings"
)

// Pod roles for the split Kubernetes topology (deploy/helm/langstroth-relay):
//
//   - LANGSTROTH_RELAY_ROUTES=tunnel makes a process serve only the tunnel
//     (/v1/tunnel/*) plus /v1/health and /metrics. The tunnel pod would
//     otherwise also answer pairing, contacts and workspace routes, a third
//     in-process pairing store beside relay-sync's for anything that reaches
//     its Service directly.
//   - APNs settings on a process with the tunnel off are refused: push only
//     ever goes out through the tunnel, so an APNs key there (for example an
//     inline LANGSTROTH_RELAY_APNS_KEY in a Secret shared with relay-sync) is a key
//     where it can only leak.

const routesTunnel = "tunnel"

// routesConfigError validates LANGSTROTH_RELAY_ROUTES against the tunnel mode.
func routesConfigError(get func(string) string) error {
	switch r := strings.ToLower(strings.TrimSpace(get("LANGSTROTH_RELAY_ROUTES"))); r {
	case "", "all":
		return nil
	case routesTunnel:
		if tunnelOff(get) {
			return fmt.Errorf("LANGSTROTH_RELAY_ROUTES=tunnel with LANGSTROTH_RELAY_TUNNEL off would serve nothing")
		}
		return nil
	default:
		return fmt.Errorf("LANGSTROTH_RELAY_ROUTES=%q: use all or tunnel", r)
	}
}

func tunnelOff(get func(string) string) bool {
	m := strings.ToLower(strings.TrimSpace(get("LANGSTROTH_RELAY_TUNNEL")))
	return m == "" || m == TunnelOff
}

// apnsWithoutTunnelError refuses APNs settings on a process whose tunnel is off.
func apnsWithoutTunnelError(get func(string) string) error {
	if !tunnelOff(get) {
		return nil
	}
	for _, k := range []string{"LANGSTROTH_RELAY_APNS_KEY", "LANGSTROTH_RELAY_APNS_KEY_FILE", "LANGSTROTH_RELAY_APNS_KEY_ID", "LANGSTROTH_RELAY_APNS_TEAM_ID"} {
		if strings.TrimSpace(get(k)) != "" {
			return fmt.Errorf("%s is set but the tunnel is off on this process: APNs keys belong only on the tunnel pod (push goes out through the tunnel); remove it here", k)
		}
	}
	return nil
}

// restrictRoutes wraps h per LANGSTROTH_RELAY_ROUTES.
func restrictRoutes(h http.Handler, get func(string) string) http.Handler {
	if strings.ToLower(strings.TrimSpace(get("LANGSTROTH_RELAY_ROUTES"))) != routesTunnel {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/v1/tunnel/") || p == "/v1/health" || p == "/metrics" {
			h.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}
