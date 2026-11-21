package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestTunnelOnlyRoutes(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })
	h := restrictRoutes(inner, env(map[string]string{"LANGSTROTH_RELAY_ROUTES": "tunnel"}))
	for path, want := range map[string]int{
		"/v1/tunnel/connect": 299, "/v1/tunnel/info": 299, "/v1/health": 299, "/metrics": 299,
		"/v1/pair": 404, "/v1/pair/ABCD": 404, "/v1/contacts/x": 404, "/v1/workspaces/w/envelopes": 404, "/": 404, "/v1/tunnelx": 404,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}
	all := restrictRoutes(inner, env(nil))
	rec := httptest.NewRecorder()
	all.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/pair", nil))
	if rec.Code != 299 {
		t.Fatal("default must serve every route")
	}
}

func TestRoutesAndAPNsConfig(t *testing.T) {
	if routesConfigError(env(map[string]string{"LANGSTROTH_RELAY_ROUTES": "tunnel"})) == nil {
		t.Error("tunnel-only routes with the tunnel off must be refused")
	}
	if routesConfigError(env(map[string]string{"LANGSTROTH_RELAY_ROUTES": "tunnel", "LANGSTROTH_RELAY_TUNNEL": "open"})) != nil {
		t.Error("tunnel-only with the tunnel on is fine")
	}
	if routesConfigError(env(map[string]string{"LANGSTROTH_RELAY_ROUTES": "bogus"})) == nil {
		t.Error("unknown routes value must be refused")
	}
	if apnsWithoutTunnelError(env(map[string]string{"LANGSTROTH_RELAY_APNS_KEY": "-----BEGIN"})) == nil {
		t.Error("an inline APNs key on a tunnel-off (sync) process must be refused")
	}
	if apnsWithoutTunnelError(env(map[string]string{"LANGSTROTH_RELAY_APNS_KEY": "k", "LANGSTROTH_RELAY_TUNNEL": "allowlist"})) != nil {
		t.Error("APNs on the tunnel pod is fine")
	}
	if apnsWithoutTunnelError(env(nil)) != nil {
		t.Error("no APNs, no error")
	}
}
