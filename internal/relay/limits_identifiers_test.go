package relay

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// F-10: workspace ids (path) and device ids (body) had no length bound. They
// are map keys and table keys that the store byte budget doesn't count, so a
// client could attach up to the 1 MB header limit per workspace id, or up to
// the 4 MiB body cap per device id, across an unbounded number of workspaces.
func TestIdentifierLengthsBounded(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()
	longWS := strings.Repeat("w", maxWorkspaceIDLen+1)
	if code := postRaw(t, h, "/v1/workspaces/"+longWS+"/envelopes", `"x"`, "192.0.2.1:1"); code != http.StatusBadRequest {
		t.Errorf("over-long workspace id: want 400, got %d", code)
	}
	if code, _ := getBody(t, h, "/v1/workspaces/"+longWS+"/envelopes"); code != http.StatusBadRequest {
		t.Errorf("over-long workspace id read: want 400, got %d", code)
	}
	okWS := strings.Repeat("w", maxWorkspaceIDLen)
	if code := postRaw(t, h, "/v1/workspaces/"+okWS+"/envelopes", `"x"`, "192.0.2.1:1"); code != http.StatusOK {
		t.Errorf("workspace id at the limit: want 200, got %d", code)
	}
	longDev := strings.Repeat("d", maxDeviceIDLen+1)
	for _, rt := range []string{"candidates", "presence"} {
		body := fmt.Sprintf(`{"device_id":%q,"data":{}}`, longDev)
		if code := postRaw(t, h, "/v1/workspaces/w/"+rt, body, "192.0.2.1:1"); code != http.StatusBadRequest {
			t.Errorf("%s over-long device id: want 400, got %d", rt, code)
		}
	}
}
