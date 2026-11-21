package relay

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The /v1 wire contract of the routes that existed in relay v0.2.0 must stay
// byte-identical (only additive routes are allowed). testdata/golden_v1_routes.json
// was recorded by running this test with -update-golden against the untouched
// v0.2.0 tree; every later release must reproduce it. Volatile values
// (timestamps, random request ids) are normalized before comparing.
//
// The GitHub social routes are deprecated and off by default since v0.3, so
// this test turns them on (LANGSTROTH_RELAY_GITHUB_ROUTES=on, ignored by v0.2.0) to
// check that, when enabled for older clients, they still answer exactly as before.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/golden_v1_routes.json")

const goldenRoutesFile = "testdata/golden_v1_routes.json"

type goldenReq struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body,omitempty"`
	GitHub string `json:"github,omitempty"` // x-hive-github-token value
}

type goldenResp struct {
	Req         goldenReq `json:"req"`
	Status      int       `json:"status"`
	ContentType string    `json:"contentType"`
	Paging      string    `json:"paging,omitempty"` // X-Hive-Next-After / X-Hive-More
	Body        string    `json:"body"`
}

var goldenRequests = []goldenReq{
	{"GET", "/v1/health", "", ""},
	{"POST", "/v1/workspaces/ws1/envelopes", `{"ct":"AAAA","writer":"d1"}`, ""},
	{"POST", "/v1/workspaces/ws1/envelopes", `{"ct":"BBBB","writer":"d1"}`, ""},
	{"POST", "/v1/workspaces/ws1/envelopes", `{"ct":"AAAA","writer":"d1"}`, ""}, // dedup re-push
	{"GET", "/v1/workspaces/ws1/envelopes", "", ""},
	{"GET", "/v1/workspaces/ws1/envelopes?after=1", "", ""},
	{"GET", "/v1/workspaces/ws1/envelopes?after=x", "", ""},
	{"GET", "/v1/workspaces/ws1/envelopes?after=0&limit=1", "", ""},
	{"POST", "/v1/workspaces/ws1/envelopes", `{not json`, ""},
	{"POST", "/v1/workspaces/ws1/keyring", `{"epoch":1,"wrapped":"x"}`, ""},
	{"GET", "/v1/workspaces/ws1/keyring", "", ""},
	{"POST", "/v1/workspaces/ws1/candidates", `{"device_id":"d1","data":{"addrs":["192.0.2.1:1"]}}`, ""},
	{"GET", "/v1/workspaces/ws1/candidates", "", ""},
	{"POST", "/v1/workspaces/ws1/presence", `{"device_id":"d1","data":{"s":"on"}}`, ""},
	{"GET", "/v1/workspaces/ws1/presence", "", ""},
	{"GET", "/v1/workspaces/nope/envelopes", "", ""},
	{"GET", "/v1/workspaces/ws1/members", "", ""}, // membership off → 404
	{"POST", "/v1/pair", `{"payload":""}`, ""},
	{"GET", "/v1/pair/ZZZZZZ", "", ""},
	{"GET", "/v1/admin/users", "", ""}, // no AdminAuthorizer → 404
	{"GET", "/v1/nonexistent", "", ""},

	// GitHub social routes (enabled for this test).
	{"GET", "/v1/directory/alice", "", ""}, // no token → 401
	{"POST", "/v1/directory/register", `{"device_id":"d1","ka_public":"KA1"}`, "tok:alice:1"},
	{"GET", "/v1/directory/alice", "", "tok:bob:2"},
	{"GET", "/v1/directory/@ALICE", "", "tok:bob:2"},
	{"GET", "/v1/directory/nobody", "", "tok:bob:2"},
	{"POST", "/v1/account/register", `{"deviceId":"d1","nodeId":"n1","label":"laptop"}`, "tok:alice:1"},
	{"POST", "/v1/account/register", `{"deviceId":"d2"}`, "tok:bob:2"},
	{"POST", "/v1/account/register", `{"deviceId":""}`, "tok:bob:2"},
	{"POST", "/v1/account/heartbeat", `{"deviceId":"d1"}`, "tok:alice:1"},
	{"POST", "/v1/account/heartbeat", `{"deviceId":"zz"}`, "tok:alice:1"},
	{"GET", "/v1/account/devices", "", "tok:alice:1"},
	{"POST", "/v1/account/visibility", `{"appearOffline":true}`, "tok:alice:1"},
	{"POST", "/v1/account/visibility", `{"appearOffline":false}`, "tok:alice:1"},
	{"POST", "/v1/friends/requests", `{"toLogin":"@bob"}`, "tok:alice:1"},
	{"POST", "/v1/friends/requests", `{"toLogin":"ghost"}`, "tok:alice:1"},
	{"POST", "/v1/friends/requests", `{"toLogin":"alice"}`, "tok:alice:1"},
	{"GET", "/v1/friends/requests", "", "tok:bob:2"},
	{"GET", "/v1/account/inbox", "", "tok:bob:2"},
	{"GET", "/v1/account/inbox?after=1", "", "tok:bob:2"},
	{"POST", "/v1/friends/requests/frnope/accept", "", "tok:bob:2"},
	{"GET", "/v1/friends", "", "tok:alice:1"},
	{"GET", "/v1/friends/presence", "", "tok:alice:1"},
	{"GET", "/v1/friends/github:2/devices", "", "tok:alice:1"},
	{"POST", "/v1/account/invites", `{"toLogin":"bob","invite":{"sealed":"x"}}`, "tok:alice:1"},
	{"POST", "/v1/account/invites", `{"toLogin":"","invite":null}`, "tok:alice:1"},
	{"DELETE", "/v1/friends/github:2", "", "tok:alice:1"},
}

var goldenNormalizers = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`fr[0-9a-f]{32}`), "fr<ID>"},
	{regexp.MustCompile(`"(lastSeen|createdAt)":\d+`), `"$1":<TS>`},
}

func normalizeGolden(s string) string {
	for _, n := range goldenNormalizers {
		s = n.re.ReplaceAllString(s, n.with)
	}
	return s
}

func runGoldenRequests(t *testing.T) []goldenResp {
	t.Helper()
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	srv.verify = func(_ context.Context, token string) (*githubUser, error) {
		parts := strings.Split(token, ":")
		if len(parts) != 3 || parts[0] != "tok" {
			return nil, nil
		}
		var id uint64
		for _, c := range parts[2] {
			id = id*10 + uint64(c-'0')
		}
		return &githubUser{ID: id, Login: parts[1]}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	out := make([]goldenResp, 0, len(goldenRequests))
	for _, g := range goldenRequests {
		var body io.Reader
		if g.Body != "" {
			body = strings.NewReader(g.Body)
		}
		req, err := http.NewRequest(g.Method, ts.URL+g.Path, body)
		if err != nil {
			t.Fatal(err)
		}
		if g.GitHub != "" {
			req.Header.Set("x-hive-github-token", g.GitHub)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		out = append(out, goldenResp{
			Req: g, Status: resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Paging:      strings.Trim(resp.Header.Get(headerEnvelopesNext)+"|"+resp.Header.Get(headerEnvelopesMore), "|"),
			Body:        normalizeGolden(string(b)),
		})
	}
	return out
}

func TestExistingRoutesMatchGolden(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_GITHUB_ROUTES", "on")
	got := runGoldenRequests(t)
	if *updateGolden {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(goldenRoutesFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	checkGolden(t, got)
}

// The blob channel is additive: with it on (the default, above) or off, every
// existing route answers exactly as recorded.
func TestExistingRoutesMatchGoldenWithBlobsOff(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_GITHUB_ROUTES", "on")
	t.Setenv("LANGSTROTH_RELAY_BLOBS", "off")
	checkGolden(t, runGoldenRequests(t))
}

func checkGolden(t *testing.T, got []goldenResp) {
	t.Helper()
	raw, err := os.ReadFile(goldenRoutesFile)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var want []goldenResp
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if len(want) != len(got) {
		t.Fatalf("golden has %d responses, run produced %d", len(want), len(got))
	}
	for i := range want {
		w, g := want[i], got[i]
		if w.Req != g.Req {
			t.Fatalf("#%d: request list drifted from the golden: %+v vs %+v", i, w.Req, g.Req)
		}
		if w.Status != g.Status || w.ContentType != g.ContentType || w.Paging != g.Paging || w.Body != g.Body {
			t.Errorf("#%d %s %s:\n got %d %q %q %q\nwant %d %q %q %q", i, g.Req.Method, g.Req.Path,
				g.Status, g.ContentType, g.Paging, g.Body, w.Status, w.ContentType, w.Paging, w.Body)
		}
	}
}
