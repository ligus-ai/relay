package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The relay v0.3 contact routes (PUT/GET/DELETE /v1/contacts/{cid} and the
// drop box) are part of the Ligus 2.0 wire freeze: their requests, statuses
// and bodies must stay byte-identical from here on (only additive changes).
// testdata/golden_v03_contacts.json was recorded with -update-golden on
// release/v0.3.0; every later release must reproduce it. Timestamps and the
// time-derived drop sequence numbers are normalized before comparing.

const goldenContactsFile = "testdata/golden_v03_contacts.json"

type goldenContactReq struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body,omitempty"`
	Key    string `json:"key,omitempty"`    // X-Ligus-Contact-Key
	Bearer string `json:"bearer,omitempty"` // Authorization: Bearer
}

type goldenContactResp struct {
	Req         goldenContactReq `json:"req"`
	Status      int              `json:"status"`
	ContentType string           `json:"contentType"`
	Cache       string           `json:"cache,omitempty"`
	Body        string           `json:"body"`
}

const (
	gcCID   = "AAECAwQFBgcICQoLDA0ODw"                      // 16 bytes
	gcKey   = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // 32 bytes
	gcOther = "HxAREhMUFRYXGBkaGxwdHh8AAQIDBAUGBwgJCgsMDQ4" // 32 bytes
)

var goldenContactRequests = []goldenContactReq{
	{"GET", "/v1/contacts/" + gcCID, "", "", ""},                                                           // unknown → 404
	{"GET", "/v1/contacts/not-a-cid", "", "", ""},                                                          // bad cid → 400
	{"PUT", "/v1/contacts/" + gcCID, `{"record":{"v":1,"name":"Ana"}}`, "", ""},                            // no key → 401
	{"PUT", "/v1/contacts/" + gcCID, `{"record":{"v":1,"name":"Ana"}}`, "short", ""},                       // bad key → 400
	{"PUT", "/v1/contacts/" + gcCID, `{"record":null}`, gcKey, ""},                                         // no record → 400
	{"PUT", "/v1/contacts/" + gcCID, `{"record":{"v":1,"name":"Ana"}}`, gcKey, ""},                         // created
	{"PUT", "/v1/contacts/" + gcCID, `{"record":{"v":2,"name":"Ana"},"writeKey":"` + gcKey + `"}`, "", ""}, // update via body key
	{"PUT", "/v1/contacts/" + gcCID, `{"record":{"v":3}}`, gcOther, ""},                                    // wrong key → 403
	{"PUT", "/v1/contacts/" + gcCID, `{"record":{"v":3},"writeKey":"` + gcOther + `"}`, gcKey, ""},         // keys differ → 400
	{"GET", "/v1/contacts/" + gcCID, "", "", ""},                                                           // the record
	{"GET", "/v1/contacts/" + gcCID, "", "", "ghp_0123456789abcdef"},                                       // forge token → 400
	{"POST", "/v1/contacts/" + gcCID + "/drop", `{"blob":{"sealed":"x"}}`, "", ""},
	{"POST", "/v1/contacts/" + gcCID + "/drop", `{"blob":"second"}`, "", ""},
	{"POST", "/v1/contacts/" + gcCID + "/drop", `{"blob":null}`, "", ""}, // no blob → 400
	{"GET", "/v1/contacts/" + gcCID + "/drop", "", "", ""},               // no key → 401
	{"GET", "/v1/contacts/" + gcCID + "/drop", "", gcOther, ""},          // wrong key → 403
	{"GET", "/v1/contacts/" + gcCID + "/drop", "", gcKey, ""},
	{"GET", "/v1/contacts/" + gcCID + "/drop?after=1", "", gcKey, ""},
	{"GET", "/v1/contacts/" + gcCID + "/drop?limit=1", "", gcKey, ""},
	{"DELETE", "/v1/contacts/" + gcCID + "/drop", "", gcKey, ""},                              // no through → 400
	{"DELETE", "/v1/contacts/" + gcCID + "/drop?through=1", "", gcKey, ""},                    // before every seq → 0
	{"DELETE", "/v1/contacts/" + gcCID + "/drop?through=18446744073709551615", "", gcKey, ""}, // all → 2
	{"GET", "/v1/contacts/" + gcCID + "/drop", "", gcKey, ""},
	{"DELETE", "/v1/contacts/" + gcCID, "", gcOther, ""}, // wrong key → 403
	{"DELETE", "/v1/contacts/" + gcCID, "", gcKey, ""},
	{"GET", "/v1/contacts/" + gcCID, "", "", ""}, // gone → 404
}

var goldenContactNormalizers = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`"(updatedAt|expiresAt|createdAt)":\d+`), `"$1":<TS>`},
	// Drop sequence numbers are time-derived (monotonic per box).
	{regexp.MustCompile(`"seq":\d+`), `"seq":<SEQ>`},
}

func runGoldenContactRequests(t *testing.T) []goldenContactResp {
	t.Helper()
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	out := make([]goldenContactResp, 0, len(goldenContactRequests))
	for _, g := range goldenContactRequests {
		var body io.Reader
		if g.Body != "" {
			body = strings.NewReader(g.Body)
		}
		req, err := http.NewRequest(g.Method, ts.URL+g.Path, body)
		if err != nil {
			t.Fatal(err)
		}
		if g.Key != "" {
			req.Header.Set(contactKeyHeader, g.Key)
		}
		if g.Bearer != "" {
			req.Header.Set("Authorization", "Bearer "+g.Bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		s := string(b)
		for _, n := range goldenContactNormalizers {
			s = n.re.ReplaceAllString(s, n.with)
		}
		out = append(out, goldenContactResp{Req: g, Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Cache: resp.Header.Get("Cache-Control"), Body: s})
	}
	return out
}

func TestContactRoutesMatchGolden(t *testing.T) {
	got := runGoldenContactRequests(t)
	if *updateGolden {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(goldenContactsFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(goldenContactsFile)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var want []goldenContactResp
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
		if w != g {
			t.Errorf("#%d %s %s:\n got %d %q %q %q\nwant %d %q %q %q", i, g.Req.Method, g.Req.Path,
				g.Status, g.ContentType, g.Cache, g.Body, w.Status, w.ContentType, w.Cache, w.Body)
		}
	}
}
