package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The GitHub-backed routes (directory / account / friends) used to fall back to
// the Authorization bearer when no explicit GitHub token header was sent, and
// forwarded it to api.github.com. That bearer is the caller's relay access
// token (hrt1 / access token), so every relay credential reached GitHub. Only
// the explicit GitHub token header may be verified now.
func TestGitHubRoutesNeverUseRelayBearer(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}, GitHubRoutes: true})
	var mu sync.Mutex
	var seen []string
	srv.verify = func(_ context.Context, token string) (*githubUser, error) {
		mu.Lock()
		seen = append(seen, token)
		mu.Unlock()
		return &githubUser{ID: 7, Login: "alice"}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	routes := []struct{ method, path string }{
		{"GET", "/v1/friends"},
		{"GET", "/v1/account/devices"},
		{"GET", "/v1/account/inbox"},
		{"POST", "/v1/directory/register"},
	}
	const relayTok = "ghp_relayAccessTokenLooksPlausible"
	for _, rt := range routes {
		req, _ := http.NewRequest(rt.method, ts.URL+rt.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+relayTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with only a relay bearer: status %d, want 401", rt.method, rt.path, resp.StatusCode)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("relay bearer was sent to GitHub verification: %q", seen)
	}
}

// The explicit header still works, and wins over (and never mixes with) the
// relay bearer.
func TestGitHubRoutesUseExplicitHeaderOnly(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}, GitHubRoutes: true})
	var seen []string
	var mu sync.Mutex
	srv.verify = func(_ context.Context, token string) (*githubUser, error) {
		mu.Lock()
		seen = append(seen, token)
		mu.Unlock()
		return &githubUser{ID: 7, Login: "alice"}, nil
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, h := range []string{"X-Hive-Github-Token", "X-Ligus-Github-Token"} {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/friends", nil)
		req.Header.Set("Authorization", "Bearer hrt1.relaytokenvalue")
		req.Header.Set(h, "gho_explicitGitHubToken_"+h)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", h, resp.StatusCode)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, tok := range seen {
		if strings.Contains(tok, "hrt1") {
			t.Fatalf("relay bearer reached GitHub verification: %q", tok)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("verified %d tokens, want 2", len(seen))
	}
}

// The outbound verification sends only the GitHub token it was given.
func TestVerifyGitHubSendsOnlyGivenToken(t *testing.T) {
	var got string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"id":1,"login":"a"}`))
	}))
	defer gh.Close()
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}, GitHubRoutes: true})
	srv.httpClient = gh.Client()
	srv.httpClient.Transport = rewriteTo(gh.URL)
	if _, err := srv.verifyGitHub(context.Background(), "gho_abc"); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer gho_abc" {
		t.Fatalf("Authorization sent to GitHub = %q", got)
	}
}

type rewriteTo string

func (u rewriteTo) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme = "http"
	r2.URL.Host = strings.TrimPrefix(string(u), "http://")
	return http.DefaultTransport.RoundTrip(r2)
}
