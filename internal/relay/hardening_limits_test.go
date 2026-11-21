package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Per-client SSE cap ───────────────────────────────────────────────────────

// One client could hold every SSE slot (LANGSTROTH_RELAY_MAX_SSE, instance-wide)
// and lock every other client out of push. Each client now has its own cap.
func TestSSEPerClientCap(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_MAX_SSE_PER_CLIENT", "2")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()

	open := func(addr string) (int, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		r := httptest.NewRequest("GET", "/v1/workspaces/ws/events", nil).WithContext(ctx)
		r.RemoteAddr = addr
		w := newStreamRecorder()
		go h.ServeHTTP(w, r)
		select {
		case <-w.started:
		case <-time.After(5 * time.Second):
			t.Fatal("stream did not start")
		}
		return w.status(), cancel
	}
	var cancels []context.CancelFunc
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()
	for i := 0; i < 2; i++ {
		code, c := open("192.0.2.1:1000")
		cancels = append(cancels, c)
		if code != 200 {
			t.Fatalf("stream %d: %d", i, code)
		}
	}
	code, c := open("192.0.2.1:1001")
	cancels = append(cancels, c)
	if code != http.StatusTooManyRequests {
		t.Fatalf("third stream from one client: %d, want 429", code)
	}
	code, c = open("192.0.2.2:1000")
	cancels = append(cancels, c)
	if code != 200 {
		t.Fatalf("another client: %d, want 200", code)
	}
}

func TestKeyedLimiterReleases(t *testing.T) {
	l := newKeyedConcurrencyLimiter(1)
	rel, ok := l.acquire("a")
	if !ok {
		t.Fatal("first acquire")
	}
	if _, ok := l.acquire("a"); ok {
		t.Fatal("second acquire for the same key must fail")
	}
	rel()
	rel() // idempotent
	if _, ok := l.acquire("a"); !ok {
		t.Fatal("acquire after release")
	}
	if n := l.size(); n != 1 {
		t.Fatalf("tracked keys = %d, want 1", n)
	}
}

// streamRecorder is a ResponseWriter that signals once headers are written.
type streamRecorder struct {
	*httptest.ResponseRecorder
	started chan struct{}
	done    bool
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{})}
}

func (s *streamRecorder) WriteHeader(code int) {
	s.ResponseRecorder.WriteHeader(code)
	if !s.done {
		s.done = true
		close(s.started)
	}
}

func (s *streamRecorder) Write(b []byte) (int, error) {
	if !s.done {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseRecorder.Write(b)
}

func (s *streamRecorder) status() int { return s.ResponseRecorder.Code }

// ── Read-path rate limit ─────────────────────────────────────────────────────

// Workspace reads had no rate limit, so one client could loop the bounded
// list routes and keep the store busy. They now share a per-client bucket.
func TestReadPathRateLimited(t *testing.T) {
	t.Setenv("LANGSTROTH_RELAY_READ_RATE", "0.001")
	t.Setenv("LANGSTROTH_RELAY_READ_BURST", "3")
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := newTestHTTP(t, srv)
	paths := []string{"/v1/workspaces/ws/envelopes", "/v1/workspaces/ws/keyring", "/v1/workspaces/ws/presence"}
	for _, p := range paths {
		if resp, _ := do(t, "GET", ts+p, "", nil); resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := do(t, "GET", ts+"/v1/workspaces/ws/candidates", "", nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("read past the burst: %d, want 429", resp.StatusCode)
	}
}

// ── Admin handlers ───────────────────────────────────────────────────────────

type failingUserStore struct{ Store }

var errSecretDetail = errors.New(`pq: relation "relay_users" password=hunter2 does not exist`)

func (failingUserStore) CreateUser(context.Context, string, string, int64) (UserRecord, error) {
	return UserRecord{}, errSecretDetail
}
func (failingUserStore) ListUsers(context.Context) ([]UserRecord, error) {
	return nil, errSecretDetail
}
func (failingUserStore) SetUserDisabled(context.Context, string, bool) error {
	return errSecretDetail
}
func (failingUserStore) RevokeToken(context.Context, string, int64) error {
	return errSecretDetail
}

// Store errors were echoed in admin responses (driver messages, table names,
// connection details). They are logged, and the client gets a generic 500.
func TestAdminDoesNotEchoStoreErrors(t *testing.T) {
	srv := New(Options{Store: failingUserStore{newMemoryStore()}, AdminAuth: allowAdmin{}})
	ts := newTestHTTP(t, srv)
	cases := []struct{ method, path, body string }{
		{"POST", "/v1/admin/users", `{"name":"a"}`},
		{"GET", "/v1/admin/users", ""},
		{"POST", "/v1/admin/users/u1/tokens", `{}`},
		{"POST", "/v1/admin/users/u1/disabled", `{"disabled":true}`},
		{"DELETE", "/v1/admin/tokens/t1", ""},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, ts+c.path, strings.NewReader(c.body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s %s: status %d, want 500", c.method, c.path, resp.StatusCode)
		}
		if strings.Contains(string(buf[:n]), "hunter2") || strings.Contains(string(buf[:n]), "relay_users") {
			t.Errorf("%s %s echoed the store error: %q", c.method, c.path, buf[:n])
		}
	}
}

// Admin bodies were decoded without a size bound.
func TestAdminBodiesBounded(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), AdminAuth: allowAdmin{}})
	ts := newTestHTTP(t, srv)
	huge := `{"name":"` + strings.Repeat("a", maxAdminBodyBytes+1) + `"}`
	for _, p := range []string{"/v1/admin/users", "/v1/admin/users/u1/tokens", "/v1/admin/users/u1/disabled"} {
		resp, err := http.Post(ts+p, "application/json", strings.NewReader(huge))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("%s with an oversized body: %d, want 413", p, resp.StatusCode)
		}
	}
}

// friendErr echoed unexpected store errors; only its own refusals are shown.
func TestFriendErrHidesStoreErrors(t *testing.T) {
	w := httptest.NewRecorder()
	friendErr(w, errSecretDetail)
	if w.Code != 500 || strings.Contains(w.Body.String(), "hunter2") {
		t.Fatalf("friendErr: %d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	friendErr(w, ErrCapReached)
	if w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), ErrCapReached.Error()) {
		t.Fatalf("friendErr sentinel: %d %q", w.Code, w.Body.String())
	}
}

// ── Idempotency key scoped to the writer ─────────────────────────────────────

// A client-chosen Idempotency-Key was global to the workspace, so a writer who
// learned (or guessed) another writer's key could push first and make the
// victim's envelope a silent duplicate. The stored key is scoped to the writer.
func TestIdempotencyKeyScopedToWriter(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	h := srv.Handler()
	push := func(addr, body string) string {
		r := httptest.NewRequest("POST", "/v1/workspaces/ws/envelopes", strings.NewReader(body))
		r.RemoteAddr = addr
		r.Header.Set("Idempotency-Key", "evt-1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("push from %s: %d %s", addr, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	attacker := push("192.0.2.66:1", `{"ciphertext":"junk"}`)
	victim := push("192.0.2.7:1", `{"ciphertext":"real"}`)
	if attacker == victim {
		t.Fatalf("victim's push was deduped against the attacker's key: %s", victim)
	}
	if again := push("192.0.2.7:2", `{"ciphertext":"real"}`); again != victim {
		t.Fatalf("the same writer's re-push must still dedup: %s vs %s", again, victim)
	}
	rows, _ := srv.store.EnvelopesAfter(context.Background(), "ws", 0)
	if len(rows) != 2 {
		t.Fatalf("want 2 envelopes, got %d", len(rows))
	}
}
