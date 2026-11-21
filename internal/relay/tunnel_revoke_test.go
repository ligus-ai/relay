package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// revokeBody builds a POST /v1/tunnel/revoke body signed with key for hostID.
func revokeBody(key ed25519.PrivateKey, hostID, pid string, exp, ts int64, nonce []byte) map[string]any {
	return map[string]any{
		"v": 1, "hostId": hostID, "pid": pid, "exp": exp, "ts": ts, "nonce": b64u(nonce),
		"sig": b64u(ed25519.Sign(key, hostRevokeMessage(hostID, pid, exp, ts, nonce))),
	}
}

func freshNonce() []byte {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	return n
}

func postRevoke(t *testing.T, env *tunnelEnv, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	res, err := http.Post(env.ts.URL+"/v1/tunnel/revoke", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return res.StatusCode, m
}

// A host's signed HTTP revocation closes the phone's live session (both
// ends) within a bounded time, drops its push token, refuses its next
// session and every later push, and reports what it did.
func TestTunnelRevoke_CutsSessionPushAndReconnect(t *testing.T) {
	push := &fakePush{}
	env := newTunnelEnv(t, nil, push, nil)
	h := newFakeHost(t, env)
	h.connect()
	p := newFakePhone()
	now := time.Now().Unix()
	cred := h.cred(p.pid, p.pub(), now, now+86400)
	phone := p.connect(t, env, h.id, cred, map[string]any{"apns": map[string]any{"token": "abcdef01", "env": "production"}})
	open := h.next("open")
	host := env.mustDial("/v1/tunnel/accept?sid=" + open["sid"].(string))
	readJSONMsg(t, phone) // ready
	other := newFakePhone()
	ph2, _ := session(t, env, h, other)

	start := time.Now()
	st, res := postRevoke(t, env, revokeBody(h.sign, h.id, p.pid, now+86400, now, freshNonce()))
	if st != http.StatusOK || res["ok"] != true || res["sessionsClosed"] != float64(1) || res["pushTokenRemoved"] != true {
		t.Fatalf("revoke: %d %v", st, res)
	}
	expectClose(t, phone, 4003)
	expectClose(t, host, 4003)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("live tunnel closed after %v, want < 1 s", el)
	}
	if tok, _ := env.hub.store.TunnelPushToken(context.Background(), h.id, p.pid); tok != nil {
		t.Fatal("push token survived revocation")
	}
	// A new session with the same credential is refused.
	expectClose(t, p.connect(t, env, h.id, cred, nil), 4003)
	// No push is sent after the revocation, even if the host asks.
	push.mu.Lock()
	before := len(push.sent)
	push.mu.Unlock()
	if a := h.request(map[string]any{"t": "push", "id": "p1", "pid": p.pid, "ct": b64u(make([]byte, 40))}); a["code"] != "revoked" {
		t.Fatalf("push after revoke: %v", a)
	}
	push.mu.Lock()
	if len(push.sent) != before {
		t.Fatal("a push reached the push service after revocation")
	}
	push.mu.Unlock()
	// The other phone is untouched.
	if err := ph2.WriteMessage(websocket.BinaryMessage, []byte{1}); err != nil {
		t.Fatal(err)
	}

	// Idempotent: a second (fresh) request succeeds and reports nothing left to do.
	st, res = postRevoke(t, env, revokeBody(h.sign, h.id, p.pid, now+86400, now, freshNonce()))
	if st != http.StatusOK || res["ok"] != true || res["sessionsClosed"] != float64(0) || res["pushTokenRemoved"] != false {
		t.Fatalf("second revoke: %d %v", st, res)
	}
}

// The relay holds the revocation even without the host's control connection
// (the host may be between reconnects when the owner revokes).
func TestTunnelRevoke_WorksWithoutControlConnection(t *testing.T) {
	env := newTunnelEnv(t, nil, &fakePush{}, nil)
	h := newFakeHost(t, env)
	h.connect()
	_ = h.ctl.Close()
	p := newFakePhone()
	now := time.Now().Unix()
	st, res := postRevoke(t, env, revokeBody(h.sign, h.id, p.pid, now+3600, now, freshNonce()))
	if st != http.StatusOK || res["ok"] != true {
		t.Fatalf("revoke: %d %v", st, res)
	}
	if rv, _ := env.hub.store.TunnelPhoneRevoked(context.Background(), h.id, p.pid, now); !rv {
		t.Fatal("not revoked")
	}
}

// Forged, replayed, stale and malformed requests are refused and change nothing.
func TestTunnelRevoke_RefusesForgedReplayedStale(t *testing.T) {
	env := newTunnelEnv(t, nil, &fakePush{}, nil)
	h := newFakeHost(t, env)
	h.connect()
	p := newFakePhone()
	now := time.Now().Unix()
	notRevoked := func(what string) {
		t.Helper()
		if rv, _ := env.hub.store.TunnelPhoneRevoked(context.Background(), h.id, p.pid, now); rv {
			t.Fatalf("%s: the phone got revoked", what)
		}
	}

	// Forged: signed by a key that isn't the host's.
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if st, _ := postRevoke(t, env, revokeBody(wrong, h.id, p.pid, now+3600, now, freshNonce())); st != http.StatusUnauthorized {
		t.Fatalf("forged: %d", st)
	}
	notRevoked("forged")
	// Tampered: a valid signature over another pid.
	b := revokeBody(h.sign, h.id, newFakePhone().pid, now+3600, now, freshNonce())
	b["pid"] = p.pid
	if st, _ := postRevoke(t, env, b); st != http.StatusUnauthorized {
		t.Fatalf("tampered: %d", st)
	}
	notRevoked("tampered")
	// Tampered exp.
	b = revokeBody(h.sign, h.id, p.pid, now+3600, now, freshNonce())
	b["exp"] = now + 7200
	if st, _ := postRevoke(t, env, b); st != http.StatusUnauthorized {
		t.Fatalf("tampered exp: %d", st)
	}
	notRevoked("tampered exp")
	// Stale or future timestamps.
	for _, ts := range []int64{now - tunnelSkewSecs - 60, now + tunnelSkewSecs + 60} {
		if st, _ := postRevoke(t, env, revokeBody(h.sign, h.id, p.pid, now+3600, ts, freshNonce())); st != http.StatusUnauthorized {
			t.Fatalf("ts %d: %d", ts, st)
		}
	}
	notRevoked("stale")
	// Unknown host (never registered).
	ghost := newFakeHost(t, env)
	if st, _ := postRevoke(t, env, revokeBody(ghost.sign, ghost.id, p.pid, now+3600, now, freshNonce())); st != http.StatusUnauthorized {
		t.Fatalf("unknown host: %d", st)
	}
	// Malformed.
	for _, bad := range []any{
		map[string]any{"v": 1},
		map[string]any{"v": 2, "hostId": h.id, "pid": p.pid, "exp": now, "ts": now, "nonce": b64u(freshNonce()), "sig": b64u(make([]byte, 64))},
		"not an object",
	} {
		if st, _ := postRevoke(t, env, bad); st != http.StatusBadRequest {
			t.Fatalf("malformed %v: %d", bad, st)
		}
	}
	notRevoked("malformed")

	// Replay: the same signed request twice. The first is applied, the
	// replay is refused (409) and doesn't run again.
	body := revokeBody(h.sign, h.id, p.pid, now+3600, now, freshNonce())
	if st, _ := postRevoke(t, env, body); st != http.StatusOK {
		t.Fatalf("first: %d", st)
	}
	if st, res := postRevoke(t, env, body); st != http.StatusConflict || res["error"] != "replayed" {
		t.Fatalf("replay: %d %v", st, res)
	}
}

// Concurrent replays of one request: exactly one is applied.
func TestTunnelRevoke_ConcurrentReplayAppliedOnce(t *testing.T) {
	env := newTunnelEnv(t, nil, &fakePush{}, nil)
	h := newFakeHost(t, env)
	h.connect()
	now := time.Now().Unix()
	body := revokeBody(h.sign, h.id, newFakePhone().pid, now+3600, now, freshNonce())
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, _ := postRevoke(t, env, body)
			mu.Lock()
			codes[st]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[http.StatusOK] != 1 || codes[http.StatusConflict] != 15 {
		t.Fatalf("codes %v", codes)
	}
}

// Another host can't revoke a phone of this host: it can't sign as this host,
// and revoking "the same pid" under its own host id touches only its own
// (empty) state.
func TestTunnelRevoke_NonOwnerHostRefused(t *testing.T) {
	push := &fakePush{}
	env := newTunnelEnv(t, nil, push, nil)
	owner := newFakeHost(t, env)
	owner.connect()
	mallory := newFakeHost(t, env)
	mallory.connect()
	p := newFakePhone()
	now := time.Now().Unix()
	phone := p.connect(t, env, owner.id, owner.cred(p.pid, p.pub(), now, now+86400), map[string]any{"apns": map[string]any{"token": "abcdef01", "env": "production"}})
	open := owner.next("open")
	host := env.mustDial("/v1/tunnel/accept?sid=" + open["sid"].(string))
	readJSONMsg(t, phone)

	// Mallory signs for the owner's host id with her own key: refused.
	if st, _ := postRevoke(t, env, revokeBody(mallory.sign, owner.id, p.pid, now+3600, now, freshNonce())); st != http.StatusUnauthorized {
		t.Fatalf("cross-host: %d", st)
	}
	// Mallory revokes the pid under her own host id: allowed, but scoped to her.
	if st, res := postRevoke(t, env, revokeBody(mallory.sign, mallory.id, p.pid, now+3600, now, freshNonce())); st != http.StatusOK || res["sessionsClosed"] != float64(0) || res["pushTokenRemoved"] != false {
		t.Fatalf("own-scope: %d %v", st, res)
	}
	// The owner's phone is still connected, revocable only by the owner, and keeps its token.
	if rv, _ := env.hub.store.TunnelPhoneRevoked(context.Background(), owner.id, p.pid, now); rv {
		t.Fatal("non-owner revoked the owner's phone")
	}
	if tok, _ := env.hub.store.TunnelPushToken(context.Background(), owner.id, p.pid); tok == nil {
		t.Fatal("non-owner removed the owner's phone's push token")
	}
	if err := phone.WriteMessage(websocket.BinaryMessage, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := host.WriteMessage(websocket.BinaryMessage, []byte{1}); err != nil {
		t.Fatal(err)
	}
}

// The signed preimage is fixed (a KAT so a client implementation can't drift).
func TestTunnelRevoke_MessageLayout(t *testing.T) {
	hostID, pid := "AAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBB"
	nonce := bytes.Repeat([]byte{7}, 16)
	got := hostRevokeMessage(hostID, pid, 0x0102030405060708, 0x1112131415161718, nonce)
	want := append([]byte("hive-tunnel/1 host-revoke\x00"), hostID...)
	want = append(want, pid...)
	want = binary.BigEndian.AppendUint64(want, 0x0102030405060708)
	want = binary.BigEndian.AppendUint64(want, 0x1112131415161718)
	want = append(want, nonce...)
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage\n got %q\nwant %q", got, want)
	}
}

// raceStore runs hook right after the first TunnelPhoneRevoked check of pid
// answered "not revoked": a revocation landing between the relay's
// revocation check and the session (and its push token) going live.
type raceStore struct {
	TunnelStore
	pid  string
	once sync.Once
	hook func()
}

func (s *raceStore) TunnelPhoneRevoked(ctx context.Context, hostID, pid string, now int64) (bool, error) {
	rv, err := s.TunnelStore.TunnelPhoneRevoked(ctx, hostID, pid, now)
	if err == nil && !rv && pid == s.pid {
		s.once.Do(s.hook)
	}
	return rv, err
}

// A revocation that lands while a session is being admitted (after its
// revocation check, before it is live) must neither leave the session open
// nor let the phone's push token survive.
func TestTunnelRevoke_RacingSessionKeepsNoSessionOrPushToken(t *testing.T) {
	env := newTunnelEnv(t, nil, &fakePush{}, nil)
	h := newFakeHost(t, env)
	h.connect()
	p := newFakePhone()
	now := time.Now().Unix()
	env.hub.store = &raceStore{TunnelStore: env.hub.store, pid: p.pid, hook: func() {
		if _, _, _, err := env.hub.revokePhone(context.Background(), h.id, p.pid, now+3600); err != nil {
			t.Error(err)
		}
	}}
	phone := p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+86400), map[string]any{"apns": map[string]any{"token": "abcdef01", "env": "production"}})
	expectClose(t, phone, 4003)
	if tok, _ := env.hub.store.TunnelPushToken(context.Background(), h.id, p.pid); tok != nil {
		t.Fatal("the push token survived a revocation that raced the session")
	}
}

// One host can't fill the revoke replay cache and lock every other host
// out of POST /v1/tunnel/revoke.
func TestTunnelRevoke_ReplayCacheIsPerHost(t *testing.T) {
	env := newTunnelEnv(t, nil, &fakePush{}, nil)
	env.hub.revokeSeen = newReplayCache(64)
	flood := newFakeHost(t, env)
	flood.connect()
	victim := newFakeHost(t, env)
	victim.connect()
	now := time.Now().Unix()
	busy := 0
	for i := 0; i < 200; i++ {
		if st, _ := postRevoke(t, env, revokeBody(flood.sign, flood.id, newFakePhone().pid, now+60, now, freshNonce())); st == http.StatusServiceUnavailable {
			busy++
		}
	}
	if busy == 0 {
		t.Fatal("one host's flood was never limited")
	}
	if st, res := postRevoke(t, env, revokeBody(victim.sign, victim.id, newFakePhone().pid, now+60, now, freshNonce())); st != http.StatusOK {
		t.Fatalf("another host locked out: %d %v", st, res)
	}
}

// A real host with a skewed clock is told the relay's time (so it can
// correct) and isn't treated as an attacker: its address isn't blocked
// from the tunnel by repeated retries.
func TestTunnelRevoke_ClockSkewIsReportedNotPunished(t *testing.T) {
	env := newTunnelEnv(t, nil, &fakePush{}, func(l *tunnelLimits) { l.FailedAuthPerMin = 3 })
	h := newFakeHost(t, env)
	h.connect()
	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		st, res := postRevoke(t, env, revokeBody(h.sign, h.id, newFakePhone().pid, now+3600, now-tunnelSkewSecs-120, freshNonce()))
		if st != http.StatusUnauthorized || res["error"] != "clock_skew" {
			t.Fatalf("skewed: %d %v", st, res)
		}
		if n, ok := res["now"].(float64); !ok || int64(n) < now-5 || int64(n) > now+5 {
			t.Fatalf("relay time missing: %v", res)
		}
	}
	// Still welcome: a corrected request and a phone connect both work.
	if st, res := postRevoke(t, env, revokeBody(h.sign, h.id, newFakePhone().pid, now+3600, now, freshNonce())); st != http.StatusOK {
		t.Fatalf("corrected: %d %v", st, res)
	}
	session(t, env, h, newFakePhone())
}

// When every host's quota together fills the cache, a new host's revocation
// still applies (unrecorded: it is idempotent); expired entries free quota.
func TestReplayCache_QuotaAndFullCache(t *testing.T) {
	c := newReplayCache(16) // 2 per host
	for h := 0; h < 8; h++ {
		for n := 0; n < 2; n++ {
			if ok, hf, f := c.claim(string(rune('a'+h)), string(rune('0'+n)), 100, 0); !ok || hf || f {
				t.Fatalf("fill %d/%d: %v %v %v", h, n, ok, hf, f)
			}
		}
	}
	if _, hf, _ := c.claim("a", "9", 100, 0); !hf {
		t.Fatal("host quota not enforced")
	}
	if ok, hf, f := c.claim("z", "0", 100, 0); !ok || hf || !f {
		t.Fatalf("new host on a full cache: %v %v %v", ok, hf, f)
	}
	if ok, _, _ := c.claim("a", "0", 100, 0); ok {
		t.Fatal("replay accepted")
	}
	if ok, hf, f := c.claim("a", "9", 200, 150); !ok || hf || f {
		t.Fatalf("after expiry: %v %v %v", ok, hf, f)
	}
}
