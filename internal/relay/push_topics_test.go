package relay

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLogs routes slog to a buffer for the rest of the test.
func captureLogs(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func TestAPNsTopicsFromEnv(t *testing.T) {
	path, _ := testP8(t)
	base := func(extra map[string]string) map[string]string {
		m := map[string]string{
			"LANGSTROTH_RELAY_APNS_KEY_FILE": path, "LANGSTROTH_RELAY_APNS_KEY_ID": "KEYID12345", "LANGSTROTH_RELAY_APNS_TEAM_ID": "TEAMID1234",
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// The old single-topic config keeps working: one allowed topic.
	s, err := apnsPushSenderFrom(envMap(base(map[string]string{"LANGSTROTH_RELAY_APNS_TOPIC": "com.example.ligus"})))
	if err != nil || s.Client.Topic != "com.example.ligus" || strings.Join(s.Topics, ",") != "com.example.ligus" {
		t.Fatalf("single topic: %+v %v", s, err)
	}

	// A list alone: the first is the default for phones that don't say.
	s, err = apnsPushSenderFrom(envMap(base(map[string]string{"LANGSTROTH_RELAY_APNS_TOPICS": " com.example.ligus , com.example.ligus.lab ,"})))
	if err != nil || s.Client.Topic != "com.example.ligus" || strings.Join(s.Topics, ",") != "com.example.ligus,com.example.ligus.lab" {
		t.Fatalf("topic list: %+v %v", s, err)
	}

	// Both: TOPIC is the default, the union is allowed (no duplicates).
	s, err = apnsPushSenderFrom(envMap(base(map[string]string{
		"LANGSTROTH_RELAY_APNS_TOPIC": "com.example.ligus", "LANGSTROTH_RELAY_APNS_TOPICS": "com.example.ligus.lab,com.example.ligus",
	})))
	if err != nil || s.Client.Topic != "com.example.ligus" || strings.Join(s.Topics, ",") != "com.example.ligus,com.example.ligus.lab" {
		t.Fatalf("topic + list: %+v %v", s, err)
	}

	// The LANGSTROTH_RELAY_APNS_TOPICS list alone.
	canonical := base(map[string]string{"LANGSTROTH_RELAY_APNS_TOPICS": "com.example.ligus.lab"})
	resolved := envMap(canonical)
	if s, err = apnsPushSenderFrom(resolved); err != nil || s.Client.Topic != "com.example.ligus.lab" {
		t.Fatalf("LANGSTROTH_RELAY_APNS_TOPICS: %+v %v", s, err)
	}

	// A malformed bundle id is a configuration error (push stays off).
	if _, err := apnsPushSenderFrom(envMap(base(map[string]string{"LANGSTROTH_RELAY_APNS_TOPICS": "com.example.ligus,not a topic"}))); err == nil {
		t.Fatal("malformed topic accepted")
	}
	// No topic at all is still incomplete.
	if _, err := apnsPushSenderFrom(envMap(base(nil))); err == nil || !strings.Contains(err.Error(), "LANGSTROTH_RELAY_APNS_TOPIC") {
		t.Fatalf("no topic: %v", err)
	}
}

// The relay pushes to the topic the phone reported at registration when it is
// allow-listed, refuses one that isn't (without forgetting the token), uses
// the default topic for an older phone, logs every APNs result without the
// device token, and reports details to a host that asks (diag) while plain
// acks stay byte-for-byte what they were.
func TestTunnel_PushTopicAllowList(t *testing.T) {
	logs := captureLogs(t)
	path, _ := testP8(t)
	t.Setenv("LANGSTROTH_RELAY_APNS_KEY_FILE", path)
	t.Setenv("LANGSTROTH_RELAY_APNS_KEY_ID", "KEYID12345")
	t.Setenv("LANGSTROTH_RELAY_APNS_TEAM_ID", "TEAMID1234")
	t.Setenv("LANGSTROTH_RELAY_APNS_TOPIC", "com.example.ligus")
	t.Setenv("LANGSTROTH_RELAY_APNS_TOPICS", "com.example.ligus.lab")
	f, apnsSrv := newFakeAPNs(t)
	env := newTunnelEnv(t, nil, nil, nil)
	sender := env.hub.push.(*APNsPushSender)
	sender.Client.HTTP, sender.Client.ProductionURL, sender.Client.SandboxURL = apnsSrv.Client(), apnsSrv.URL+"/prod", apnsSrv.URL+"/sandbox"

	h := newFakeHost(t, env)
	h.connect()
	register := func(apns map[string]any) (*fakePhone, string) {
		p := newFakePhone()
		now := time.Now().Unix()
		c := p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+86400), map[string]any{"apns": apns})
		o := h.next("open")
		h.send(map[string]any{"t": "reject", "sid": o["sid"], "code": "host_rejected"})
		expectClose(t, c, 4010)
		return p, apns["token"].(string)
	}
	reqs := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.reqs)
	}
	ct := b64u([]byte("opaque"))
	tokenOf := func(p *fakePhone) *PushToken {
		tok, _ := env.hub.store.TunnelPushToken(context.Background(), h.id, p.pid)
		return tok
	}

	// The lab build reports its bundle id: pushed with that topic, sandbox.
	lab, labTok := register(map[string]any{"token": strings.Repeat("1a", 32), "env": "development", "topic": "com.example.ligus.lab"})
	a := h.request(map[string]any{"t": "push", "id": "1", "pid": lab.pid, "ct": ct, "prio": "high"})
	if a["ok"] != true || len(a) != 3 {
		t.Fatalf("plain ack must stay {t,id,ok}: %v", a)
	}
	f.mu.Lock()
	r := f.reqs[0]
	f.mu.Unlock()
	if r.Header.Get("apns-topic") != "com.example.ligus.lab" || !strings.HasPrefix(r.URL.Path, "/sandbox/") {
		t.Fatalf("lab push went to %s topic %q", r.URL.Path, r.Header.Get("apns-topic"))
	}
	// diag: the host asked what happened.
	a = h.request(map[string]any{"t": "push", "id": "2", "pid": lab.pid, "ct": ct, "diag": true})
	d, _ := a["detail"].(string)
	if a["ok"] != true || !strings.Contains(d, "200") || !strings.Contains(d, "sandbox") || !strings.Contains(d, "com.example.ligus.lab") {
		t.Fatalf("diag ack: %v", a)
	}

	// A topic that isn't allow-listed: refused before APNs, token kept.
	before := reqs()
	other, otherTok := register(map[string]any{"token": strings.Repeat("2b", 32), "env": "production", "topic": "com.other.app"})
	a = h.request(map[string]any{"t": "push", "id": "3", "pid": other.pid, "ct": ct, "diag": true})
	if a["code"] != "push_failed" || !strings.Contains(a["detail"].(string), "not allowed") {
		t.Fatalf("unlisted topic: %v", a)
	}
	if reqs() != before || tokenOf(other) == nil {
		t.Fatalf("unlisted topic reached APNs (%d→%d) or dropped the token", before, reqs())
	}

	// An older phone (no topic) gets the default; DeviceTokenNotForTopic then
	// means the relay's default is wrong for it: keep the token.
	old, oldTok := register(map[string]any{"token": strings.Repeat("3c", 32), "env": "production"})
	f.mu.Lock()
	f.status, f.reason = 400, "DeviceTokenNotForTopic"
	f.mu.Unlock()
	a = h.request(map[string]any{"t": "push", "id": "4", "pid": old.pid, "ct": ct, "diag": true})
	if a["code"] != "push_failed" || !strings.Contains(a["detail"].(string), "DeviceTokenNotForTopic") {
		t.Fatalf("not for default topic: %v", a)
	}
	f.mu.Lock()
	r = f.reqs[len(f.reqs)-1]
	f.mu.Unlock()
	if r.Header.Get("apns-topic") != "com.example.ligus" || !strings.HasPrefix(r.URL.Path, "/prod/") {
		t.Fatalf("old phone push: %s %q", r.URL.Path, r.Header.Get("apns-topic"))
	}
	if tokenOf(old) == nil {
		t.Fatal("a relay-side topic mistake dropped the phone's token")
	}
	// …but for the topic the phone itself reported, the token is gone.
	a = h.request(map[string]any{"t": "push", "id": "5", "pid": lab.pid, "ct": ct})
	if a["code"] != "push_failed" || a["detail"] != nil {
		t.Fatalf("not for reported topic: %v", a)
	}
	if tokenOf(lab) != nil {
		t.Fatal("a token APNs says isn't for the phone's own topic was kept")
	}

	// A malformed topic is a malformed apns member.
	p := newFakePhone()
	now := time.Now().Unix()
	c := p.connect(t, env, h.id, h.cred(p.pid, p.pub(), now, now+86400),
		map[string]any{"apns": map[string]any{"token": strings.Repeat("4d", 32), "env": "production", "topic": "bad topic/../x"}})
	expectClose(t, c, 4000)

	// Every APNs answer is logged with status and reason, never a token.
	out := logs.String()
	for _, want := range []string{"status=200", "reason=DeviceTokenNotForTopic", "topic=com.example.ligus.lab", "env=sandbox", "not allowed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %q:\n%s", want, out)
		}
	}
	for _, tok := range []string{labTok, otherTok, oldTok} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(tok)) {
			t.Fatalf("a device token reached the log:\n%s", out)
		}
	}
}

// Refusals before APNs (no token, rate limit) are logged too.
func TestTunnel_PushRefusalsAreLogged(t *testing.T) {
	logs := captureLogs(t)
	env := newTunnelEnv(t, nil, &fakePush{}, nil)
	h := newFakeHost(t, env)
	h.connect()
	p := newFakePhone()
	a := h.request(map[string]any{"t": "push", "id": "1", "pid": p.pid, "ct": b64u([]byte("x")), "diag": true})
	if a["code"] != "no_push_token" || !strings.Contains(a["detail"].(string), "no push token") {
		t.Fatalf("no token: %v", a)
	}
	if out := logs.String(); !strings.Contains(out, "tunnel push") || !strings.Contains(out, "result=no_push_token") {
		t.Fatalf("refusal not logged:\n%s", out)
	}
}
