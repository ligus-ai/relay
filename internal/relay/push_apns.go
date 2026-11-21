package relay

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/langstroth-ai/langstroth-relay/internal/apns"
)

// Built-in APNs PushSender (spec §14) for a relay run by the app's publisher.
//
// APNs accepts a push only when it's signed with a key from the Apple
// developer team that publishes the app, so this is useful only to someone
// who builds and signs the iPhone app under their own team (and points
// LANGSTROTH_RELAY_APNS_TOPIC / LANGSTROTH_RELAY_APNS_TOPICS at that build's bundle
// ids). It's off unless configured; then GET /v1/tunnel/info and the host's
// welcome report "push": true. The relay only ever forwards the host's
// ciphertext.
//
//	LANGSTROTH_RELAY_APNS_KEY_FILE  path to the AuthKey_<KEYID>.p8 file (or LANGSTROTH_RELAY_APNS_KEY: the PEM inline, "\n" escapes allowed)
//	LANGSTROTH_RELAY_APNS_KEY_ID    the key's 10-character Key ID
//	LANGSTROTH_RELAY_APNS_TEAM_ID   the Apple developer Team ID
//	LANGSTROTH_RELAY_APNS_TOPIC     the app's bundle id: the default topic
//	LANGSTROTH_RELAY_APNS_TOPICS    more allowed bundle ids, comma-separated (e.g.
//	                           the release and the lab build); the first is the
//	                           default when LANGSTROTH_RELAY_APNS_TOPIC is unset
//	LANGSTROTH_RELAY_APNS_ENV       auto (default: the environment the phone reports with its token) | sandbox | production
//
// A phone reports its bundle id with its token (apns.topic); the relay pushes
// with that topic when it is allowed and refuses the push otherwise. A phone
// that doesn't report one (an older app) gets the default topic.

// ErrPushTokenGone is returned (wrapped) by a PushSender when the push
// service says the device token is no longer valid. The relay then forgets
// the phone's token; the phone re-registers on its next connect.
var ErrPushTokenGone = errors.New("push: device token is gone")

// ErrPushTopicNotAllowed is returned (wrapped) when the phone's reported
// bundle id isn't one this relay pushes to. The token is kept: the relay's
// configuration is what's missing.
var ErrPushTopicNotAllowed = errors.New("push: topic not allowed on this relay")

// PushOutcome is what a push service said about one push, for logs and for a
// host's diagnostic request. It never holds the device token.
type PushOutcome struct {
	Service string // "apns"
	Env     string // "sandbox" | "production"
	Topic   string
	Status  int    // HTTP status from the service; 0 = no answer
	Reason  string // the service's reason, or why the relay didn't send
	ID      string // apns-id
}

// String is the one-line detail a host's push-test prints.
func (o PushOutcome) String() string {
	var b strings.Builder
	b.WriteString(o.Service)
	if o.Env != "" {
		b.WriteString(" " + o.Env)
	}
	if o.Topic != "" {
		b.WriteString(" topic " + o.Topic)
	}
	if o.Status != 0 {
		fmt.Fprintf(&b, ": %d", o.Status)
	} else {
		b.WriteString(":")
	}
	if o.Reason != "" {
		b.WriteString(" " + o.Reason)
	}
	if o.ID != "" {
		b.WriteString(" (apns-id " + o.ID + ")")
	}
	return b.String()
}

// DetailedPushSender is a PushSender that also says what the push service
// answered (logged by the relay; returned to a host that asks with diag).
type DetailedPushSender interface {
	PushSender
	SendDetailed(ctx context.Context, hostID, pid string, token PushToken, ct []byte, prio, collapse string) (PushOutcome, error)
}

// bundleIDRe matches an iOS bundle id (an APNs topic).
var bundleIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)

func validTopic(s string) bool { return bundleIDRe.MatchString(s) && !strings.Contains(s, "..") }

// APNs environment selection for LANGSTROTH_RELAY_APNS_ENV.
const (
	APNsEnvAuto       = "auto"
	APNsEnvSandbox    = "sandbox"
	APNsEnvProduction = "production"
)

// APNsPushSender forwards an encrypted push to APNs.
type APNsPushSender struct {
	Client *apns.Client
	// Env is auto (use the token's reported env), sandbox or production.
	Env string
	// TTL becomes apns-expiration (spec: now + 1 h). Zero = 1 h.
	TTL time.Duration
	// Topics are the bundle ids this relay pushes to. Client.Topic (the
	// default, for a phone that doesn't report one) is always allowed.
	Topics []string
}

func (s *APNsPushSender) allowed(topic string) bool {
	if topic == s.Client.Topic {
		return true
	}
	for _, t := range s.Topics {
		if t == topic {
			return true
		}
	}
	return false
}

// Send implements PushSender.
func (s *APNsPushSender) Send(ctx context.Context, hostID, pid string, tok PushToken, ct []byte, prio, collapse string) error {
	_, err := s.SendDetailed(ctx, hostID, pid, tok, ct, prio, collapse)
	return err
}

// SendDetailed implements DetailedPushSender.
func (s *APNsPushSender) SendDetailed(ctx context.Context, hostID, pid string, tok PushToken, ct []byte, prio, collapse string) (PushOutcome, error) {
	sandbox := tok.Env == "development"
	switch s.Env {
	case APNsEnvSandbox:
		sandbox = true
	case APNsEnvProduction:
		sandbox = false
	}
	out := PushOutcome{Service: "apns", Env: "production", Topic: s.Client.Topic}
	if sandbox {
		out.Env = "sandbox"
	}
	if tok.Topic != "" {
		out.Topic = tok.Topic
		if !s.allowed(tok.Topic) {
			out.Reason = "topic not allowed on this relay (add it to LANGSTROTH_RELAY_APNS_TOPICS)"
			return out, fmt.Errorf("%w: %s", ErrPushTopicNotAllowed, tok.Topic)
		}
	}
	ttl := s.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	p := 10
	if prio == "normal" {
		p = 5
	}
	now := time.Now()
	if s.Client.Now != nil {
		now = s.Client.Now()
	}
	res, err := s.Client.Send(ctx, apns.Message{
		DeviceToken: tok.Token, Sandbox: sandbox, HostID: hostID, PID: pid,
		Ciphertext: ct, CollapseID: collapse, Priority: p, Expiration: now.Add(ttl), Topic: out.Topic,
	})
	if err != nil {
		// A transport error's text carries the request URL, which holds the
		// device token: keep only the underlying cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		out.Reason = "unreachable: " + err.Error()
		return out, fmt.Errorf("apns: %w", err)
	}
	out.Status, out.Reason, out.ID = res.Status, res.Reason, res.APNsID
	// DeviceTokenNotForTopic for a topic the relay picked (the phone didn't
	// report one) is the relay's misconfiguration, not a dead token.
	if res.DeviceGone() && !(res.Reason == "DeviceTokenNotForTopic" && tok.Topic == "") {
		return out, fmt.Errorf("%w (%d %s)", ErrPushTokenGone, res.Status, res.Reason)
	}
	if !res.OK() {
		return out, fmt.Errorf("apns: %d %s", res.Status, res.Reason)
	}
	return out, nil
}

// APNsPushSenderFromEnv builds the built-in sender from LANGSTROTH_RELAY_APNS_*.
// It returns (nil, nil) when none of them is set, and an error when the
// configuration is incomplete or the key doesn't parse (push then stays off).
func APNsPushSenderFromEnv() (*APNsPushSender, error) {
	return apnsPushSenderFrom(getenv)
}

func apnsPushSenderFrom(getenv func(string) string) (*APNsPushSender, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	keyFile, keyPEM := get("LANGSTROTH_RELAY_APNS_KEY_FILE"), get("LANGSTROTH_RELAY_APNS_KEY")
	keyID, teamID, topic, env := get("LANGSTROTH_RELAY_APNS_KEY_ID"), get("LANGSTROTH_RELAY_APNS_TEAM_ID"), get("LANGSTROTH_RELAY_APNS_TOPIC"), strings.ToLower(get("LANGSTROTH_RELAY_APNS_ENV"))
	list := get("LANGSTROTH_RELAY_APNS_TOPICS")
	if keyFile == "" && keyPEM == "" && keyID == "" && teamID == "" && topic == "" && list == "" {
		return nil, nil
	}
	var topics []string
	add := func(t string) error {
		if !validTopic(t) {
			return fmt.Errorf("APNs topic %q is not a bundle id", t)
		}
		for _, have := range topics {
			if have == t {
				return nil
			}
		}
		topics = append(topics, t)
		return nil
	}
	if topic != "" {
		if err := add(topic); err != nil {
			return nil, err
		}
	}
	for _, t := range strings.Split(list, ",") {
		if t = strings.TrimSpace(t); t != "" {
			if err := add(t); err != nil {
				return nil, err
			}
		}
	}
	if topic == "" && len(topics) > 0 {
		topic = topics[0]
	}
	var missing []string
	if keyFile == "" && keyPEM == "" {
		missing = append(missing, "LANGSTROTH_RELAY_APNS_KEY_FILE")
	}
	for _, kv := range [][2]string{{"LANGSTROTH_RELAY_APNS_KEY_ID", keyID}, {"LANGSTROTH_RELAY_APNS_TEAM_ID", teamID}, {"LANGSTROTH_RELAY_APNS_TOPIC (or LANGSTROTH_RELAY_APNS_TOPICS)", topic}} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("APNs push is partly configured; missing %s", strings.Join(missing, ", "))
	}
	switch env {
	case "":
		env = APNsEnvAuto
	case APNsEnvAuto, APNsEnvSandbox, APNsEnvProduction:
	case "development":
		env = APNsEnvSandbox
	default:
		return nil, fmt.Errorf("LANGSTROTH_RELAY_APNS_ENV=%q is not auto|sandbox|production", env)
	}
	var pemBytes []byte
	if keyPEM != "" {
		pemBytes = []byte(strings.ReplaceAll(keyPEM, `\n`, "\n"))
	} else {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("LANGSTROTH_RELAY_APNS_KEY_FILE: %w", err)
		}
		pemBytes = b
	}
	key, err := apns.ParseP8(pemBytes)
	if err != nil {
		// Never echo the key material.
		return nil, errors.New("APNs key doesn't parse as a .p8 (PKCS#8 P-256) key")
	}
	return &APNsPushSender{Client: apns.New(keyID, teamID, topic, key), Env: env, Topics: topics}, nil
}

// pushSenderFromEnv is New's fallback when Options.PushSender is nil and the
// tunnel is on. A misconfiguration is logged and leaves push off.
func pushSenderFromEnv() PushSender {
	s, err := APNsPushSenderFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "langstroth-relay: %v; tunnel push stays off\n", err)
		return nil
	}
	if s == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "langstroth-relay: tunnel push via APNs (topics %s; default %s; env %s)\n", strings.Join(s.Topics, ", "), s.Client.Topic, s.Env)
	return s
}
