package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// The relay side of hive-tunnel/1: phone ↔ home host remote access through the
// relay (docs/reference.md "Relay tunnel"; spec: ligus repo docs/relay-tunnel.md).
//
//	GET /v1/tunnel/info              discovery (plain HTTPS)
//	GET /v1/tunnel/host              host control WebSocket (challenge-signed)
//	GET /v1/tunnel/accept?sid=…      host data WebSocket, one per phone session
//	GET /v1/tunnel/connect?host=…    phone WebSocket (hpc1 credential + PoP, or enrollment)
//
// The relay authenticates who may reach a host, then splices binary messages
// 1:1 between the phone and the host's accept connection. Those messages are
// Noise transport messages: the relay never holds a key that opens them.
//
// v1 keeps live control connections in process (spec §15.4): run one instance,
// or route connect/accept for a host to the instance holding its control conn.

// tunnelLimits are the spec §10/§11 defaults. Tests shrink the timeouts.
type tunnelLimits struct {
	TextMax   int64 // text message cap (bytes)
	BinaryMax int64 // binary message cap (bytes)

	SessionsPerHost int     // default concurrent sessions per host (HostStatus.MaxSessions overrides)
	SessionsPerPID  int     // concurrent sessions per phone
	OpensPerMin     float64 // sessions opened per host per minute

	ConnectsPerMin   float64       // connect attempts per source IP per minute
	FailedAuthPerMin int           // failed auths per IP per minute before blocking
	FailedAuthBlock  time.Duration // block duration once over

	EnrollWindowsPerHost int
	EnrollAttempts       int
	EnrollWindowMax      time.Duration
	EnrollSpliceMax      time.Duration
	EnrollSpliceBytes    int64

	ControlRate  float64 // control messages per second per host…
	ControlBurst float64 // …with this burst
	PushRate     float64 // pushes per second per host (sustained)
	PushBurst    float64
	PushPerDay   int

	PingInterval time.Duration // relay WebSocket ping
	PeerSilence  time.Duration // close a peer silent this long
	AuthTimeout  time.Duration // hello/auth after challenge
	OpenTimeout  time.Duration // open → accept attached; sid lifetime
	WriteTimeout time.Duration // a single write may block this long
	StatusTTL    time.Duration // policy Status cache / re-check interval
	PendingGC    time.Duration // forget pending hosts unseen this long
	GCInterval   time.Duration
}

func defaultTunnelLimits() tunnelLimits {
	return tunnelLimits{
		TextMax:              8 << 10,
		BinaryMax:            65535,
		SessionsPerHost:      8,
		SessionsPerPID:       3,
		OpensPerMin:          60,
		ConnectsPerMin:       30,
		FailedAuthPerMin:     10,
		FailedAuthBlock:      5 * time.Minute,
		EnrollWindowsPerHost: 2,
		EnrollAttempts:       5,
		EnrollWindowMax:      15 * time.Minute,
		EnrollSpliceMax:      5 * time.Minute,
		EnrollSpliceBytes:    4 << 20,
		ControlRate:          20,
		ControlBurst:         20,
		PushRate:             1,
		PushBurst:            5,
		PushPerDay:           2000,
		PingInterval:         20 * time.Second,
		PeerSilence:          60 * time.Second,
		AuthTimeout:          10 * time.Second,
		OpenTimeout:          10 * time.Second,
		WriteTimeout:         60 * time.Second,
		StatusTTL:            60 * time.Second,
		PendingGC:            30 * 24 * time.Hour,
		GCInterval:           10 * time.Minute,
	}
}

type tunnelHub struct {
	store  TunnelStore
	policy TunnelPolicy
	push   PushSender
	lim    tunnelLimits
	now    func() time.Time

	// tap, when set (tests only), sees every spliced binary message. It exists
	// to prove the relay only ever handles ciphertext (T-relay-canary).
	tap func(fromPhone bool, msg []byte)

	upgrader websocket.Upgrader

	mu       sync.Mutex
	hosts    map[string]*hostCtl
	opens    map[string]*pendingOpen
	windows  map[string]map[string]*enrollWindow // host → eid → window
	sessions map[string]*hostSessions
	status   map[string]statusEntry
	pushDay  map[string]*dayCount
	// tenancy binds hosts to tenants and limits them per tenant (nil = off).
	tenancy       *tenancyConf
	tenantPushDay map[string]*dayCount // pushes per tenant per day
	// hostRegMu serializes a tenant host's count-then-register, so hosts
	// registering at once can't all pass max_hosts (one tunnel replica).
	hostRegMu sync.Mutex
	conns     map[*tconn]struct{}
	shutting  bool

	connectLim *ipRateLimiter // per IP
	openLim    *ipRateLimiter // per host
	ctlLim     *ipRateLimiter // per host
	pushLim    *ipRateLimiter // per host
	authFail   *failLimiter   // per IP: phone-side failures (connect, revoke)
	// hostFail counts host-side failures (/v1/tunnel/host, /accept) per IP,
	// apart from authFail: a phone retrying a stale pairing link from the
	// same home network (one IPv4 NAT address, or one IPv6 /64) must not
	// lock the box on that network out of its own control connection.
	hostFail *failLimiter

	// revokeSeen: accepted POST /v1/tunnel/revoke nonces (replay refusal).
	revokeSeen *replayCache

	stop     chan struct{}
	stopOnce sync.Once
}

type hostCtl struct {
	hostID string
	tenant string // the host's tenant (tenancy only)
	conn   *tconn
	gone   chan struct{}
	poke   chan struct{} // buffered 1: re-check status now (RefreshTunnelStatus)
}

type pendingOpen struct {
	sid     string
	hostID  string
	expires time.Time
	result  chan openResult // buffered 1
}

type openResult struct {
	conn     *tconn        // the host's accept connection (nil = not accepted)
	done     chan struct{} // closed when the splice ends
	rejected bool
}

type liveSession struct {
	hostID, pid string
	killOnce    sync.Once
	killed      chan struct{}
	killCode    tunnelCode
	mu          sync.Mutex
	phone, host *tconn
}

// kill ends the session from the relay side (e.g. revocation).
func (ls *liveSession) kill(tc tunnelCode, msg string) {
	ls.killOnce.Do(func() {
		ls.killCode = tc
		close(ls.killed)
		ls.mu.Lock()
		phone, host := ls.phone, ls.host
		ls.mu.Unlock()
		if phone != nil {
			phone.fail(tc, msg)
		}
		if host != nil {
			host.fail(tc, msg)
		}
	})
}

type hostSessions struct {
	total  int
	perPID map[string]int
	live   map[*liveSession]struct{}
}

type enrollWindow struct {
	tagHash  []byte
	exp      time.Time
	attempts int
}

type statusEntry struct {
	st  HostStatus
	err error
	at  time.Time
}

type dayCount struct {
	day int64
	n   int
}

func newTunnelHub(store Store, policy TunnelPolicy, push PushSender) *tunnelHub {
	ts, ok := store.(TunnelStore)
	if !ok {
		slog.Warn("store does not implement TunnelStore; tunnel host registrations and revocations are kept in memory only")
		ts = newMemTunnel()
	}
	lim := defaultTunnelLimits()
	// Push limits per host (LANGSTROTH_RELAY_TUNNEL_PUSH_*; 0 = no limit).
	lim.PushRate = envFloat("LANGSTROTH_RELAY_TUNNEL_PUSH_RATE", lim.PushRate)
	lim.PushBurst = envFloat("LANGSTROTH_RELAY_TUNNEL_PUSH_BURST", lim.PushBurst)
	lim.PushPerDay = int(envInt64("LANGSTROTH_RELAY_TUNNEL_PUSH_PER_DAY", int64(lim.PushPerDay)))
	h := &tunnelHub{
		store:    ts,
		policy:   policy,
		push:     push,
		lim:      lim,
		now:      time.Now,
		hosts:    map[string]*hostCtl{},
		opens:    map[string]*pendingOpen{},
		windows:  map[string]map[string]*enrollWindow{},
		sessions: map[string]*hostSessions{},
		status:   map[string]statusEntry{},
		pushDay:  map[string]*dayCount{},

		tenantPushDay: map[string]*dayCount{},
		conns:         map[*tconn]struct{}{},
		stop:          make(chan struct{}),

		revokeSeen: newReplayCache(100_000),
	}
	h.upgrader = websocket.Upgrader{
		Subprotocols: []string{tunnelSubprotocol},
		// Tunnel clients are native apps authenticating with signatures, not
		// browsers with ambient cookies; there's no origin to protect.
		CheckOrigin:     func(*http.Request) bool { return true },
		ReadBufferSize:  4096,
		WriteBufferSize: 64 << 10,
		WriteBufferPool: &sync.Pool{},
	}
	h.applyLimits()
	go h.gcLoop()
	return h
}

// applyLimits (re)builds the rate limiters from lim (tests call it after tuning).
func (h *tunnelHub) applyLimits() {
	h.connectLim = newIPRateLimiter(h.lim.ConnectsPerMin/60, h.lim.ConnectsPerMin)
	h.openLim = newIPRateLimiter(h.lim.OpensPerMin/60, h.lim.OpensPerMin)
	h.ctlLim = newIPRateLimiter(h.lim.ControlRate, h.lim.ControlBurst)
	h.pushLim = newIPRateLimiter(h.lim.PushRate, h.lim.PushBurst)
	h.authFail = newFailLimiter(h.lim.FailedAuthPerMin, time.Minute, h.lim.FailedAuthBlock)
	h.hostFail = newFailLimiter(h.lim.FailedAuthPerMin, time.Minute, h.lim.FailedAuthBlock)
}

func (h *tunnelHub) nowUnix() int64 { return h.now().Unix() }

// ── HTTP plumbing ────────────────────────────────────────────────────────────

func (h *tunnelHub) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/tunnel/info", h.handleInfo)
	mux.HandleFunc("GET /v1/tunnel/host", h.handleHost)
	mux.HandleFunc("GET /v1/tunnel/accept", h.handleAccept)
	mux.HandleFunc("GET /v1/tunnel/connect", h.handleConnect)
	mux.HandleFunc("POST /v1/tunnel/revoke", h.handleRevokeHTTP)
}

// tunnelBilling is the "billing" field of GET /v1/tunnel/info. Clients still
// read it, so it stays on the wire, fixed at "none".
const tunnelBilling = "none"

func (h *tunnelHub) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"versions": []int{tunnelVersion}, "push": h.push != nil, "billing": tunnelBilling})
}

// upgrade enforces the subprotocol (426 otherwise), upgrades, clears the
// http.Server read/write deadlines that would otherwise sever the hijacked
// conn after 30 s (spec §10), and starts keepalives.
func (h *tunnelHub) upgrade(w http.ResponseWriter, r *http.Request, readLimit int64) *tconn {
	offered := false
	for _, p := range websocket.Subprotocols(r) {
		if p == tunnelSubprotocol {
			offered = true
		}
	}
	if !offered {
		w.Header().Set("Sec-WebSocket-Protocol", tunnelSubprotocol)
		http.Error(w, "the hive-tunnel.1 WebSocket subprotocol is required", http.StatusUpgradeRequired)
		return nil
	}
	ws, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil // the upgrader already answered
	}
	_ = ws.NetConn().SetDeadline(time.Time{})
	ws.SetReadLimit(readLimit)
	t := newTconn(ws, h)
	ws.SetPongHandler(t.onPong)
	h.mu.Lock()
	shutting := h.shutting
	if !shutting {
		h.conns[t] = struct{}{}
	}
	h.mu.Unlock()
	if shutting {
		t.fail(tcShuttingDown, "relay is shutting down")
		return nil
	}
	go t.pinger(h.lim.PingInterval)
	return t
}

func (h *tunnelHub) untrack(t *tconn) {
	h.mu.Lock()
	delete(h.conns, t)
	h.mu.Unlock()
}

// shutdown closes every tunnel socket with shutting_down (4011).
func (h *tunnelHub) shutdown() {
	h.stopOnce.Do(func() { close(h.stop) })
	h.mu.Lock()
	h.shutting = true
	conns := make([]*tconn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	for _, c := range conns {
		c.fail(tcShuttingDown, "relay is restarting")
	}
}

// relayMsg is the union of relay-layer JSON messages we read.
type relayMsg struct {
	T string `json:"t"`
	V *int   `json:"v"`
	// hello
	HostID  string `json:"hostId"`
	HostPub string `json:"hostPub"`
	Sig     string `json:"sig"`
	Reg     string `json:"reg"`
	Agent   string `json:"agent"`
	// auth
	Cred string          `json:"cred"`
	Apns json.RawMessage `json:"apns"`
	// enroll (phone) / control requests
	Eid      string          `json:"eid"`
	Tag      string          `json:"tag"`
	ID       string          `json:"id"`
	TagHash  string          `json:"tagHash"`
	Exp      json.RawMessage `json:"exp"`
	PID      string          `json:"pid"`
	SID      string          `json:"sid"`
	Code     string          `json:"code"`
	CT       string          `json:"ct"`
	Prio     string          `json:"prio"`
	Collapse string          `json:"collapse"`
	// Diag: the host asks for the push service's answer in the ack
	// ("detail"). Only a diagnostic push sets it; plain acks are unchanged.
	Diag bool `json:"diag"`
}

// readRelayMsg reads one text message, skipping unknown `t` values. Binary
// messages are a protocol error before ready.
func (h *tunnelHub) readRelayMsg(c *tconn, deadline time.Duration, known ...string) (*relayMsg, *tunnelError, error) {
	until := time.Now().Add(deadline)
	for {
		mt, data, err := c.readBefore(until)
		if err != nil {
			if isTimeout(err) {
				return nil, terr(tcTimeout, "no message before the deadline"), nil
			}
			return nil, nil, err
		}
		if mt != websocket.TextMessage {
			return nil, terr(tcProtocol, "binary message before ready"), nil
		}
		var m relayMsg
		if json.Unmarshal(data, &m) != nil || m.T == "" {
			return nil, terr(tcProtocol, "malformed relay message"), nil
		}
		for _, k := range known {
			if m.T == k {
				return &m, nil, nil
			}
		}
		// Unknown t: ignore (spec §6).
	}
}

func randomB64u(n int) (string, []byte) {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64u(b), b
}

// ── Host status (policy, cached ≤ StatusTTL) ─────────────────────────────────

func (h *tunnelHub) hostStatus(ctx context.Context, hostID string, fresh bool) (HostStatus, error) {
	now := h.now()
	h.mu.Lock()
	e, ok := h.status[hostID]
	h.mu.Unlock()
	if ok && !fresh && now.Sub(e.at) < h.lim.StatusTTL {
		return e.st, e.err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := h.policy.Status(cctx, hostID)
	h.mu.Lock()
	h.status[hostID] = statusEntry{st: st, err: err, at: now}
	h.mu.Unlock()
	return st, err
}

func (h *tunnelHub) maxSessions(st HostStatus) int {
	if st.MaxSessions > 0 {
		return st.MaxSessions
	}
	return h.lim.SessionsPerHost
}

func statusString(st HostStatus) string {
	if st.Active {
		return "active"
	}
	return "pending"
}

// ── Host control connection (§6.2) ───────────────────────────────────────────

func (h *tunnelHub) handleHost(w http.ResponseWriter, r *http.Request) {
	ip := clientKey(r)
	c := h.upgrade(w, r, h.lim.TextMax)
	if c == nil {
		return
	}
	if h.hostFail.blocked(ip, h.now()) || !h.connectLim.allow(ip) {
		c.fail(tcRateLimited, "too many attempts")
		return
	}
	nonceStr, nonce := randomB64u(32)
	if c.writeJSON(map[string]any{"t": "challenge", "v": tunnelVersion, "nonce": nonceStr}) != nil {
		c.abort()
		return
	}
	m, te, err := h.readRelayMsg(c, h.lim.AuthTimeout, "hello")
	if err != nil {
		c.abort()
		return
	}
	if te != nil {
		c.fail(te.tc, te.msg)
		return
	}
	ctx := r.Context()
	ctl, te := h.admitHost(ctx, m, nonce)
	if te != nil {
		if te.tc == tcUnauthorized {
			h.hostFail.note(ip, h.now())
		}
		c.fail(te.tc, te.msg)
		return
	}
	ctl.conn = c
	st, _ := h.hostStatus(ctx, ctl.hostID, false)

	h.mu.Lock()
	old := h.hosts[ctl.hostID]
	h.hosts[ctl.hostID] = ctl
	h.mu.Unlock()
	if old != nil {
		old.conn.fail(tcSuperseded, "a newer control connection for this host took over")
	}
	slog.Info("tunnel host connected", "host", ctl.hostID, "status", statusString(st), "agent", truncate(m.Agent, 64))

	if c.writeJSON(map[string]any{"t": "welcome", "status": statusString(st), "maxSessions": h.maxSessions(st), "push": h.push != nil}) != nil {
		c.abort()
	}
	stopWatch := make(chan struct{})
	go h.watchStatus(ctl, st, stopWatch)
	h.controlLoop(ctl)
	close(stopWatch)

	h.mu.Lock()
	if h.hosts[ctl.hostID] == ctl {
		delete(h.hosts, ctl.hostID)
	}
	h.mu.Unlock()
	close(ctl.gone)
	c.abort()
	slog.Info("tunnel host disconnected", "host", ctl.hostID)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// admitHost verifies hello: version, host_id = H(hostPub), the challenge
// signature, then registration (first sight) and status.
func (h *tunnelHub) admitHost(ctx context.Context, m *relayMsg, nonce []byte) (*hostCtl, *tunnelError) {
	if m.V == nil || *m.V != tunnelVersion {
		return nil, terr(tcUnsupportedVersion, "this relay speaks hive-tunnel/1")
	}
	pubB, ok := b64uFixed(m.HostPub, ed25519.PublicKeySize)
	if !ok {
		return nil, terr(tcUnauthorized, "malformed hostPub")
	}
	pub := ed25519.PublicKey(pubB)
	if !validTunnelID(m.HostID) || TunnelHostID(pub) != m.HostID {
		return nil, terr(tcUnauthorized, "hostId is not the hash of hostPub")
	}
	sig, ok := b64uFixed(m.Sig, ed25519.SignatureSize)
	if !ok || !ed25519.Verify(pub, tunnelCtx("host-auth", []byte(m.HostID), nonce), sig) {
		return nil, terr(tcUnauthorized, "bad challenge signature")
	}
	rec, err := h.store.TunnelHost(ctx, m.HostID)
	if err != nil {
		return nil, terr(tcInternal, "store unavailable")
	}
	now := h.nowUnix()
	if rec == nil {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := h.policy.Register(rctx, m.HostID, pub, m.Reg)
		cancel()
		if err != nil {
			return nil, terr(tcUnauthorized, "registration refused")
		}
		rec = &TunnelHostRecord{HostID: m.HostID, Pub: pubB, CreatedAt: now}
		if h.tenancy != nil {
			// The host joins the tenant its registration token proves, once.
			_, t, ok := h.tenancy.verify(m.Reg, now)
			if !ok {
				return nil, terr(tcUnauthorized, "registration refused")
			}
			if t.limits.MaxHosts > 0 {
				// Held until the record is stored (the deferred unlock).
				h.hostRegMu.Lock()
				defer h.hostRegMu.Unlock()
				hc, ok := h.store.(tenantHostCounter)
				if !ok {
					return nil, terr(tcInternal, "store unavailable")
				}
				n, err := hc.TunnelHostsOfTenant(ctx, t.id)
				if err != nil {
					return nil, terr(tcInternal, "store unavailable")
				}
				if n >= t.limits.MaxHosts {
					countLimit(limTenantHosts, t.id)
					return nil, terr(tcUnauthorized, "registration refused: the tenant has its maximum number of hosts")
				}
			}
			rec.Tenant = t.id
		}
	} else if !bytes.Equal(rec.Pub, pubB) {
		return nil, terr(tcUnauthorized, "hostPub does not match the registered key")
	}
	st, err := h.hostStatus(ctx, m.HostID, true)
	if err != nil {
		return nil, terr(tcUnauthorized, "host is not admitted by this relay")
	}
	rec.LastSeen, rec.Active = now, st.Active
	if err := h.store.UpsertTunnelHost(ctx, *rec); err != nil {
		return nil, terr(tcInternal, "store unavailable")
	}
	return &hostCtl{hostID: m.HostID, tenant: rec.Tenant, gone: make(chan struct{}), poke: make(chan struct{}, 1)}, nil
}

// watchStatus re-checks admission status every StatusTTL (or at once when poked by
// refreshStatus), tells the host when it changes and refreshes last_seen (for
// pending-host GC).
func (h *tunnelHub) watchStatus(ctl *hostCtl, last HostStatus, stop <-chan struct{}) {
	tick := time.NewTicker(h.lim.StatusTTL)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		case <-ctl.poke:
		}
		st, err := h.hostStatus(context.Background(), ctl.hostID, true)
		if err != nil {
			ctl.conn.fail(tcUnauthorized, "host is no longer admitted by this relay")
			return
		}
		if st.Active != last.Active {
			_ = ctl.conn.writeJSON(map[string]any{"t": "status", "status": statusString(st)})
		}
		last = st
		if rec, err := h.store.TunnelHost(context.Background(), ctl.hostID); err == nil && rec != nil {
			rec.LastSeen, rec.Active = h.nowUnix(), st.Active
			_ = h.store.UpsertTunnelHost(context.Background(), *rec)
		}
	}
}

// refreshStatus drops the cached status for hostID and pokes its control
// connection, if any, to re-check now.
func (h *tunnelHub) refreshStatus(hostID string) {
	h.mu.Lock()
	delete(h.status, hostID)
	ctl := h.hosts[hostID]
	h.mu.Unlock()
	if ctl != nil {
		select {
		case ctl.poke <- struct{}{}:
		default: // a re-check is already queued
		}
	}
}

func (h *tunnelHub) controlLoop(ctl *hostCtl) {
	c := ctl.conn
	for {
		mt, data, err := c.read(h.lim.PeerSilence)
		if err != nil {
			if isTimeout(err) {
				c.fail(tcTimeout, "control connection silent")
			}
			return
		}
		if mt != websocket.TextMessage {
			c.fail(tcProtocol, "binary message on the control connection")
			return
		}
		var m relayMsg
		if json.Unmarshal(data, &m) != nil || m.T == "" {
			c.fail(tcProtocol, "malformed relay message")
			return
		}
		if !h.ctlLim.allow(ctl.hostID) {
			if m.ID != "" {
				h.ack(c, m.ID, "rate_limited")
			}
			continue
		}
		switch m.T {
		case "reject":
			h.deliverReject(ctl.hostID, m.SID)
		case "enroll", "enrollClose", "revoke", "push", "deregister":
			if m.ID == "" || len(m.ID) > 64 {
				c.fail(tcProtocol, "request id missing or longer than 64")
				return
			}
			if h.controlRequest(ctl, &m) {
				return
			}
		default:
			// Unknown t: ignore.
		}
	}
}

func (h *tunnelHub) ack(c *tconn, id, code string) {
	if code == "" {
		_ = c.writeJSON(map[string]any{"t": "ack", "id": id, "ok": true})
		return
	}
	_ = c.writeJSON(map[string]any{"t": "ack", "id": id, "ok": false, "code": code})
}

// ackDetail is ack plus "detail", for a host that asked (diag).
func (h *tunnelHub) ackDetail(c *tconn, id, code, detail string) {
	msg := map[string]any{"t": "ack", "id": id, "ok": code == "", "detail": truncate(detail, 300)}
	if code != "" {
		msg["code"] = code
	}
	_ = c.writeJSON(msg)
}

// parseUnix reads an integer Unix time.
func parseUnix(raw json.RawMessage) (int64, bool) {
	var n int64
	if len(raw) == 0 || json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	return n, true
}

// controlRequest handles one id-bearing host request; true = connection ended.
func (h *tunnelHub) controlRequest(ctl *hostCtl, m *relayMsg) bool {
	c := ctl.conn
	ctx := context.Background()
	now := h.now()
	switch m.T {
	case "enroll":
		tagHash, ok1 := b64uFixed(m.TagHash, sha256.Size)
		exp, ok2 := parseUnix(m.Exp)
		if !validTunnelID(m.Eid) || !ok1 || !ok2 {
			h.ack(c, m.ID, "protocol")
			return false
		}
		maxExp := now.Add(h.lim.EnrollWindowMax)
		if exp > maxExp.Unix()+tunnelSkewSecs {
			h.ack(c, m.ID, "window_too_long")
			return false
		}
		until := time.Unix(exp, 0)
		if until.After(maxExp) {
			until = maxExp
		}
		if !until.After(now) {
			h.ack(c, m.ID, "expired")
			return false
		}
		h.mu.Lock()
		ws := h.windows[ctl.hostID]
		if ws == nil {
			ws = map[string]*enrollWindow{}
			h.windows[ctl.hostID] = ws
		}
		for eid, w := range ws {
			if !w.exp.After(now) {
				delete(ws, eid)
			}
		}
		if cur, ok := ws[m.Eid]; ok {
			cur.tagHash, cur.exp = tagHash, until // idempotent re-send keeps the attempt count
		} else if len(ws) >= h.lim.EnrollWindowsPerHost {
			h.mu.Unlock()
			h.ack(c, m.ID, "rate_limited")
			return false
		} else {
			ws[m.Eid] = &enrollWindow{tagHash: tagHash, exp: until}
		}
		h.mu.Unlock()
		h.ack(c, m.ID, "")
	case "enrollClose":
		h.mu.Lock()
		if ws := h.windows[ctl.hostID]; ws != nil {
			delete(ws, m.Eid)
		}
		h.mu.Unlock()
		h.ack(c, m.ID, "")
	case "revoke":
		exp, ok := parseUnix(m.Exp)
		if !validTunnelID(m.PID) || !ok {
			h.ack(c, m.ID, "protocol")
			return false
		}
		if _, _, _, err := h.revokePhone(ctx, ctl.hostID, m.PID, exp); err != nil {
			h.ack(c, m.ID, "internal")
			return false
		}
		h.ack(c, m.ID, "")
	case "push":
		go h.handlePush(ctl, *m)
	case "deregister":
		if err := h.store.DeleteTunnelHost(ctx, ctl.hostID); err != nil {
			h.ack(c, m.ID, "internal")
			return false
		}
		h.mu.Lock()
		delete(h.windows, ctl.hostID)
		delete(h.status, ctl.hostID)
		h.mu.Unlock()
		h.killSessions(ctl.hostID, "", tcHostUnknown, "host deregistered")
		h.ack(c, m.ID, "")
		c.closeWith(websocket.CloseNormalClosure, "deregistered")
		return true
	}
	return false
}

func (h *tunnelHub) handlePush(ctl *hostCtl, m relayMsg) {
	c := ctl.conn
	// Every push decision is logged at info (never the token or the
	// ciphertext), so "did the box ask, and what did APNs say" is answerable
	// from the relay's logs alone.
	result := func(code, detail string, o *PushOutcome) {
		attrs := []any{"host", ctl.hostID, "pid", m.PID, "result", resultName(code)}
		if o != nil {
			attrs = append(attrs, "service", o.Service, "env", o.Env, "topic", o.Topic, "status", o.Status, "reason", o.Reason)
			if o.ID != "" {
				attrs = append(attrs, "apns_id", o.ID)
			}
		} else if detail != "" {
			attrs = append(attrs, "reason", detail)
		}
		if code == "" {
			slog.Info("tunnel push", attrs...)
		} else {
			slog.Warn("tunnel push", attrs...)
		}
		if !m.Diag {
			h.ack(c, m.ID, code)
			return
		}
		if o != nil {
			detail = o.String()
		}
		h.ackDetail(c, m.ID, code, detail)
	}
	if h.push == nil {
		result("push_unavailable", "this relay has no push sender configured", nil)
		return
	}
	ct, err := b64uDecode(m.CT)
	if !validTunnelID(m.PID) || err != nil || len(ct) == 0 || len(ct) > 2048 || len(m.Collapse) > 64 ||
		(m.Prio != "" && m.Prio != "high" && m.Prio != "normal") {
		result("protocol", "malformed push", nil)
		return
	}
	prio := m.Prio
	if prio == "" {
		prio = "normal"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if revoked, err := h.store.TunnelPhoneRevoked(ctx, ctl.hostID, m.PID, h.nowUnix()); err != nil || revoked {
		result("revoked", "the phone is revoked", nil)
		return
	}
	if !h.pushLim.allow(ctl.hostID) || !h.pushDayAllow(ctl.hostID) {
		countLimit(limPush, ctl.tenant)
		result("rate_limited", "the host is over the relay's push rate", nil)
		return
	}
	if !h.tenantPushAllow(ctl.tenant) {
		countLimit(limPush, ctl.tenant)
		result("rate_limited", "the host's tenant is over the relay's push rate", nil)
		return
	}
	tok, err := h.store.TunnelPushToken(ctx, ctl.hostID, m.PID)
	if err != nil {
		result("internal", "store unavailable", nil)
		return
	}
	if tok == nil {
		result("no_push_token", "no push token: the phone hasn't registered one with this relay (open the app with notifications on)", nil)
		return
	}
	var outcome *PushOutcome
	if ds, ok := h.push.(DetailedPushSender); ok {
		o, e := ds.SendDetailed(ctx, ctl.hostID, m.PID, *tok, ct, prio, m.Collapse)
		outcome, err = &o, e
	} else {
		err = h.push.Send(ctx, ctl.hostID, m.PID, *tok, ct, prio, m.Collapse)
	}
	if err != nil {
		if errors.Is(err, ErrPushTokenGone) {
			// The push service says the token is dead: forget it, so later
			// pushes ack no_push_token until the phone re-registers.
			_ = h.store.SetTunnelPushToken(ctx, ctl.hostID, m.PID, nil, h.nowUnix())
		}
		detail := ""
		if outcome == nil {
			detail = "the push service refused it"
		}
		result("push_failed", detail, outcome)
		return
	}
	result("", "", outcome)
}

// resultName is the log value for an ack code ("" = sent).
func resultName(code string) string {
	if code == "" {
		return "sent"
	}
	return code
}

func (h *tunnelHub) pushDayAllow(hostID string) bool {
	if h.lim.PushPerDay <= 0 {
		return true
	}
	day := h.nowUnix() / 86400
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.pushDay[hostID]
	if d == nil || d.day != day {
		d = &dayCount{day: day}
		h.pushDay[hostID] = d
	}
	if d.n >= h.lim.PushPerDay {
		return false
	}
	d.n++
	return true
}

// tenantPushAllow counts one push against the tenant's push_per_day.
func (h *tunnelHub) tenantPushAllow(tenant string) bool {
	if h.tenancy == nil || tenant == "" {
		return true
	}
	t := h.tenancy.tenants[tenant]
	if t == nil || t.limits.PushPerDay <= 0 {
		return true
	}
	day := h.nowUnix() / 86400
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.tenantPushDay[tenant]
	if d == nil || d.day != day {
		d = &dayCount{day: day}
		h.tenantPushDay[tenant] = d
	}
	if d.n >= t.limits.PushPerDay {
		return false
	}
	d.n++
	return true
}

func (h *tunnelHub) deliverReject(hostID, sid string) {
	h.mu.Lock()
	po := h.opens[sid]
	if po != nil && po.hostID == hostID {
		delete(h.opens, sid)
	} else {
		po = nil
	}
	h.mu.Unlock()
	if po != nil {
		po.result <- openResult{rejected: true}
	}
}

// killSessions ends live and pending sessions of a host ("" pid = all) and
// returns how many it ended.
func (h *tunnelHub) killSessions(hostID, pid string, tc tunnelCode, msg string) int {
	h.mu.Lock()
	var victims []*liveSession
	if hs := h.sessions[hostID]; hs != nil {
		for ls := range hs.live {
			if pid == "" || ls.pid == pid {
				victims = append(victims, ls)
			}
		}
	}
	h.mu.Unlock()
	for _, ls := range victims {
		ls.kill(tc, msg)
	}
	return len(victims)
}

// ── Host accept connection (§6.3) ────────────────────────────────────────────

func (h *tunnelHub) handleAccept(w http.ResponseWriter, r *http.Request) {
	ip := clientKey(r)
	c := h.upgrade(w, r, h.lim.BinaryMax)
	if c == nil {
		return
	}
	if h.hostFail.blocked(ip, h.now()) {
		c.fail(tcRateLimited, "too many failed attempts")
		return
	}
	sid := r.URL.Query().Get("sid")
	h.mu.Lock()
	po := h.opens[sid]
	if po != nil {
		delete(h.opens, sid) // single use
	}
	h.mu.Unlock()
	if po == nil || !h.now().Before(po.expires) {
		h.hostFail.note(ip, h.now())
		c.fail(tcUnauthorized, "unknown, used or expired sid")
		return
	}
	done := make(chan struct{})
	po.result <- openResult{conn: c, done: done}
	<-done
}

// ── Phone connect (§6.4) ─────────────────────────────────────────────────────

func (h *tunnelHub) handleConnect(w http.ResponseWriter, r *http.Request) {
	ip := clientKey(r)
	c := h.upgrade(w, r, h.lim.TextMax)
	if c == nil {
		return
	}
	if h.authFail.blocked(ip, h.now()) || !h.connectLim.allow(ip) {
		c.fail(tcRateLimited, "too many attempts")
		return
	}
	hostID := r.URL.Query().Get("host")
	if !validTunnelID(hostID) {
		c.fail(tcHostUnknown, "host is not a host_id")
		return
	}
	nonceStr, nonce := randomB64u(32)
	if c.writeJSON(map[string]any{"t": "challenge", "v": tunnelVersion, "nonce": nonceStr}) != nil {
		c.abort()
		return
	}
	m, te, err := h.readRelayMsg(c, h.lim.AuthTimeout, "auth", "enroll")
	if err != nil {
		c.abort()
		return
	}
	if te == nil {
		if m.T == "auth" {
			te = h.admitSession(r.Context(), c, hostID, nonce, m)
		} else {
			te = h.admitEnroll(r.Context(), c, hostID, m)
		}
	}
	if te != nil {
		if te.tc == tcUnauthorized || te.tc == tcHostUnknown {
			h.authFail.note(ip, h.now())
		}
		c.fail(te.tc, te.msg)
	}
}

func (h *tunnelHub) hostKey(ctx context.Context) func(string) (ed25519.PublicKey, bool, error) {
	return func(hostID string) (ed25519.PublicKey, bool, error) {
		rec, err := h.store.TunnelHost(ctx, hostID)
		if err != nil || rec == nil || len(rec.Pub) != ed25519.PublicKeySize {
			return nil, false, err
		}
		return ed25519.PublicKey(rec.Pub), true, nil
	}
}

// parseApns validates the optional apns member: absent → (nil, false), null →
// (nil, true) = clear, object → token.
func parseApns(raw json.RawMessage) (tok *PushToken, set bool, ok bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false, true
	}
	if string(raw) == "null" {
		return nil, true, true
	}
	var t PushToken
	if json.Unmarshal(raw, &t) != nil || t.Token == "" || len(t.Token) > 512 ||
		(t.Env != "production" && t.Env != "development") || (t.Topic != "" && !validTopic(t.Topic)) {
		return nil, false, false
	}
	if _, err := hex.DecodeString(t.Token); err != nil {
		return nil, false, false
	}
	t.Token = strings.ToLower(t.Token)
	return &t, true, true
}

func (h *tunnelHub) admitSession(ctx context.Context, c *tconn, hostID string, nonce []byte, m *relayMsg) *tunnelError {
	now := h.nowUnix()
	// 1. Credential (§5 steps 1–5) …
	cred, te := verifyPhoneCredential(m.Cred, hostID, h.hostKey(ctx), now)
	if te != nil {
		return te
	}
	// … step 6, revocation.
	revoked, err := h.store.TunnelPhoneRevoked(ctx, hostID, cred.PID, now)
	if err != nil {
		return terr(tcInternal, "store unavailable")
	}
	if revoked {
		return terr(tcRevoked, "this phone was revoked by its host")
	}
	// 2. Proof of possession over this connection's challenge.
	sig, ok := b64uFixed(m.Sig, ed25519.SignatureSize)
	if !ok || !ed25519.Verify(cred.PhoneKey, tunnelCtx("phone-auth", []byte(hostID), nonce), sig) {
		return terr(tcUnauthorized, "bad proof-of-possession signature")
	}
	apns, setApns, ok := parseApns(m.Apns)
	if !ok {
		return terr(tcProtocol, "malformed apns")
	}
	// 3. Admission status.
	st, err := h.hostStatus(ctx, hostID, false)
	if err != nil || !st.Active {
		return terr(tcNotEntitled, "this host is not active on this relay")
	}
	// 4.–8.
	return h.openAndSplice(c, hostID, cred.PID, "session", "", h.maxSessions(st), func() *tunnelError {
		if setApns {
			_ = h.store.SetTunnelPushToken(ctx, hostID, cred.PID, apns, h.nowUnix())
		}
		// A revocation may have landed since step 6. Checked after the
		// session is registered and its push token stored: a revocation
		// before this check is seen here (and its token cleared), one after
		// it kills the registered session and deletes the stored token.
		revoked, err := h.store.TunnelPhoneRevoked(ctx, hostID, cred.PID, h.nowUnix())
		if err != nil || revoked {
			if setApns {
				_ = h.store.SetTunnelPushToken(ctx, hostID, cred.PID, nil, h.nowUnix())
			}
			if err != nil {
				return terr(tcInternal, "store unavailable")
			}
			return terr(tcRevoked, "this phone was revoked by its host")
		}
		return nil
	})
}

func (h *tunnelHub) admitEnroll(ctx context.Context, c *tconn, hostID string, m *relayMsg) *tunnelError {
	tag, ok := b64uFixed(m.Tag, 32)
	if !ok || !validTunnelID(m.Eid) {
		return terr(tcUnauthorized, "malformed enrollment")
	}
	now := h.now()
	sum := sha256.Sum256(tag)
	h.mu.Lock()
	win := h.windows[hostID][m.Eid]
	if win == nil || !win.exp.After(now) {
		h.mu.Unlock()
		return terr(tcUnauthorized, "no open enrollment window")
	}
	win.attempts++
	if win.attempts > h.lim.EnrollAttempts {
		delete(h.windows[hostID], m.Eid)
		h.mu.Unlock()
		return terr(tcUnauthorized, "enrollment window exhausted")
	}
	match := subtle.ConstantTimeCompare(sum[:], win.tagHash) == 1
	h.mu.Unlock()
	if !match {
		return terr(tcUnauthorized, "wrong enrollment tag")
	}
	// A pending host may enroll; an unadmitted one (policy error) may not.
	st, err := h.hostStatus(ctx, hostID, false)
	if err != nil {
		return terr(tcNotEntitled, "this host is not admitted by this relay")
	}
	return h.openAndSplice(c, hostID, "", "enroll", m.Eid, h.maxSessions(st), nil)
}

// openAndSplice runs §6.4.1 steps 4, 5, 7 and 8 (beforeOpen is step 6).
//
// beforeOpen runs once the session is registered (so a revocation from here
// on closes it); a non-nil error refuses the session.
func (h *tunnelHub) openAndSplice(c *tconn, hostID, pid, mode, eid string, maxSessions int, beforeOpen func() *tunnelError) *tunnelError {
	h.mu.Lock()
	ctl := h.hosts[hostID]
	if ctl == nil {
		h.mu.Unlock()
		return terr(tcHostOffline, "the host is not connected to this relay")
	}
	hs := h.sessions[hostID]
	if hs == nil {
		hs = &hostSessions{perPID: map[string]int{}, live: map[*liveSession]struct{}{}}
		h.sessions[hostID] = hs
	}
	if hs.total >= maxSessions || (pid != "" && hs.perPID[pid] >= h.lim.SessionsPerPID) {
		h.mu.Unlock()
		return terr(tcRateLimited, "too many concurrent sessions")
	}
	if !h.openLim.allow(hostID) {
		h.mu.Unlock()
		return terr(tcRateLimited, "too many sessions opened for this host")
	}
	sid, _ := randomB64u(16)
	po := &pendingOpen{sid: sid, hostID: hostID, expires: h.now().Add(h.lim.OpenTimeout), result: make(chan openResult, 1)}
	h.opens[sid] = po
	ls := &liveSession{hostID: hostID, pid: pid, killed: make(chan struct{}), phone: c}
	hs.total++
	hs.perPID[pid]++
	hs.live[ls] = struct{}{}
	h.mu.Unlock()
	defer h.releaseSession(ls)

	if beforeOpen != nil {
		if te := beforeOpen(); te != nil {
			h.cancelOpen(po, te.tc)
			return te
		}
	}
	open := map[string]any{"t": "open", "sid": sid, "mode": mode}
	if mode == "enroll" {
		open["eid"] = eid
	} else {
		open["pid"] = pid
	}
	if ctl.conn.writeJSON(open) != nil {
		h.cancelOpen(po, tcHostOffline)
		return terr(tcHostOffline, "the host is not connected to this relay")
	}

	timer := time.NewTimer(h.lim.OpenTimeout)
	defer timer.Stop()
	var res openResult
	select {
	case res = <-po.result:
	case <-timer.C:
		if r, ok := h.cancelOpen(po, tcTimeout); !ok {
			return terr(tcTimeout, "the host did not attach in time")
		} else {
			res = r // attached at the last moment
		}
	case <-ctl.gone:
		if r, ok := h.cancelOpen(po, tcHostOffline); !ok {
			return terr(tcHostOffline, "the host disconnected")
		} else {
			res = r
		}
	case <-ls.killed:
		h.cancelOpen(po, ls.killCode)
		return nil // kill already closed the phone
	}
	if res.rejected {
		return terr(tcHostRejected, "the host declined the session")
	}
	defer close(res.done)
	host := res.conn

	ls.mu.Lock()
	ls.host = host
	ls.mu.Unlock()
	select {
	case <-ls.killed: // revoked while attaching
		host.fail(ls.killCode, "session ended")
		return nil
	default:
	}
	if c.writeJSON(map[string]any{"t": "ready", "sid": sid}) != nil {
		c.abort()
		host.closeWith(websocket.CloseNormalClosure, "")
		return nil
	}
	c.ws.SetReadLimit(h.lim.BinaryMax)
	h.splice(c, host, mode == "enroll")
	return nil
}

// cancelOpen withdraws a pending open. ok=false: withdrawn. ok=true: the host
// attached concurrently and res holds its result (the caller proceeds).
func (h *tunnelHub) cancelOpen(po *pendingOpen, tc tunnelCode) (openResult, bool) {
	h.mu.Lock()
	_, pending := h.opens[po.sid]
	if pending {
		delete(h.opens, po.sid)
	}
	h.mu.Unlock()
	if pending {
		return openResult{}, false
	}
	res := <-po.result // the accept/reject that took it is already queued
	if res.conn != nil && tc != tcTimeout && tc != tcHostOffline {
		res.conn.fail(tc, "session ended")
		close(res.done)
		return openResult{}, false
	}
	return res, true
}

func (h *tunnelHub) releaseSession(ls *liveSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hs := h.sessions[ls.hostID]
	if hs == nil {
		return
	}
	if _, ok := hs.live[ls]; !ok {
		return
	}
	delete(hs.live, ls)
	hs.total--
	if hs.perPID[ls.pid]--; hs.perPID[ls.pid] <= 0 {
		delete(hs.perPID, ls.pid)
	}
	if hs.total <= 0 {
		delete(h.sessions, ls.hostID)
	}
}

// ── Splice (§6.5) ────────────────────────────────────────────────────────────

// splice copies binary messages 1:1 in both directions. Each direction reads
// the next message only after the previous one was written, so at most one
// message is in flight per direction and TCP backpressure reaches the sender.
func (h *tunnelHub) splice(phone, host *tconn, enroll bool) {
	var budget *atomic.Int64
	if enroll {
		budget = &atomic.Int64{}
		budget.Store(h.lim.EnrollSpliceBytes)
		t := time.AfterFunc(h.lim.EnrollSpliceMax, func() {
			phone.fail(tcTimeout, "enrollment session time cap reached; reconnect in session mode")
			host.fail(tcTimeout, "enrollment session time cap reached")
		})
		defer t.Stop()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); h.pump(phone, host, true, budget) }()
	go func() { defer wg.Done(); h.pump(host, phone, false, budget) }()
	wg.Wait()
}

func (h *tunnelHub) pump(src, dst *tconn, fromPhone bool, budget *atomic.Int64) {
	for {
		mt, data, err := src.read(h.lim.PeerSilence)
		if err != nil {
			if src.isClosed() {
				// We closed src ourselves (kill, cap, or propagation from dst).
				return
			}
			if isTimeout(err) {
				src.fail(tcTimeout, "peer silent")
				dst.fail(tcTimeout, "peer silent")
				return
			}
			code, reason := passCloseCode(err)
			src.abort()
			dst.closeWith(code, reason)
			return
		}
		if mt != websocket.BinaryMessage {
			src.fail(tcProtocol, "text message after ready")
			dst.closeWith(tcProtocol.Close, tcProtocol.Code)
			return
		}
		if budget != nil && budget.Add(-int64(len(data))) < 0 {
			src.fail(tcRateLimited, "enrollment session byte cap reached; reconnect in session mode")
			dst.fail(tcRateLimited, "enrollment session byte cap reached")
			return
		}
		if h.tap != nil {
			h.tap(fromPhone, data)
		}
		if err := dst.writeMsg(websocket.BinaryMessage, data); err != nil {
			if !dst.isClosed() {
				dst.fail(tcTimeout, "peer stopped reading")
				src.fail(tcTimeout, "peer stopped reading")
			}
			return
		}
	}
}

// ── Housekeeping ─────────────────────────────────────────────────────────────

func (h *tunnelHub) gcLoop() {
	tick := time.NewTicker(h.lim.GCInterval)
	defer tick.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-tick.C:
			h.gc()
		}
	}
}

func (h *tunnelHub) gc() {
	now := h.now()
	h.revokeSeen.prune(now.Unix())
	if n, err := h.store.PruneTunnel(context.Background(), now.Unix(), h.lim.PendingGC); err != nil {
		slog.Warn("tunnel prune failed", "error", err)
	} else if n > 0 {
		slog.Info("tunnel pruned", "rows", n)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for host, ws := range h.windows {
		for eid, w := range ws {
			if !w.exp.After(now) {
				delete(ws, eid)
			}
		}
		if len(ws) == 0 {
			delete(h.windows, host)
		}
	}
	for host, e := range h.status {
		if now.Sub(e.at) > h.lim.StatusTTL {
			delete(h.status, host)
		}
	}
	for host, d := range h.pushDay {
		if d.day != now.Unix()/86400 {
			delete(h.pushDay, host)
		}
	}
}

// failLimiter blocks a key for `block` once it records more than max failures
// inside `window` (spec §11: failed auth 10/min, then 4029 for 5 min).
type failLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	block  time.Duration
	m      map[string]*failEntry
	lastGC time.Time
}

type failEntry struct {
	n            int
	windowStart  time.Time
	blockedUntil time.Time
}

func newFailLimiter(max int, window, block time.Duration) *failLimiter {
	return &failLimiter{max: max, window: window, block: block, m: map[string]*failEntry{}}
}

func (l *failLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	return e != nil && now.Before(e.blockedUntil)
}

// wait is how long key stays blocked (for Retry-After).
func (l *failLimiter) wait(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[key]; e != nil {
		return e.blockedUntil.Sub(now)
	}
	return 0
}

func (l *failLimiter) note(key string, now time.Time) {
	if l.max <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastGC) > l.window+l.block {
		for k, e := range l.m {
			if now.Sub(e.windowStart) > l.window && now.After(e.blockedUntil) {
				delete(l.m, k)
			}
		}
		l.lastGC = now
	}
	e := l.m[key]
	if e == nil || now.Sub(e.windowStart) > l.window {
		e = &failEntry{windowStart: now}
		l.m[key] = e
	}
	e.n++
	if e.n >= l.max {
		e.blockedUntil = now.Add(l.block)
	}
}
