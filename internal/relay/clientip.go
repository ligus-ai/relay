package relay

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
)

// Client address resolution for rate limits, abuse blocks and request logs.
//
// By default the relay uses the TCP peer address (RemoteAddr) and ignores
// every forwarding header: a header is only as trustworthy as the hop that
// set it, and a client can send any header it likes.
//
//	LANGSTROTH_RELAY_TRUSTED_PROXIES   comma-separated CIDRs or IPs of the reverse
//	                              proxies in front of the relay (an ingress
//	                              controller's pod CIDR, a load balancer).
//	                              Empty (default) = trust no forwarding header.
//	LANGSTROTH_RELAY_CLIENT_IP_HEADER  the header those proxies set. Default
//	                              X-Forwarded-For (walked right to left,
//	                              skipping trusted hops); any other name
//	                              (X-Real-IP, CF-Connecting-IP, ...) is read
//	                              as a single address.
//
// Only when the peer is inside LANGSTROTH_RELAY_TRUSTED_PROXIES is the header read.
//
// Fly.io: the Fly edge overwrites Fly-Client-IP on every request, and the
// platform sets FLY_APP_NAME in every machine. When FLY_APP_NAME is set and
// LANGSTROTH_RELAY_TRUSTED_PROXIES is not, the relay keeps its earlier behavior and
// takes Fly-Client-IP as the client address. Anywhere else Fly-Client-IP is an
// ordinary client-supplied header and is ignored.
type clientIPPolicy struct {
	trusted []netip.Prefix
	header  string // canonical header name read from trusted peers
	fly     bool   // trust Fly-Client-IP from any peer (running on Fly)
}

// activeClientIP is the policy clientIP uses. New loads it from the
// environment; nil means peer address only.
var activeClientIP atomic.Pointer[clientIPPolicy]

func clientIPPolicyFromEnv() *clientIPPolicy {
	p := &clientIPPolicy{header: "X-Forwarded-For"}
	if h := strings.TrimSpace(getenv("LANGSTROTH_RELAY_CLIENT_IP_HEADER")); h != "" {
		p.header = http.CanonicalHeaderKey(h)
	}
	for _, part := range strings.Split(getenv("LANGSTROTH_RELAY_TRUSTED_PROXIES"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(part)
		if err != nil {
			addr, aerr := netip.ParseAddr(part)
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "langstroth-relay: LANGSTROTH_RELAY_TRUSTED_PROXIES: %q is not a CIDR or IP; ignoring it\n", part)
				continue
			}
			addr = addr.Unmap()
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		p.trusted = append(p.trusted, pfx.Masked())
	}
	p.fly = len(p.trusted) == 0 && strings.TrimSpace(os.Getenv("FLY_APP_NAME")) != ""
	return p
}

func (p *clientIPPolicy) isTrusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, pfx := range p.trusted {
		if pfx.Contains(a) {
			return true
		}
	}
	return false
}

func parseIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// ip returns the client address for r under the policy.
func (p *clientIPPolicy) ip(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	peer, ok := parseIP(host)
	if !ok {
		return host
	}
	if p == nil {
		return peer.String()
	}
	if p.fly {
		if a, ok := parseIP(r.Header.Get("Fly-Client-IP")); ok {
			return a.String()
		}
		return peer.String()
	}
	if !p.isTrusted(peer) {
		return peer.String()
	}
	values := r.Header.Values(p.header)
	if len(values) == 0 {
		return peer.String()
	}
	if p.header != "X-Forwarded-For" {
		if a, ok := parseIP(values[len(values)-1]); ok {
			return a.String()
		}
		return peer.String()
	}
	// X-Forwarded-For: each proxy appends the address it received from, so the
	// rightmost entry not added by one of our own proxies is the client. Entries
	// to its left are client-controlled.
	var hops []string
	for _, v := range values {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseIP(hops[i])
		if !ok {
			return peer.String()
		}
		if !p.isTrusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

// clientIP is the caller's address under the active policy (see the file
// comment): the TCP peer unless a configured trusted proxy vouches otherwise.
func clientIP(r *http.Request) string {
	return activeClientIP.Load().ip(r)
}

// clientKey is the rate-limit and abuse-block key for r: the client address,
// with IPv6 reduced to its /64. An IPv6 host is normally handed a whole /64 and
// can use a fresh source address per request, so a per-address key would give
// it a fresh bucket each time.
func clientKey(r *http.Request) string {
	return rateKey(clientIP(r))
}

func rateKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() || a.Is4In6() {
		return ip
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}
