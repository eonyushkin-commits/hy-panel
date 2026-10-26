package main

import (
	"fmt"
	"strings"
)

// The panel's protocols, each one way clients reach the server. A protocol
// says what clients get from it — its share link and its mihomo proxy,
// built from the server's settings in Endpoint; its backend (sync.go)
// keeps its server's users and counters in step with the panel. Adding a
// protocol is a type for each and an entry in protocols.

const (
	protoHy2   = "hysteria2"
	protoVless = "vless"
)

type protocol interface {
	ID() string    // as in User.ProtoOff, the API and the UI
	Title() string // as the panel names it
	// On reports whether the server runs it: e has its settings.
	On(e Endpoint) bool
	// Link is u's share link; AmneziaWG's is the .conf text.
	Link(e Endpoint, u User) string
	// InSubscription reports whether apps take the link from a subscription.
	InSubscription() bool
	// ProxyName names u's proxy in mihomo and the apps.
	ProxyName(e Endpoint, u User) string
	// Mihomo is u's proxy list item for mihomo.
	Mihomo(e Endpoint, u User) string
}

// protocols are all the panel knows, in fallback order: Hysteria (fast,
// UDP) first, then AmneziaWG (UDP, looks different), VLESS over TCP when
// UDP is cut.
var protocols = []protocol{hy2Proto{}, awgProto{}, vlessProto{}}

func protoByID(id string) protocol {
	for _, p := range protocols {
		if p.ID() == id {
			return p
		}
	}
	return nil
}

func knownProto(id string) bool { return protoByID(id) != nil }

// running are the protocols the server runs, in fallback order.
func (e Endpoint) running() []protocol {
	var ps []protocol
	for _, p := range protocols {
		if p.On(e) {
			ps = append(ps, p)
		}
	}
	return ps
}

// userProtos are the server's protocols u may use, in fallback order.
func (e Endpoint) userProtos(u User) []protocol {
	var ps []protocol
	for _, p := range e.running() {
		if u.Uses(p.ID()) {
			ps = append(ps, p)
		}
	}
	return ps
}

func ids(ps []protocol) []string {
	var s []string
	for _, p := range ps {
		s = append(s, p.ID())
	}
	return s
}

// Protocols the server runs, in fallback order.
func (e Endpoint) Protocols() []string { return ids(e.running()) }

// UserProtocols are the server's protocols u may use, in fallback order.
func (e Endpoint) UserProtocols(u User) []string { return ids(e.userProtos(u)) }

// Link is u's share link for one protocol; for AmneziaWG, the .conf text.
func (e Endpoint) Link(id string, u User) string {
	if p := protoByID(id); p != nil {
		return p.Link(e, u)
	}
	return ""
}

// URIs are u's share links for subscriptions, in fallback order.
func (e Endpoint) URIs(u User) []string {
	var ls []string
	for _, p := range e.userProtos(u) {
		if p.InSubscription() {
			ls = append(ls, p.Link(e, u))
		}
	}
	return ls
}

// MihomoProxy is the proxy list item of one protocol.
func (e Endpoint) MihomoProxy(id string, u User) string {
	if p := protoByID(id); p != nil {
		return p.Mihomo(e, u)
	}
	return ""
}

// MihomoDoc is a complete mihomo proxy-provider document for u: a proxy
// for each of u's protocols.
func (e Endpoint) MihomoDoc(u User) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, p := range e.userProtos(u) {
		b.WriteString(p.Mihomo(e, u))
	}
	return b.String()
}

// MihomoFallback is u's proxies plus a fallback group over them in the
// panel's order: when a protocol is blocked, mihomo moves to the next one.
func (e Endpoint) MihomoFallback(u User) string {
	var names []string
	for _, p := range e.userProtos(u) {
		names = append(names, fmt.Sprintf("%q", p.ProxyName(e, u)))
	}
	return e.MihomoDoc(u) + fmt.Sprintf(`proxy-groups:
  - name: %q
    type: fallback
    proxies: [%s]
    url: https://www.gstatic.com/generate_204
    interval: 120
`, e.groupName(), strings.Join(names, ", "))
}

func (e Endpoint) groupName() string {
	if e.Name == "" {
		return "VPN"
	}
	return e.Name
}
