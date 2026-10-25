package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/url"
	"slices"
	"strings"
)

// Endpoint describes how clients reach the server; built from hysteria config + flags.
type Endpoint struct {
	Host     string // public IP/domain
	Port     string // "8443" or port-hopping range "20000-50000"
	SNI      string
	ObfsType string
	ObfsPass string
	Pin      string // hex sha256 of a self-signed cert
	ECH      string // base64 ECHConfigList, "" if ECH is off
	Name     string // profile/remark prefix
	Vless    *Vless // Xray's VLESS + Reality, nil if off
}

// endpointFor builds the link parameters from the Hysteria config and the
// panel settings (HYP_HOST, HYP_NAME); certificate problems only lose the pin.
func endpointFor(c *hyConfig, env map[string]string) Endpoint {
	ci, err := readCert(c.TLS.Cert)
	if err != nil {
		log.Printf("WARN: tls.cert: %v (no pin/SNI from cert)", err)
	}
	ech, err := readECH(c.ECH.KeyPath)
	if err != nil {
		log.Printf("WARN: ech.keyPath: %v (links without ECH)", err)
	}
	return buildEndpoint(c, ci, ech, env["HYP_HOST"], env["HYP_NAME"])
}

// buildEndpoint fills the link parameters from the Hysteria config and certificate.
// SNI matters: Hysteria's default sniGuard (dns-san) rejects handshakes whose
// SNI does not match the cert's DNS SANs, and clients dialing an IP send none.
func buildEndpoint(c *hyConfig, ci certInfo, ech, host, name string) Endpoint {
	e := Endpoint{Host: host, Port: c.port(), Pin: ci.Pin, ECH: ech, Name: name}
	e.ObfsType, e.ObfsPass = c.obfs()
	domain := ""
	if len(c.ACME.Domains) > 0 {
		domain = c.ACME.Domains[0]
	} else if ci.DNSName != "" && !ci.SelfSigned && !strings.HasPrefix(ci.DNSName, "*") {
		domain = ci.DNSName
	}
	if e.Host == "" {
		e.Host = domain
	}
	switch {
	case domain != "":
		e.SNI = domain
	case ci.DNSName != "":
		e.SNI = strings.Replace(ci.DNSName, "*", "www", 1)
	}
	if e.SNI == e.Host {
		e.SNI = "" // implied by the host
	}
	return e
}

func (e Endpoint) remark(u User) string {
	if e.Name == "" {
		return u.Name
	}
	return e.Name + "-" + u.Name
}

// firstPort is the first port of a hopping range ("20000-50000" → "20000").
func (e Endpoint) firstPort() string {
	return strings.FieldsFunc(e.Port, func(r rune) bool { return r == '-' || r == ',' })[0]
}

func (e Endpoint) hopping() bool { return strings.ContainsAny(e.Port, "-,") }

// URI builds the official hysteria2:// share link
// (https://v2.hysteria.network/docs/developers/URI-Scheme/). A hopping range
// goes into mport with the first port in the address: Xray-based apps
// (v2RayTun, v2rayN) cannot parse a range there, and the server listens on
// the whole range, so every app connects.
func (e Endpoint) URI(u User) string {
	q := url.Values{}
	port := e.Port
	if e.hopping() {
		port = e.firstPort()
		q.Set("mport", e.Port)
	}
	if e.ObfsType != "" {
		q.Set("obfs", e.ObfsType)
		q.Set("obfs-password", e.ObfsPass)
	}
	if e.SNI != "" {
		q.Set("sni", e.SNI)
	}
	if e.ECH != "" {
		q.Set("ech", e.ECH)
	}
	if e.Pin != "" {
		// A self-signed cert fails normal verification; the pin replaces it.
		// pinSHA256 is Hysteria's name; Xray-based apps (v2RayTun, Happ)
		// dropped insecure and read the pin as pcs.
		q.Set("insecure", "1")
		q.Set("pinSHA256", e.Pin)
		q.Set("pcs", e.Pin)
	}
	v := url.URL{
		Scheme:   "hysteria2",
		User:     url.UserPassword(u.Name, u.Password),
		Host:     net.JoinHostPort(e.Host, port),
		Path:     "/",
		RawQuery: q.Encode(),
		Fragment: e.remark(u),
	}
	return v.String()
}

// Mihomo returns a proxy list item for mihomo (Clash Meta).
func (e Endpoint) Mihomo(u User) string {
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "    %s: %s\n", k, v) }
	q := func(k, v string) { w(k, fmt.Sprintf("%q", v)) } // quoted: a hex pin could read as a number
	fmt.Fprintf(&b, "  - name: %q\n", e.remark(u))
	w("type", "hysteria2")
	q("server", e.Host)
	if e.hopping() {
		w("port", e.firstPort())
		q("ports", e.Port)
	} else {
		w("port", e.Port)
	}
	q("password", u.Name+":"+u.Password)
	if e.ObfsType != "" {
		w("obfs", e.ObfsType)
		q("obfs-password", e.ObfsPass)
	}
	if e.SNI != "" {
		q("sni", e.SNI)
	}
	if e.Pin != "" {
		// mihomo checks the pin itself and then skips chain verification.
		q("fingerprint", e.Pin)
	}
	if e.ECH != "" {
		fmt.Fprintf(&b, "    ech-opts: {enable: true, config: %q}\n", e.ECH)
	}
	return b.String()
}

// VlessURI builds the vless:// share link the way v2rayN and the Xray apps
// (Happ, v2RayTun, Streisand) read it; "" if VLESS is off.
func (e Endpoint) VlessURI(u User) string {
	v := e.Vless
	if v == nil {
		return ""
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", v.SNI)
	q.Set("fp", "chrome") // a browser's TLS handshake: Reality only works with uTLS fingerprints
	q.Set("pbk", v.PublicKey)
	if v.ShortID != "" {
		q.Set("sid", v.ShortID)
	}
	q.Set("type", v.Network)
	if v.Network == "xhttp" {
		q.Set("path", v.Path)
		q.Set("mode", v.Mode)
		if v.Host != "" {
			q.Set("host", v.Host)
		}
	}
	if v.Flow != "" {
		q.Set("flow", v.Flow)
	}
	l := url.URL{
		Scheme:   "vless",
		User:     url.User(u.UUID),
		Host:     net.JoinHostPort(e.Host, v.Port),
		RawQuery: q.Encode(),
		Fragment: e.vlessRemark(u),
	}
	return l.String()
}

func (e Endpoint) vlessRemark(u User) string { return e.remark(u) + "-vless" }

// MihomoVless returns the VLESS proxy list item for mihomo, "" if VLESS is off.
func (e Endpoint) MihomoVless(u User) string {
	v := e.Vless
	if v == nil {
		return ""
	}
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "    %s: %s\n", k, v) }
	q := func(k, v string) { w(k, fmt.Sprintf("%q", v)) } // quoted: a hex short-id could read as a number
	fmt.Fprintf(&b, "  - name: %q\n", e.vlessRemark(u))
	w("type", "vless")
	q("server", e.Host)
	w("port", v.Port)
	q("uuid", u.UUID)
	w("udp", "true")
	w("packet-encoding", "xudp")
	w("tls", "true")
	q("servername", v.SNI)
	w("client-fingerprint", "chrome")
	w("network", v.Network)
	if v.Flow != "" {
		w("flow", v.Flow)
	}
	if v.Network == "xhttp" {
		host := ""
		if v.Host != "" {
			host = fmt.Sprintf(", host: %q", v.Host)
		}
		fmt.Fprintf(&b, "    xhttp-opts: {path: %q, mode: %q%s}\n", v.Path, v.Mode, host)
	}
	fmt.Fprintf(&b, "    reality-opts: {public-key: %q, short-id: %q}\n", v.PublicKey, v.ShortID)
	return b.String()
}

// ---- protocols ----

const (
	protoHy2   = "hysteria2"
	protoVless = "vless"
)

// protoTitles name the protocols in the panel, in fallback order: Hysteria
// (fast, UDP) first, VLESS over TCP when UDP is cut.
var protoTitles = []struct{ ID, Title string }{
	{protoHy2, "Hysteria 2"},
	{protoVless, "VLESS"},
}

func knownProto(id string) bool {
	return slices.ContainsFunc(protoTitles, func(p struct{ ID, Title string }) bool { return p.ID == id })
}

func protoTitle(id string) string {
	for _, p := range protoTitles {
		if p.ID == id {
			return p.Title
		}
	}
	return id
}

// Protocols the server runs, in fallback order.
func (e Endpoint) Protocols() []string {
	var ps []string
	for _, p := range protoTitles {
		switch {
		case p.ID == protoHy2 && e.Port != "", p.ID == protoVless && e.Vless != nil:
			ps = append(ps, p.ID)
		}
	}
	return ps
}

// UserProtocols are the server's protocols u may use, in fallback order.
func (e Endpoint) UserProtocols(u User) []string {
	var ps []string
	for _, p := range e.Protocols() {
		if u.Uses(p) {
			ps = append(ps, p)
		}
	}
	return ps
}

// Link is u's share link for one protocol.
func (e Endpoint) Link(proto string, u User) string {
	switch proto {
	case protoHy2:
		return e.URI(u)
	case protoVless:
		return e.VlessURI(u)
	}
	return ""
}

// URIs are u's share links, in fallback order.
func (e Endpoint) URIs(u User) []string {
	var ls []string
	for _, p := range e.UserProtocols(u) {
		ls = append(ls, e.Link(p, u))
	}
	return ls
}

// proxyName is the name of u's proxy for proto in mihomo and the apps.
func (e Endpoint) proxyName(proto string, u User) string {
	if proto == protoVless {
		return e.vlessRemark(u)
	}
	return e.remark(u)
}

// MihomoProxy is the proxy list item of one protocol.
func (e Endpoint) MihomoProxy(proto string, u User) string {
	switch proto {
	case protoHy2:
		return e.Mihomo(u)
	case protoVless:
		return e.MihomoVless(u)
	}
	return ""
}

// MihomoDoc is a complete mihomo proxy-provider document for u: a proxy
// for each of u's protocols.
func (e Endpoint) MihomoDoc(u User) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, p := range e.UserProtocols(u) {
		b.WriteString(e.MihomoProxy(p, u))
	}
	return b.String()
}

// MihomoFallback is u's proxies plus a fallback group over them in the
// panel's order: when a protocol is blocked, mihomo moves to the next one.
func (e Endpoint) MihomoFallback(u User) string {
	var names []string
	for _, p := range e.UserProtocols(u) {
		names = append(names, fmt.Sprintf("%q", e.proxyName(p, u)))
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

func subscriptionUserinfo(u User) string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.Up, u.Down, u.QuotaBytes, u.ExpiresAt)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
