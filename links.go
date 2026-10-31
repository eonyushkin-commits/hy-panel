package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

// Endpoint describes how clients reach the server; built from hysteria config + flags.
type Endpoint struct {
	Host     string // public IP/domain
	Port     string // "8443" or port-hopping range "20000-50000"
	SNI      string
	ObfsType string
	ObfsPass string
	Pin      string     // hex sha256 of a self-signed cert
	ECH      string     // base64 ECHConfigList, "" if ECH is off
	Name     string     // profile/remark prefix
	Vless    *Vless     // Xray's VLESS + Reality, nil if off
	AWG      *awgConfig // AmneziaWG server, nil if off
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

// hy2Proto is Hysteria 2: on when the server has its config (a port).
type hy2Proto struct{}

func (hy2Proto) ID() string                          { return protoHy2 }
func (hy2Proto) Title() string                       { return "Hysteria 2" }
func (hy2Proto) On(e Endpoint) bool                  { return e.Port != "" }
func (hy2Proto) Link(e Endpoint, u User) string      { return e.URI(u) }
func (hy2Proto) InSubscription() bool                { return true }
func (hy2Proto) ProxyName(e Endpoint, u User) string { return e.remark(u) }
func (hy2Proto) Mihomo(e Endpoint, u User) string    { return e.Mihomo(u) }

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

// vlessProto is VLESS + Reality (Xray): on once hy-panel xray set it up.
type vlessProto struct{}

func (vlessProto) ID() string                          { return protoVless }
func (vlessProto) Title() string                       { return "VLESS" }
func (vlessProto) On(e Endpoint) bool                  { return e.Vless != nil }
func (vlessProto) Link(e Endpoint, u User) string      { return e.VlessURI(u) }
func (vlessProto) InSubscription() bool                { return true }
func (vlessProto) ProxyName(e Endpoint, u User) string { return e.vlessRemark(u) }
func (vlessProto) Mihomo(e Endpoint, u User) string    { return e.MihomoVless(u) }

// The Safari preset and ClientHello size depend on the client core version.
const realityFP = "safari"

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
	q.Set("fp", realityFP)
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
	w("client-fingerprint", realityFP)
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

func subscriptionUserinfo(u User) string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.Up, u.Down, u.QuotaBytes, u.ExpiresAt)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
