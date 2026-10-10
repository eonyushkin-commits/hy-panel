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
	Pin      string // hex sha256 of a self-signed cert
	ECH      string // base64 ECHConfigList, "" if ECH is off
	Name     string // profile/remark prefix
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
		q.Set("insecure", "1")
		q.Set("pinSHA256", e.Pin)
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

// MihomoDoc is a complete mihomo proxy-provider document for u.
func (e Endpoint) MihomoDoc(u User) string { return "proxies:\n" + e.Mihomo(u) }

func subscriptionUserinfo(u User) string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.Up, u.Down, u.QuotaBytes, u.ExpiresAt)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
