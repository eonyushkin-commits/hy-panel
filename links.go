package main

import (
	"encoding/base64"
	"fmt"
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
	Name     string // profile/remark prefix
}

// buildEndpoint fills gaps in the flags from the Hysteria config and certificate.
// SNI matters: Hysteria's default sniGuard (dns-san) rejects handshakes whose
// SNI does not match the cert's DNS SANs, and clients dialing an IP send none.
func buildEndpoint(c *hyConfig, ci certInfo, host, port, sni, name string) Endpoint {
	e := Endpoint{Host: host, Port: port, SNI: sni, Pin: ci.Pin, Name: name}
	e.ObfsType, e.ObfsPass = c.obfs()
	if e.Port == "" {
		e.Port = c.port()
	}
	domain := ""
	if len(c.ACME.Domains) > 0 {
		domain = c.ACME.Domains[0]
	} else if ci.DNSName != "" && !ci.SelfSigned && !strings.HasPrefix(ci.DNSName, "*") {
		domain = ci.DNSName
	}
	if e.Host == "" {
		e.Host = domain
	}
	if e.SNI == "" {
		switch {
		case domain != "":
			e.SNI = domain
		case ci.DNSName != "":
			e.SNI = strings.Replace(ci.DNSName, "*", "www", 1)
		}
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

// URI builds the official hysteria2:// share link
// (https://v2.hysteria.network/docs/developers/URI-Scheme/).
func (e Endpoint) URI(u User) string {
	q := url.Values{}
	if e.ObfsType != "" {
		q.Set("obfs", e.ObfsType)
		q.Set("obfs-password", e.ObfsPass)
	}
	if e.SNI != "" {
		q.Set("sni", e.SNI)
	}
	if e.Pin != "" {
		// A self-signed cert fails normal verification; the pin replaces it.
		q.Set("insecure", "1")
		q.Set("pinSHA256", e.Pin)
	}
	v := url.URL{
		Scheme:   "hysteria2",
		User:     url.UserPassword(u.Name, u.Password),
		Host:     net.JoinHostPort(e.Host, e.Port),
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
	if strings.ContainsAny(e.Port, "-,") {
		w("port", strings.FieldsFunc(e.Port, func(r rune) bool { return r == '-' || r == ',' })[0])
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
	return b.String()
}

func subscriptionUserinfo(u User) string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.Up, u.Down, u.QuotaBytes, u.ExpiresAt)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
