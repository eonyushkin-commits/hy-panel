package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
)

type trustTunnelConfig struct {
	Domain string `json:"domain"`
	Port   string `json:"port"`
	cert   []byte
}

type trustTunnelProto struct{}

func (trustTunnelProto) ID() string                          { return protoTrustTunnel }
func (trustTunnelProto) Title() string                       { return "TrustTunnel" }
func (trustTunnelProto) On(e Endpoint) bool                  { return e.TrustTunnel != nil }
func (trustTunnelProto) ProxyName(e Endpoint, u User) string { return e.remark(u) + " / TrustTunnel" }
func (trustTunnelProto) Mihomo(Endpoint, User) string        { return "" }

func trustTunnelPassword(u User) string {
	mac := hmac.New(sha256.New, []byte(u.SubToken))
	mac.Write([]byte("hy-panel/trusttunnel/password/v1"))
	mac.Write([]byte(u.UUID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (c trustTunnelConfig) address() string { return net.JoinHostPort(c.Domain, c.Port) }

// TrustTunnel deep links use QUIC-varint tag lengths.
func (p trustTunnelProto) Link(e Endpoint, u User) string {
	if e.TrustTunnel == nil {
		return ""
	}
	c := e.TrustTunnel
	payload := []byte{0, 1, 2} // version
	add := func(tag byte, value string) {
		n := len(value)
		payload = append(payload, tag)
		switch {
		case n < 1<<6:
			payload = append(payload, byte(n))
		case n < 1<<14:
			payload = binary.BigEndian.AppendUint16(payload, uint16(n)|1<<14)
		case n < 1<<30:
			payload = binary.BigEndian.AppendUint32(payload, uint32(n)|1<<31)
		default:
			payload = binary.BigEndian.AppendUint64(payload, uint64(n)|3<<62)
		}
		payload = append(payload, value...)
	}
	add(0x01, c.Domain)
	add(0x05, u.Name)
	add(0x06, trustTunnelPassword(u))
	add(0x02, c.address())
	add(0x04, "\x00") // IPv6 egress is disabled
	add(0x08, string(c.cert))
	add(0x0c, p.ProxyName(e, u))
	return "tt://?" + base64.RawURLEncoding.EncodeToString(payload)
}

func (a *App) handleTrustTunnelConf(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.exportUser(w, r)
	if !ok {
		return
	}
	c := a.ep.TrustTunnel
	if c == nil || !u.Uses(protoTrustTunnel) {
		http.Error(w, "TrustTunnel недоступен", http.StatusNotFound)
		return
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert})
	name, _ := json.Marshal((trustTunnelProto{}).ProxyName(a.ep, u))
	w.Header().Set("Content-Type", "application/toml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fileName(a.ep.remark(u))+`-trusttunnel.toml"`)
	fmt.Fprintf(w, `hostname = %q
addresses = [%q]
has_ipv6 = false
username = %q
password = %q
certificate = %q
skip_verification = false
upstream_protocol = "http2"
name = %s
`, c.Domain, c.address(), u.Name, trustTunnelPassword(u), cert, name)
}
