package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AmneziaWG 3.1: WireGuard with junk packets, padded and re-typed messages,
// and (AWG 3) encrypted headers and content padding. The server is
// amneziawg-go built into this binary (hy-panel awg-serve, service
// hy-panel-awg); like Xray, it holds no peers of its own: the panel puts
// its active users in.

const (
	awgCfgPath  = "/etc/hy-panel/awg.json"
	awgUnitPath = "/etc/systemd/system/hy-panel-awg.service"
	awgSockDir  = "/run/hy-panel-awg"
	awgSock     = awgSockDir + "/control.sock"
	awgIface    = "awg0"
	protoAWG    = "awg"
)

// awgNet is the clients' network: the server is .0.1, users get .0.2 on.
var awgNet = net.IPNet{IP: net.IP{10, 66, 0, 0}, Mask: net.CIDRMask(16, 32)}

// awgConfig is the server: the parameters every client config repeats.
type awgConfig struct {
	Port       int    `json:"port"`
	PrivateKey string `json:"privateKey"` // base64, as in .conf files
	MTU        int    `json:"mtu"`
	DNS        string `json:"dns"`
	// Junk packets before each handshake, paddings, message types.
	Jc, Jmin, Jmax int
	S1, S2, S3, S4 int
	H1, H2, H3, H4 string
	I1             string // signature packet, client-side: a DNS query
	// AWG 3: header protection (server-side) and content padding.
	HeaderProtectionKey    string `json:"headerProtectionKey"`
	ContentPaddingAddition string `json:"contentPaddingAddition"`
}

func randInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

// newAWGConfig makes a server with fresh keys and random paddings, the
// "3.1" profile of the usual installers: H1-H4 = 1-4 (headers are
// encrypted anyway), S1-S4 >= 12: header protection takes its nonce from
// the padding (amneziawg-go's HeaderCipherNonceSize; its docs say 8).
func newAWGConfig(port int) *awgConfig {
	c := &awgConfig{Port: port, PrivateKey: newWGKey(), MTU: 1280, DNS: "1.1.1.1, 1.0.0.1",
		Jc: randInt(4, 8), Jmin: 40, Jmax: 70, S3: randInt(12, 64), S4: randInt(12, 32),
		H1: "1", H2: "2", H3: "3", H4: "4",
		// A DNS query for a random .com name: id, flags, 1 question, qname, A IN.
		I1:                     "<r 2><b 0x01000001000000000000><b 0x0a><rc 10><b 0x03636f6d00><b 0x00010001>",
		HeaderProtectionKey:    newWGKey(),
		ContentPaddingAddition: "0-32",
	}
	// Handshake init (148 B) and response (92 B) must not end up the same size.
	for c.S1, c.S2 = randInt(15, 150), randInt(15, 150); 148+c.S1 == 92+c.S2; c.S2 = randInt(15, 150) {
	}
	return c
}

func readAWG(path string) (*awgConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c awgConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, fmt.Errorf("port %d", c.Port)
	}
	if _, err := wgPublic(c.PrivateKey); err != nil {
		return nil, err
	}
	if k, err := base64.StdEncoding.DecodeString(c.HeaderProtectionKey); err != nil || len(k) != 32 {
		return nil, errors.New("headerProtectionKey: нужен ключ (awg genkey)")
	}
	return &c, nil
}

func (c *awgConfig) write(path string) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := writeAtomic(path, append(b, '\n'), 0o640); err != nil {
		return err
	}
	_, gid := userIDs(panelUser) // the panel reads it to build client configs
	if gid == 0 || os.Geteuid() != 0 {
		return nil // no panel user, or not root (tests): nothing to hand over
	}
	return os.Chown(path, 0, gid)
}

// ---- keys and addresses ----

// newWGKey is a private key as `awg genkey` prints it: clamped, base64.
func newWGKey() string {
	k := make([]byte, 32)
	rand.Read(k)
	k[0] &= 248
	k[31] = k[31]&127 | 64
	return base64.StdEncoding.EncodeToString(k)
}

func wgPublic(priv string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(priv)
	if err == nil && len(b) != 32 {
		err = errors.New("not 32 bytes")
	}
	if err != nil {
		return "", fmt.Errorf("ключ WireGuard: %v", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func b64hex(k string) string {
	b, _ := base64.StdEncoding.DecodeString(k)
	return hex.EncodeToString(b)
}

// awgIP is a user's address: index 2 is 10.66.0.2, 256 is 10.66.1.0.
func awgIP(index int) string {
	ip := awgNet.IP.To4()
	return net.IP{ip[0], ip[1], byte(index >> 8), byte(index)}.String()
}

const awgMaxIndex = 1<<16 - 2

// ---- what clients get ----

// AWGConf is u's client config: AmneziaWG apps and Amnezia VPN import it as a
// file or a QR code.
func (e Endpoint) AWGConf(u User) string {
	c := e.AWG
	if c == nil || u.AWGKey == "" {
		return ""
	}
	pub, _ := wgPublic(c.PrivateKey)
	var b strings.Builder
	w := func(k string, v any) { fmt.Fprintf(&b, "%s = %v\n", k, v) }
	b.WriteString("[Interface]\n")
	w("PrivateKey", u.AWGKey)
	w("Address", awgIP(u.AWGIndex)+"/32")
	w("DNS", c.DNS)
	w("MTU", c.MTU)
	for _, kv := range []struct {
		k string
		v any
	}{{"Jc", c.Jc}, {"Jmin", c.Jmin}, {"Jmax", c.Jmax}, {"S1", c.S1}, {"S2", c.S2}, {"S3", c.S3}, {"S4", c.S4},
		{"H1", c.H1}, {"H2", c.H2}, {"H3", c.H3}, {"H4", c.H4}, {"I1", c.I1},
		{"HeaderProtectionKey", c.HeaderProtectionKey}, {"ContentPaddingAddition", c.ContentPaddingAddition}} {
		w(kv.k, kv.v)
	}
	b.WriteString("\n[Peer]\n")
	w("PublicKey", pub)
	w("Endpoint", net.JoinHostPort(e.Host, fmt.Sprint(c.Port)))
	w("AllowedIPs", "0.0.0.0/0, ::/0")
	w("PersistentKeepalive", 25)
	return b.String()
}

func (e Endpoint) awgRemark(u User) string { return e.remark(u) + "-awg" }

// MihomoAWG is the proxy list item: mihomo's wireguard with AmneziaWG v3.
func (e Endpoint) MihomoAWG(u User) string {
	c := e.AWG
	if c == nil || u.AWGKey == "" {
		return ""
	}
	pub, _ := wgPublic(c.PrivateKey)
	var b strings.Builder
	w := func(k string, v any) { fmt.Fprintf(&b, "    %s: %v\n", k, v) }
	q := func(k, v string) { w(k, fmt.Sprintf("%q", v)) }
	fmt.Fprintf(&b, "  - name: %q\n", e.awgRemark(u))
	w("type", "wireguard")
	q("server", e.Host)
	w("port", c.Port)
	q("ip", awgIP(u.AWGIndex))
	q("private-key", u.AWGKey)
	q("public-key", pub)
	w("udp", "true")
	w("mtu", c.MTU)
	b.WriteString("    amnezia-wg-option:\n")
	o := func(k string, v any) { fmt.Fprintf(&b, "      %s: %v\n", k, v) }
	o("version", 3)
	for _, kv := range []struct {
		k string
		v int
	}{{"jc", c.Jc}, {"jmin", c.Jmin}, {"jmax", c.Jmax}, {"s1", c.S1}, {"s2", c.S2}, {"s3", c.S3}, {"s4", c.S4}} {
		o(kv.k, kv.v)
	}
	for _, kv := range [][2]string{{"h1", c.H1}, {"h2", c.H2}, {"h3", c.H3}, {"h4", c.H4}, {"i1", c.I1},
		{"header-protection-key", c.HeaderProtectionKey}, {"content-padding-addition", c.ContentPaddingAddition}} {
		o(kv[0], fmt.Sprintf("%q", kv[1]))
	}
	return b.String()
}

// ---- the panel's client of the AWG service ----

type awgPeer struct {
	Key           string `json:"key"`                     // public, base64
	IP            string `json:"ip,omitempty"`            // client address
	Rx            int64  `json:"rx,omitempty"`            // from the client
	Tx            int64  `json:"tx,omitempty"`            // to the client
	LastHandshake int64  `json:"lastHandshake,omitempty"` // unix seconds
}

type awgClient struct{ hc *http.Client }

func newAWGClient(sock string) *awgClient {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	return &awgClient{hc: &http.Client{Timeout: 5 * time.Second, Transport: tr}}
}

func (c *awgClient) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://awg"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return fmt.Errorf("awg %s: %s %s", path, resp.Status, bytes.TrimSpace(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Peers are the service's peers with their counters.
func (c *awgClient) Peers() ([]awgPeer, error) {
	var ps []awgPeer
	return ps, c.do("GET", "/peers", nil, &ps)
}

// SetPeers makes the service's peers exactly ps (it only changes what differs,
// so sessions of untouched peers go on).
func (c *awgClient) SetPeers(ps []awgPeer) error { return c.do("PUT", "/peers", ps, nil) }
