package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/eonyushkin-commits/hy-panel/internal/model"
)

const awgConfigPath = "/etc/hy-panel/awg.json"
const awgInterface = "hyp-awg"

// All wire parameters are persisted once and shared by server/client exports.
type awgConfig struct {
	Port       string `json:"port"`
	Subnet     string `json:"subnet"`
	DNS        string `json:"dns"`
	MTU        int    `json:"mtu"`
	PrivateKey string `json:"privateKey"`
	awgObfuscation
}

func freshAWG() *awgConfig {
	c := &awgConfig{Port: "51820", Subnet: "10.77.0.0/16", DNS: "1.1.1.1, 1.0.0.1", MTU: 1380, PrivateKey: model.NewAWGKey(), awgObfuscation: awgObfuscation{Jc: 4, Jmin: 40, Jmax: 100, S1: 24, S2: 24, S3: 24, S4: 24, I1: "<r 64>", HeaderProtectionKey: model.NewAWGKey(), ContentPaddingAddition: "8-16", RekeyAfterTime: "110-130", RekeyTimeout: "4-7", RejectAfterTime: "180-240", KeepaliveTimeout: "8-12", MaxHandshakeAttempts: "18-24"}}
	for i := range c.H {
		// Separate bands guarantee uniqueness and stay within signed int32.
		b, _ := base64.StdEncoding.DecodeString(model.NewAWGKey())
		c.H[i] = strconv.FormatUint(uint64(5+uint32(i)*500000000+binary.LittleEndian.Uint32(b[:4])%499999995), 10)
	}
	return c
}

func (c *awgConfig) check() error {
	if !validPortNumber(c.Port) {
		return errors.New("AWG: нужен UDP-порт 1–65535")
	}
	p, err := netip.ParsePrefix(c.Subnet)
	if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() != 16 || p != p.Masked() {
		return errors.New("AWG: нужна частная IPv4-подсеть /16, например 10.77.0.0/16")
	}
	if c.MTU < 1280 || c.MTU > 1380 {
		return errors.New("AWG: MTU должен быть 1280–1380")
	}
	if _, err := model.AWGPublicKey(c.PrivateKey); err != nil {
		return err
	}
	if err := c.awgObfuscation.check(c.MTU); err != nil {
		return err
	}
	dns := strings.Split(c.DNS, ",")
	if len(dns) > 3 {
		return errors.New("AWG: не более трёх DNS")
	}
	for _, s := range dns {
		ip, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !ip.Is4() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("AWG: DNS должен быть публичным IPv4-адресом")
		}
	}
	return nil
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
	if err := c.check(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *awgConfig) address(index int) string {
	p, _ := netip.ParsePrefix(c.Subnet)
	b := p.Addr().As4()
	b[2], b[3] = byte(index>>8), byte(index)
	return netip.AddrFrom4(b).String()
}

func (c *awgConfig) obfuscation() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\nS1 = %d\nS2 = %d\nS3 = %d\nS4 = %d\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n", c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4, c.H[0], c.H[1], c.H[2], c.H[3])
	for _, pair := range c.awgObfuscation.strings() {
		if pair[1] != "" {
			fmt.Fprintf(&b, "%s = %s\n", pair[0], pair[1])
		}
	}
	// Explicit off values allow true -> false changes through awg syncconf.
	fmt.Fprintf(&b, "RandomTrailers = %s\nDisableCookies = %s\n", awgBool(c.RandomTrailers), awgBool(c.DisableCookies))
	return b.String()
}

func (e Endpoint) AWGConf(u User) string {
	if e.AWG == nil || u.AWGIndex < 2 || u.AWGKey == "" {
		return ""
	}
	c := e.AWG
	public, _ := model.AWGPublicKey(c.PrivateKey)
	// Route IPv6 into the tunnel and discard it server-side, so a full
	// tunnel cannot silently leak IPv6 outside the IPv4-only server path.
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32, fd77:77::%x/128\nDNS = %s\nMTU = %d\n%s\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s\nPersistentKeepalive = %s\n", u.AWGKey, c.address(u.AWGIndex), u.AWGIndex, c.DNS, c.MTU, c.obfuscation(), public, net.JoinHostPort(e.Host, c.Port), c.keepalive())
}

type awgProto struct{}

func (awgProto) ID() string                          { return protoAWG }
func (awgProto) Title() string                       { return "AmneziaWG" }
func (awgProto) On(e Endpoint) bool                  { return e.AWG != nil }
func (awgProto) ProxyName(e Endpoint, u User) string { return e.remark(u) + "-awg" }
func (awgProto) Link(e Endpoint, u User) string {
	if c := e.AWGConf(u); c != "" {
		return "vpn://" + base64.RawURLEncoding.EncodeToString([]byte(c))
	}
	return ""
}
func (awgProto) Mihomo(e Endpoint, u User) string {
	if e.AWG == nil {
		return ""
	}
	c := e.AWG
	pub, _ := model.AWGPublicKey(c.PrivateKey)
	var b strings.Builder
	fmt.Fprintf(&b, "  - name: %q\n    type: wireguard\n    server: %q\n    port: %s\n    ip: %q\n    ipv6: %q\n    private-key: %q\n    public-key: %q\n    allowed-ips: [\"0.0.0.0/0\", \"::/0\"]\n    udp: true\n    mtu: %d\n    persistent-keepalive: %d\n    remote-dns-resolve: true\n    dns: [", e.remark(u)+"-awg", e.Host, c.Port, c.address(u.AWGIndex), fmt.Sprintf("fd77:77::%x", u.AWGIndex), u.AWGKey, pub, c.MTU, c.mihomoKeepalive())
	for i, s := range strings.Split(c.DNS, ",") {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", strings.TrimSpace(s))
	}
	b.WriteString("]\n    amnezia-wg-option:\n")
	options, _ := yaml.Marshal(c.awgObfuscation.mihomo())
	for _, line := range strings.Split(strings.TrimSuffix(string(options), "\n"), "\n") {
		fmt.Fprintf(&b, "      %s\n", line)
	}
	return b.String()
}

func (a *App) handleAWGConf(w http.ResponseWriter, r *http.Request) {
	u, _, ok := a.exportUser(w, r)
	if !ok {
		return
	}
	if a.ep.AWG == nil || !u.Uses(protoAWG) {
		http.Error(w, "AmneziaWG недоступен", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fileName(a.ep.remark(u))+`-awg.conf"`)
	fmt.Fprint(w, a.ep.AWGConf(u))
}

type awgCounter struct {
	Rx, Tx    int64
	Handshake int64
}
type awgSnapshot struct {
	Epoch string
	Peers map[string]awgCounter
}
type awgPeer struct {
	Name, PublicKey string
	Index           int
}

type awgBackend struct {
	agent    *agentClient
	config   *awgConfig
	previous map[string]awgCounter
	epoch    string
}

func (*awgBackend) proto() string   { return protoAWG }
func (*awgBackend) errText() string { return "AmneziaWG: " }
func (b *awgBackend) stats(now time.Time, users []User) (map[string]trafficEntry, onlineSnapshot, error) {
	code, body, err := b.agent.do("GET", "/awg/state", nil)
	if err != nil {
		return nil, onlineSnapshot{}, err
	}
	if code != http.StatusOK {
		return nil, onlineSnapshot{}, errors.New(strings.TrimSpace(string(body)))
	}
	var snapshot awgSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return nil, onlineSnapshot{}, err
	}
	tr, on := map[string]trafficEntry{}, map[string]int{}
	for _, u := range users {
		pub, _ := model.AWGPublicKey(u.AWGKey)
		cur, exists := snapshot.Peers[pub]
		if !exists {
			continue
		}
		if b.previous != nil && b.epoch == snapshot.Epoch {
			prev := b.previous[pub]
			// Receive is upload from the client; kernel counters are cumulative.
			up, down := cur.Rx-prev.Rx, cur.Tx-prev.Tx
			if up < 0 {
				up = cur.Rx
			}
			if down < 0 {
				down = cur.Tx
			}
			tr[u.Name] = trafficEntry{Tx: up, Rx: down}
		}
		if cur.Handshake > 0 && cur.Handshake <= now.Unix() && now.Unix()-cur.Handshake < 180 && u.Allowed(protoAWG, now) {
			on[u.Name] = 1
		}
	}
	b.previous, b.epoch = snapshot.Peers, snapshot.Epoch
	return tr, onlineSnapshot{users: on, at: now}, nil
}
func (b *awgBackend) push(now time.Time, users []User) error {
	peers := []awgPeer{}
	for _, u := range users {
		if u.Allowed(protoAWG, now) {
			pub, err := model.AWGPublicKey(u.AWGKey)
			if err != nil {
				return err
			}
			peers = append(peers, awgPeer{u.Name, pub, u.AWGIndex})
		}
	}
	body, _ := json.Marshal(peers)
	code, out, err := b.agent.do("POST", "/awg/sync", bytes.NewReader(body))
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}

func awgRequestFlags(p map[string]string) (*awgConfig, error) {
	c := freshAWG()
	if p["port"] != "" {
		c.Port = p["port"]
	}
	if p["subnet"] != "" {
		c.Subnet = p["subnet"]
	}
	if p["dns"] != "" {
		c.DNS = p["dns"]
	}
	if p["mtu"] != "" {
		n, err := strconv.Atoi(p["mtu"])
		if err != nil {
			return nil, err
		}
		c.MTU = n
	}
	if p["obfuscation"] != "" {
		if err := parseAWGObfuscation(p["obfuscation"], &c.awgObfuscation); err != nil {
			return nil, err
		}
	}
	return c, c.check()
}
