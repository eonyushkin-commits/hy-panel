package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
	"gopkg.in/yaml.v3"
)

func parseConf(t *testing.T, conf string) map[string]map[string]string {
	t.Helper()
	m, sec := map[string]map[string]string{}, ""
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case l == "":
		case strings.HasPrefix(l, "["):
			sec = strings.Trim(l, "[]")
			m[sec] = map[string]string{}
		default:
			k, v, ok := strings.Cut(l, " = ")
			if !ok {
				t.Fatalf("bad line %q", l)
			}
			m[sec][k] = v
		}
	}
	return m
}

func TestAWGConfig(t *testing.T) {
	for i := 0; i < 500; i++ {
		c := newAWGConfig(51820)
		if 148+c.S1 == 92+c.S2 || min(c.S1, c.S2, c.S3, c.S4) < 12 || c.Jmax >= c.MTU || c.Jc < 4 {
			t.Fatalf("%+v", c)
		}
	}
	p := filepath.Join(t.TempDir(), "awg", "awg.json")
	c := newAWGConfig(51820)
	if err := c.write(p); err != nil {
		t.Fatal(err)
	}
	r, err := readAWG(p)
	if err != nil || *r != *c {
		t.Fatalf("%v %+v", err, r)
	}
	os.WriteFile(p, []byte(`{"port": 51820, "privateKey": "bad"}`), 0o600)
	if _, err := readAWG(p); err == nil {
		t.Fatal("bad key accepted")
	}
	// The public key as X25519 gives it (vector from `xray x25519 -i`).
	if pub, err := wgPublic("YAnz8UHVPqIoBqA9xbrmWkzZ6W6U6V0b3n1h1E3vC2Y="); err != nil || pub != "LY3HAnYBhLSxLlMVzw8SVXC3BqzCELYIcrrEW+BLH0E=" {
		t.Fatalf("%s %v", pub, err)
	}
	if awgIP(2) != "10.66.0.2" || awgIP(258) != "10.66.1.2" {
		t.Fatal(awgIP(258))
	}
}

func TestAWGLinks(t *testing.T) {
	c := newAWGConfig(51820)
	ep := Endpoint{Host: "195.63.134.68", Port: "443", Name: "NL", AWG: c}
	u := User{Name: "phone", Password: "Pw123456", UUID: newUUID(), AWGKey: newWGKey(), AWGIndex: 7}
	conf := parseConf(t, ep.AWGConf(u))
	in, peer := conf["Interface"], conf["Peer"]
	srvPub, _ := wgPublic(c.PrivateKey)
	if in["PrivateKey"] != u.AWGKey || in["Address"] != "10.66.0.7/32" || in["HeaderProtectionKey"] != c.HeaderProtectionKey ||
		in["S1"] != fmt.Sprint(c.S1) || in["H4"] != "4" || in["ContentPaddingAddition"] != "0-32" || in["I1"] != c.I1 ||
		peer["PublicKey"] != srvPub || peer["Endpoint"] != "195.63.134.68:51820" || peer["AllowedIPs"] != "0.0.0.0/0, ::/0" {
		t.Fatalf("%v", conf)
	}

	var doc struct{ Proxies []map[string]any }
	if err := yaml.Unmarshal([]byte("proxies:\n"+ep.MihomoAWG(u)), &doc); err != nil {
		t.Fatalf("%v\n%s", err, ep.MihomoAWG(u))
	}
	m := doc.Proxies[0]
	o, _ := m["amnezia-wg-option"].(map[string]any)
	if m["type"] != "wireguard" || m["name"] != "NL-phone-awg" || m["port"] != 51820 || m["ip"] != "10.66.0.7" ||
		m["private-key"] != u.AWGKey || m["public-key"] != srvPub || o["version"] != 3 || o["s1"] != c.S1 ||
		o["h1"] != "1" || o["header-protection-key"] != c.HeaderProtectionKey || o["i1"] != c.I1 {
		t.Fatalf("%v", m)
	}

	// In the fallback order, between Hysteria and VLESS; not in subscriptions.
	xs, _ := parseXray(freshXray("443", "lurkpro.tech"))
	ep.Vless = &xs.Link
	if got := ep.UserProtocols(u); !slices.Equal(got, []string{protoHy2, protoAWG, protoVless}) {
		t.Fatal(got)
	}
	if ls := ep.URIs(u); len(ls) != 2 || strings.Contains(strings.Join(ls, ""), "PrivateKey") {
		t.Fatal(ls)
	}
	if !strings.Contains(ep.MihomoFallback(u), `proxies: ["NL-phone", "NL-phone-awg", "NL-phone-vless"]`) {
		t.Fatal(ep.MihomoFallback(u))
	}
}

func TestStoreAWGKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "users.json")
	os.WriteFile(p, []byte(`[{"name":"a","password":"pw123456","enabled":true},{"name":"b","password":"pw1234567","enabled":true,"awgKey":"`+newWGKey()+`","awgIndex":2}]`), 0o600)
	s, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Get("a")
	if a.AWGKey == "" || a.AWGIndex != 3 { // 2 is b's
		t.Fatalf("%+v", a)
	}
	c := mustCreate(t, s, User{Name: "c"})
	if c.AWGIndex != 4 {
		t.Fatalf("%+v", c)
	}
	s.Delete("a")
	if d := mustCreate(t, s, User{Name: "d"}); d.AWGIndex != 3 {
		t.Fatalf("freed index not reused: %+v", d)
	}
}

// ---- the real amneziawg-go device, in memory ----

func newTestDevice(t *testing.T, uapi string) (*device.Device, *tuntest.ChannelTUN) {
	t.Helper()
	tn := tuntest.NewChannelTUN()
	dev := device.NewDevice(tn.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "test: "))
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("ipc: %v\n%s", err, uapi)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	// Packets the device delivers must be taken, or it blocks (and Close with it).
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-tn.Inbound:
			case <-done:
				return
			}
		}
	}()
	t.Cleanup(func() { dev.Close(); close(done) })
	return dev, tn
}

func freeUDP(t *testing.T) int {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

// TestAWGHandshake runs our server config and a client built from our .conf
// on amneziawg-go: they must agree on every obfuscation parameter, or no
// handshake comes through.
func TestAWGHandshake(t *testing.T) {
	c := newAWGConfig(freeUDP(t))
	srv, _ := newTestDevice(t, c.uapi())
	ep := Endpoint{Host: "127.0.0.1", AWG: c}
	u := User{Name: "u", AWGKey: newWGKey(), AWGIndex: 2}

	// The panel's side: control API over a unix socket, as hy-panel-awg serves it.
	sock := filepath.Join(t.TempDir(), "c.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(l, awgControl(srv))
	t.Cleanup(func() { l.Close() })
	a := testApp(t, nil)
	a.addBackend(newAWGBackend(newAWGClient(sock)))
	a.ep = ep
	mustCreate(t, a.store, u)
	a.syncOnce(time.Now())
	if l := syncState(a, protoAWG); l.err != "" || l.fails != 0 {
		t.Fatal(l.err)
	}
	pub, _ := wgPublic(u.AWGKey)
	if ps, _ := devPeers(srv); len(ps) != 1 || ps[0].Key != pub || ps[0].IP != "10.66.0.2" {
		t.Fatalf("%+v", ps)
	}

	// The client, from the .conf the user gets.
	conf := parseConf(t, ep.AWGConf(u))
	in := conf["Interface"]
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", b64hex(in["PrivateKey"]))
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1"} {
		fmt.Fprintf(&b, "%s=%s\n", strings.ToLower(k), in[k])
	}
	fmt.Fprintf(&b, "header_protection_key=%s\ncontent_padding_addition=%s\n", b64hex(in["HeaderProtectionKey"]), in["ContentPaddingAddition"])
	fmt.Fprintf(&b, "public_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\n", b64hex(conf["Peer"]["PublicKey"]), conf["Peer"]["Endpoint"])
	_, cli := newTestDevice(t, b.String())

	// Packets from the client to the internet start the handshake. Not one
	// packet: AmneziaWG tells message types by size, and content padding now
	// and then makes a data packet the size of a cookie reply, which the
	// server then drops. Real traffic goes on; so does this.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case cli.Outbound <- tuntest.Ping(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.66.0.2")):
		default:
		}
		if ps, _ := devPeers(srv); len(ps) == 1 && ps[0].LastHandshake > 0 && ps[0].Rx > 0 {
			a.syncOnce(time.Now())
			if a.onlineOf(protoAWG)["u"] != 1 {
				t.Fatalf("not online: %v", a.onlineOf(protoAWG))
			}
			if su, _ := a.store.Get("u"); su.Up == 0 {
				t.Fatalf("traffic not counted: %+v", su)
			}
			// Blocked: the peer goes, and with it the session.
			a.store.Update("u", func(u *User) error { u.Enabled = false; return nil })
			a.syncOnce(time.Now())
			if ps, _ := devPeers(srv); len(ps) != 0 {
				t.Fatalf("blocked peer kept: %+v", ps)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	ps, _ := devPeers(srv)
	t.Fatalf("no handshake: %+v\nserver: %+v", ps, *c)
}

// TestAWGConfigsAccepted gives amneziawg-go many random server configs:
// each must pass its own checks (paddings, header ranges, keys).
func TestAWGConfigsAccepted(t *testing.T) {
	dev, _ := newTestDevice(t, newAWGConfig(freeUDP(t)).uapi())
	for i := 0; i < 300; i++ {
		c := newAWGConfig(0)
		if err := dev.IpcSet(c.uapi()); err != nil {
			t.Fatalf("%v\n%s", err, c.uapi())
		}
	}
}
