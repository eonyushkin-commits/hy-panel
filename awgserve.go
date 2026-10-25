package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/unix"
)

const awgUnit = `[Unit]
Description=hy-panel AmneziaWG 3.1 server (amneziawg-go)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/hy-panel awg-serve
RuntimeDirectory=hy-panel-awg
RuntimeDirectoryMode=0755
Restart=always
RestartSec=2
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
`

// Clients may not reach the server's private networks through the tunnel,
// as Xray's geoip:private rule keeps VLESS users out of them.
var awgBlocked = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"}

// uapi is the device part of the server config in amneziawg-go's UAPI form.
// I1 stays out: signature packets are the initiator's, i.e. the client's.
func (c *awgConfig) uapi() string {
	var b strings.Builder
	w := func(k string, v any) { fmt.Fprintf(&b, "%s=%v\n", k, v) }
	w("private_key", b64hex(c.PrivateKey))
	w("listen_port", c.Port)
	for _, kv := range []struct {
		k string
		v any
	}{{"jc", c.Jc}, {"jmin", c.Jmin}, {"jmax", c.Jmax}, {"s1", c.S1}, {"s2", c.S2}, {"s3", c.S3}, {"s4", c.S4},
		{"h1", c.H1}, {"h2", c.H2}, {"h3", c.H3}, {"h4", c.H4},
		{"header_protection_key", b64hex(c.HeaderProtectionKey)}, {"content_padding_addition", c.ContentPaddingAddition}} {
		w(kv.k, kv.v)
	}
	return b.String()
}

// runAWGServe is the AmneziaWG server (`hy-panel awg-serve`, service
// hy-panel-awg): the device, its address and NAT, and a control socket for
// the panel. Peers come only from the panel.
func runAWGServe() {
	log.SetFlags(0)
	c, err := readAWG(awgCfgPath)
	if err != nil {
		log.Fatalf("%s: %v", awgCfgPath, err)
	}
	tdev, err := tun.CreateTUN(awgIface, c.MTU)
	if err != nil {
		log.Fatalf("tun %s: %v", awgIface, err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg: "))
	if err := dev.IpcSet(c.uapi()); err != nil {
		dev.Close()
		log.Fatalf("awg config: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		log.Fatalf("awg up: %v", err)
	}
	awgNetDown() // leftovers of a crash
	if err := awgNetUp(); err != nil {
		awgNetDown()
		dev.Close()
		log.Fatalf("awg network: %v", err)
	}
	os.Remove(awgSock)
	l, err := net.Listen("unix", awgSock)
	if err != nil {
		log.Fatal(err)
	}
	_, gid := userIDs(panelUser)
	os.Chown(awgSock, 0, gid)
	os.Chmod(awgSock, 0o660)
	go server("", awgControl(dev)).Serve(l)
	log.Printf("awg: %s on udp :%d, %s", awgIface, c.Port, awgNet.String())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
	case <-dev.Wait():
	}
	l.Close()
	awgNetDown()
	dev.Close()
}

// awgControl is the control API the panel uses: the peers, and setting them.
func awgControl(dev *device.Device) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /peers", func(w http.ResponseWriter, r *http.Request) {
		ps, err := devPeers(dev)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, ps)
	})
	mux.HandleFunc("PUT /peers", func(w http.ResponseWriter, r *http.Request) {
		var want []awgPeer
		if err := json.NewDecoder(r.Body).Decode(&want); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := setPeers(dev, want); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// devPeers reads the device's peers from its UAPI dump.
func devPeers(dev *device.Device) ([]awgPeer, error) {
	s, err := dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parsePeers(s), nil
}

func parsePeers(s string) []awgPeer {
	var ps []awgPeer
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		if k == "public_key" {
			b, _ := hex.DecodeString(v)
			ps = append(ps, awgPeer{Key: base64.StdEncoding.EncodeToString(b)})
			continue
		}
		if len(ps) == 0 {
			continue // device keys
		}
		p := &ps[len(ps)-1]
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "rx_bytes":
			p.Rx = n
		case "tx_bytes":
			p.Tx = n
		case "last_handshake_time_sec":
			p.LastHandshake = n
		case "allowed_ip":
			p.IP = strings.TrimSuffix(v, "/32")
		}
	}
	return ps
}

// setPeers changes only what differs from want: peers that stay keep their
// sessions.
func setPeers(dev *device.Device, want []awgPeer) error {
	have, err := devPeers(dev)
	if err != nil {
		return err
	}
	var b strings.Builder
	cur := map[string]string{}
	for _, p := range have {
		cur[p.Key] = p.IP
	}
	keep := map[string]bool{}
	for _, p := range want {
		k, err := base64.StdEncoding.DecodeString(p.Key)
		ip := net.ParseIP(p.IP).To4()
		if err != nil || len(k) != 32 || ip == nil || !awgNet.Contains(ip) {
			return fmt.Errorf("peer %q %q", p.Key, p.IP)
		}
		keep[p.Key] = true
		if ip, ok := cur[p.Key]; ok && ip == p.IP {
			continue
		}
		fmt.Fprintf(&b, "public_key=%x\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", k, p.IP)
	}
	for _, p := range have {
		if !keep[p.Key] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", b64hex(p.Key))
		}
	}
	if b.Len() == 0 {
		return nil
	}
	return dev.IpcSet(b.String())
}

// ---- address, forwarding, NAT ----

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func haveCmd(name string) bool { _, err := exec.LookPath(name); return err == nil }

const awgChain = "HYP_AWG"

// ifUp gives the interface the server's address and brings it up, by
// ioctl: no iproute2 needed.
func ifUp(name string, ip net.IP, mask net.IPMask) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	set := func(req uint, what string, v []byte) error {
		ifr, err := unix.NewIfreq(name)
		if err == nil {
			err = ifr.SetInet4Addr(v)
		}
		if err == nil {
			err = unix.IoctlIfreq(fd, req, ifr)
		}
		if err != nil {
			return fmt.Errorf("%s %s: %v", name, what, err)
		}
		return nil
	}
	if err := set(unix.SIOCSIFADDR, "address", ip.To4()); err != nil {
		return err
	}
	if err := set(unix.SIOCSIFNETMASK, "netmask", net.IP(mask).To4()); err != nil {
		return err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func awgNetUp() error {
	server := awgNet.IP.To4()
	if err := ifUp(awgIface, net.IP{server[0], server[1], 0, 1}, awgNet.Mask); err != nil {
		return err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return err
	}
	src := awgNet.String()
	if haveCmd("iptables") {
		// iptables also when it is nft underneath: ufw and Docker drop
		// forwarded packets there, our rules must sit in the same chains.
		cmds := [][]string{
			{"-t", "nat", "-A", "POSTROUTING", "-s", src, "!", "-o", awgIface, "-j", "MASQUERADE"},
			{"-N", awgChain},
		}
		for _, n := range awgBlocked {
			cmds = append(cmds, []string{"-A", awgChain, "-d", n, "-j", "DROP"})
		}
		cmds = append(cmds, []string{"-A", awgChain, "-j", "ACCEPT"},
			[]string{"-I", "FORWARD", "-i", awgIface, "-j", awgChain},
			[]string{"-I", "FORWARD", "-o", awgIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"})
		for _, c := range cmds {
			if err := run("iptables", append([]string{"-w"}, c...)...); err != nil {
				return err
			}
		}
		return nil
	}
	rules := fmt.Sprintf(`table ip hy_panel_awg {
	chain postrouting { type nat hook postrouting priority srcnat; ip saddr %[1]s oifname != "%[2]s" masquerade; }
	chain forward {
		type filter hook forward priority filter;
		iifname "%[2]s" ip daddr { %[3]s } drop
		iifname "%[2]s" accept
		oifname "%[2]s" ct state related,established accept
	}
}
`, src, awgIface, strings.Join(awgBlocked, ", "))
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// awgNetDown removes the firewall rules; the interface goes with the device.
func awgNetDown() {
	if haveCmd("iptables") {
		ipt := func(args ...string) { run("iptables", append([]string{"-w"}, args...)...) }
		ipt("-t", "nat", "-D", "POSTROUTING", "-s", awgNet.String(), "!", "-o", awgIface, "-j", "MASQUERADE")
		ipt("-D", "FORWARD", "-i", awgIface, "-j", awgChain)
		ipt("-D", "FORWARD", "-o", awgIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		ipt("-F", awgChain)
		ipt("-X", awgChain)
		return
	}
	run("nft", "delete", "table", "ip", "hy_panel_awg")
}

// ---- hy-panel awg ----

// runAWG sets up the AmneziaWG server, or changes its port (`hy-panel awg`).
func runAWG(args []string) {
	fs := flag.NewFlagSet("awg", flag.ExitOnError)
	port := fs.Int("port", 0, "UDP port (default: a random one, 51000-59999)")
	yes := fs.Bool("y", false, "no questions")
	fs.Parse(args)
	needRoot("awg")
	env := readEnv()
	if !installed(env) {
		log.Fatal("✗ панель не установлена: сначала hy-panel install")
	}
	if *port != 0 && (*port < 1 || *port > 65535) {
		log.Fatalf("✗ -port %d: нужен 1–65535", *port)
	}
	p := newPrompter()
	if *yes {
		p.in = nil
	}
	c, err := readAWG(awgCfgPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		pt := *port
		if pt == 0 {
			pt = 51000 + rand.IntN(9000) // clear of Hysteria's hopping range 20000-50000
			if p.choose("Порт AmneziaWG (UDP):", []string{fmt.Sprintf("случайный: %d", pt), "свой"}, 0) == 1 {
				pt, _ = strconv.Atoi(p.port("Порт: "))
			}
		}
		awgPortFree(pt)
		c = newAWGConfig(pt)
		fmt.Printf("AmneziaWG 3.1: UDP %d, сеть клиентов %s.\n", pt, awgNet.String())
	case err != nil:
		log.Fatalf("✗ %s: %v", awgCfgPath, err)
	case *port != 0 && *port != c.Port:
		if !*yes && !p.yes(fmt.Sprintf("Сменить порт %d → %d? Клиентам нужны будут новые конфиги (QR в панели).", c.Port, *port), false) {
			fmt.Println("Отменено.")
			return
		}
		awgPortFree(*port)
		c.Port = *port
	default:
		fmt.Printf("AmneziaWG уже настроен: UDP %d — перезапускаю службу.\n", c.Port)
	}
	noInterrupt()
	step("awg config → "+awgCfgPath, c.write(awgCfgPath))
	step("systemd unit → "+awgUnitPath, os.WriteFile(awgUnitPath, []byte(awgUnit), 0o644))
	step("systemd daemon-reload", systemctl("daemon-reload"))
	ufwAllow(fmt.Sprintf("%d/udp", c.Port))
	ufwRoute(awgIface)
	step("enable hy-panel-awg", systemctl("enable", "hy-panel-awg"))
	step("restart hy-panel-awg", systemctl("restart", "hy-panel-awg"))
	step("restart hy-panel", systemctl("restart", "hy-panel")) // the panel puts its users in
	waitAWG()
	fmt.Printf("\nГотово. AmneziaWG 3.1 на UDP %d: конфиги и QR клиентов — в панели (кнопка QR → AmneziaWG).\n", c.Port)
}

// awgPortFree stops when something else listens on the UDP port.
func awgPortFree(port int) {
	if l, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port)); err == nil {
		l.Close()
	} else if systemctl("is-active", "--quiet", "hy-panel-awg") != nil {
		log.Fatalf("✗ порт %d/udp занят: посмотри, кем — ss -ulnp | grep ':%d '", port, port)
	}
}

// ufwRoute lets ufw forward the tunnel's traffic (its default forward policy drops it).
func ufwRoute(iface string) {
	if out, err := exec.Command("ufw", "status").Output(); err != nil || !strings.Contains(string(out), "Status: active") {
		return
	}
	step("ufw route allow in on "+iface, exec.Command("ufw", "route", "allow", "in", "on", iface).Run())
}

// waitAWG waits until the service answers and the panel has put its users in.
func waitAWG() {
	var list []User
	b, _ := os.ReadFile(dataPath)
	json.Unmarshal(b, &list)
	want := 0
	for _, u := range list {
		if u.Blocked(time.Now()) == "" && u.Uses(protoAWG) {
			want++
		}
	}
	cl := newAWGClient(awgSock)
	var ps []awgPeer
	var err error
	for i := 0; i < 40; i++ {
		if ps, err = cl.Peers(); err == nil && len(ps) >= want {
			step(fmt.Sprintf("awg: пользователей: %d", len(ps)), nil)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		log.Fatalf("✗ AmneziaWG не отвечает: %v\n  смотри: journalctl -u hy-panel-awg -n 30 --no-pager", err)
	}
	fmt.Printf("  ✗ в AmneziaWG %d из %d пользователей — смотри journalctl -u hy-panel -n 30 --no-pager\n", len(ps), want)
}
