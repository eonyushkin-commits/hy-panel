//go:build e2e

// End-to-end with the real binaries (also run by verify.yml):
//
//	XRAY_BIN=/path/to/xray MIHOMO_BIN=/path/to/mihomo go test -tags e2e -run E2E -v
//
// Xray serves VLESS + Reality + XHTTP from a config made by freshXray, a local
// TLS 1.3 site plays the Reality target, and mihomo connects with the
// panel's own mihomo snippet.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

func waitTCP(t *testing.T, addr string) {
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s does not listen", addr)
}

func start(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := os.Create(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		out.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		out.Close()
		if t.Failed() {
			b, _ := os.ReadFile(out.Name())
			t.Logf("%s log:\n%s", filepath.Base(name), b)
		}
	})
	return cmd
}

func TestE2EXray(t *testing.T) {
	t.Run("current", func(t *testing.T) { testE2EXray(t, os.Getenv("XRAY_BIN")) })
	if minimum := os.Getenv("XRAY_MINIMUM_BIN"); minimum != "" {
		t.Run("minimum", func(t *testing.T) { testE2EXray(t, minimum) })
	}
}

func testE2EXray(t *testing.T, xray string) {
	if xray == "" {
		t.Skip("XRAY_BIN not set")
	}
	dir := t.TempDir()

	// The site Reality impersonates (httptest's cert is for example.com) and
	// a page to fetch through the tunnel.
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "decoy") }))
	site.EnableHTTP2 = true
	site.StartTLS()
	defer site.Close()
	hold := make(chan struct{})
	var releaseOnce sync.Once
	releaseHold := func() { releaseOnce.Do(func() { close(hold) }) }
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			<-hold
		}
		io.WriteString(w, strings.Repeat("x", 100000))
	}))
	defer func() { releaseHold(); page.Close() }()

	// freshXray, pointed at the local site and free ports; no geoip.dat here.
	vport, aport := freePort(t), freePort(t)
	d, err := parseXrayDoc(freshXray(vport, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	d.root.sub("api").set("listen", "127.0.0.1:"+aport)
	d.inbound().sub("streamSettings").sub("realitySettings").set("target", strings.TrimPrefix(site.URL, "https://"))
	d.root.set("routing", newObj())
	// The integration page is local. New Xray versions block private targets in
	// freedom by default; allow only this test's loopback HTTP destination.
	d.root.set("outbounds", []any{map[string]any{"protocol": "freedom", "tag": "direct", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}})
	cfg, _ := d.bytes()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, cfg, 0o644)
	if out, err := exec.Command(xray, "run", "-test", "-c", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("xray -test: %v\n%s", err, out)
	}
	srv := start(t, xray, "run", "-c", cfgPath)
	waitTCP(t, "127.0.0.1:"+aport)

	xs, err := readXray(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	versionOutput, err := exec.Command(xray, "version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	xs.Link.setServerVersion(parseVersion(xrayVersionRe, versionOutput))
	a := testApp(t, nil)
	xb := &xrayBackend{api: newXrayAPI(xs.API), tag: xs.Tag, flow: xs.Link.Flow}
	a.addBackend(xb)
	// Xray does not count 127.0.0.1 as online: clients come from another local address.
	host := "127.0.0.1"
	interfaces, _ := net.Interfaces()
chooseHost:
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, ad := range addrs {
			if ip, _, _ := net.ParseCIDR(ad.String()); ip.To4() != nil && !ip.IsLoopback() {
				host = ip.String()
				break chooseHost
			}
		}
	}
	t.Logf("clients connect to %s", host)
	a.ep = Endpoint{Host: host, Port: "1", Name: "T", Vless: &xs.Link} // Hysteria: a placeholder
	alice := mustCreate(t, a.store, User{Name: "alice"})
	mustCreate(t, a.store, User{Name: "bob"})
	sync := func() {
		a.syncOnce(time.Now())
		if syncState(a, protoVless).err != "" {
			t.Fatalf("xray sync: %s", syncState(a, protoVless).err)
		}
	}
	sync()
	users, err := xb.api.usersContext(context.Background(), xs.Tag)
	if err != nil || len(users) != 2 || users["alice"] != alice.UUID {
		t.Fatalf("users in xray: %v %v", users, err)
	}

	// A probe without the key gets the impersonated site, certificate and all.
	tlsCfg := site.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tlsCfg.ServerName = "example.com"
	probe := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, "127.0.0.1:"+vport)
		},
	}}
	resp, err := probe.Get("https://example.com/")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "decoy" || resp.ProtoMajor != 2 {
		t.Fatalf("probe got %s %q", resp.Proto, body)
	}

	mihomo := os.Getenv("MIHOMO_BIN")
	if mihomo == "" {
		t.Skip("MIHOMO_BIN not set: client part skipped")
	}
	// mihomo with the panel's snippet, as a router would use it.
	mport := freePort(t)
	mcfg := fmt.Sprintf("mixed-port: %s\nmode: rule\nlog-level: info\n%s\nrules:\n  - MATCH,%s\n", mport, a.ep.MihomoDoc(alice), "T-alice-vless")
	os.WriteFile(filepath.Join(dir, "mihomo.yaml"), []byte(mcfg), 0o600)
	start(t, mihomo, "-d", dir, "-f", filepath.Join(dir, "mihomo.yaml"))
	waitTCP(t, "127.0.0.1:"+mport)
	purl, _ := url.Parse("http://127.0.0.1:" + mport)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(purl), DisableKeepAlives: true}}
	get := func() error {
		resp, err := client.Get(page.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		n, _ := io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != 200 || n != 100000 {
			return fmt.Errorf("status %s, %d bytes", resp.Status, n)
		}
		return nil
	}
	if err := get(); err != nil {
		t.Fatalf("through vless: %v", err)
	}
	sync()
	if u, _ := a.store.Get("alice"); u.Down < 100000 || u.Up == 0 {
		t.Fatalf("traffic not counted: %+v", u)
	}
	if host != "127.0.0.1" {
		done := make(chan error)
		go func() { done <- get2(client, page.URL+"/hold") }()
		time.Sleep(500 * time.Millisecond)
		sync()
		releaseHold()
		<-done
		if a.onlineOf(protoVless)["alice"] != 1 {
			t.Fatalf("online while connected: %v", a.onlineOf(protoVless))
		}
	}

	// Disabled: out of Xray, new connections refused.
	a.store.Update("alice", func(u *User) error { u.Enabled = false; return nil })
	sync()
	if err := get(); err == nil {
		t.Fatal("disabled user still connects")
	}
	// Xray restarted with no users in its config: the next sync puts them back.
	a.store.Update("alice", func(u *User) error { u.Enabled = true; return nil })
	srv.Process.Kill()
	srv.Wait()
	start(t, xray, "run", "-c", cfgPath)
	waitTCP(t, "127.0.0.1:"+aport)
	sync()
	if err := get(); err != nil {
		t.Fatalf("after xray restart: %v", err)
	}
}

func get2(c *http.Client, u string) error {
	resp, err := c.Get(u)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return err
}

// TestE2EMihomoFull has mihomo check both full configs: the template, the
// panel's proxies of every protocol and the rule it adds.
func TestE2EMihomoFull(t *testing.T) {
	mihomo := os.Getenv("MIHOMO_BIN")
	if mihomo == "" {
		t.Skip("MIHOMO_BIN not set")
	}
	xs, _ := parseXray(freshXray("443", "lurkpro.tech"))
	ci := certInfo{Pin: strings.Repeat("ab", 32)}
	e := buildEndpoint(&hyConfig{Listen: ":443"}, ci, "", "203.0.113.7", "NL")
	e.Vless = &xs.Link
	u := User{Name: "u", Password: "secret123", UUID: newUUID(), SubToken: "tok"}
	for _, router := range []bool{true, false} {
		b, err := e.MihomoFull(mihomoBuiltin, u, router)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		f := filepath.Join(dir, "config.yaml")
		os.WriteFile(f, b, 0o600)
		if out, err := exec.Command(mihomo, "-t", "-d", dir, "-f", f).CombinedOutput(); err != nil || !strings.Contains(string(out), "test is successful") {
			t.Fatalf("router=%v: %v\n%s", router, err, out)
		}
	}
}

func TestE2EHysteria(t *testing.T) {
	hysteria, mihomo := os.Getenv("HYSTERIA_BIN"), os.Getenv("MIHOMO_BIN")
	if hysteria == "" || mihomo == "" {
		t.Skip("HYSTERIA_BIN and MIHOMO_BIN required")
	}
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := newSelfSigned(crt, key, "example.com"); err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := udp.LocalAddr().String()
	udp.Close()
	statsAddr := "127.0.0.1:" + freePort(t)
	a := testApp(t, newStatsClient(statsAddr, "integration-secret"))
	auth := httptest.NewServer(a.routes(true))
	defer auth.Close()
	doc := map[string]any{
		"listen":       listen,
		"tls":          map[string]string{"cert": crt, "key": key},
		"auth":         map[string]any{"type": "http", "http": map[string]string{"url": auth.URL + "/auth"}},
		"trafficStats": map[string]string{"listen": statsAddr, "secret": "integration-secret"},
		"obfs":         map[string]any{"type": "salamander", "salamander": map[string]string{"password": "integration-obfuscation"}},
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "hysteria.yaml")
	if err = os.WriteFile(config, b, 0600); err != nil {
		t.Fatal(err)
	}
	start(t, hysteria, "server", "--config", config)
	waitTCP(t, statsAddr)
	cfg, err := parseHyConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := readCert(crt)
	if err != nil {
		t.Fatal(err)
	}
	a.ep = buildEndpoint(cfg, cert, "", "127.0.0.1", "HY")
	u := mustCreate(t, a.store, User{Name: "phone"})
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("h", 100000)) }))
	defer page.Close()
	clientPort := freePort(t)
	clientCfg := fmt.Sprintf("mixed-port: %s\nmode: rule\nlog-level: info\n%s\nrules:\n  - MATCH,HY-phone\n", clientPort, a.ep.MihomoDoc(u))
	clientPath := filepath.Join(dir, "mihomo.yaml")
	if err = os.WriteFile(clientPath, []byte(clientCfg), 0600); err != nil {
		t.Fatal(err)
	}
	start(t, mihomo, "-d", dir, "-f", clientPath)
	waitTCP(t, "127.0.0.1:"+clientPort)
	proxy, _ := url.Parse("http://127.0.0.1:" + clientPort)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	response, err := client.Get(page.URL)
	if err != nil {
		t.Fatal(err)
	}
	n, readErr := io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || n != 100000 {
		t.Fatalf("tunnel: code=%d bytes=%d error=%v", response.StatusCode, n, readErr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		a.syncOnce(time.Now())
		current, _ := a.store.Get(u.Name)
		if current.Down >= 100000 && current.Up > 0 && a.onlineOf(protoHy2)[u.Name] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("traffic/online not accounted: up=%d down=%d online=%v", current.Up, current.Down, a.onlineOf(protoHy2))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err = a.store.Update(u.Name, func(u *User) error { u.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	a.syncOnce(time.Now())
	if ok, _, _ := a.authorize(u.Name + ":" + u.Password); ok {
		t.Fatal("disabled Hysteria user still authenticates")
	}
}
