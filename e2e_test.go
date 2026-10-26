//go:build e2e

// End-to-end with the real binaries, not run in CI:
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
	"testing"
	"time"
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
	cmd := exec.Command(name, args...)
	out, _ := os.Create(filepath.Join(t.TempDir(), "log"))
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(out.Name())
			t.Logf("%s log:\n%s", filepath.Base(name), b)
		}
	})
	return cmd
}

func TestE2EXray(t *testing.T) {
	xray := os.Getenv("XRAY_BIN")
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
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			<-hold
		}
		io.WriteString(w, strings.Repeat("x", 100000))
	}))
	defer page.Close()

	// freshXray, pointed at the local site and free ports; no geoip.dat here.
	vport, aport := freePort(t), freePort(t)
	d, err := parseXrayDoc(freshXray(vport, "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	d.root.sub("api").set("listen", "127.0.0.1:"+aport)
	d.inbound().sub("streamSettings").sub("realitySettings").set("target", strings.TrimPrefix(site.URL, "https://"))
	d.root.set("routing", newObj())
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
	a := testApp(t, nil)
	xb := &xrayBackend{api: newXrayAPI(xs.API), tag: xs.Tag, flow: xs.Link.Flow}
	a.addBackend(xb)
	// Xray does not count 127.0.0.1 as online: clients come from another local address.
	host := "127.0.0.1"
	if addrs, _ := net.InterfaceAddrs(); addrs != nil {
		for _, ad := range addrs {
			if ip, _, _ := net.ParseCIDR(ad.String()); ip.To4() != nil && !ip.IsLoopback() {
				host = ip.String()
				break
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
	users, err := xb.api.Users(xs.Tag)
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
		close(hold)
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
