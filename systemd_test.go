//go:build systemd

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in suite installs real services. Refuse existing installations and
// use only the explicitly supplied test binaries. Ordinary go test excludes it.
func TestSystemdLifecycle(t *testing.T) {
	if os.Getenv("HYP_SYSTEMD_SMOKE") != "1" {
		t.Skip("requires explicit HYP_SYSTEMD_SMOKE=1")
	}
	if os.Geteuid() != 0 {
		t.Fatal("systemd smoke verification requires root")
	}
	init, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(init)) != "systemd" {
		t.Fatal("systemd must run as PID 1")
	}
	candidate := os.Getenv("HYP_PANEL_BIN")
	for _, path := range []string{candidate, os.Getenv("HYSTERIA_BIN"), os.Getenv("XRAY_BIN")} {
		if !filepath.IsAbs(path) {
			t.Fatal("absolute binary paths required")
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("test binary unavailable: %s", path)
		}
	}
	smokeDir := "/run/hy-panel-smoke"
	owned := []string{binPath, envPath, unitPath, agentUnitPath, hysteriaBin, xrayBin, hysteriaUnitPath, xrayUnitPath, dataDir, agentStateDir, "/etc/hysteria", "/var/lib/hysteria", filepath.Dir(defaultXrayCfg), smokeDir, hysteriaUnitPath + ".d", xrayUnitPath + ".d"}
	for _, path := range owned {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refusing to touch existing path %s (use a clean test VM/WSL)", path)
		}
	}
	for _, addr := range []string{panelAddr, "127.0.0.1:25413"} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("test port is occupied: %s", addr)
		}
		l.Close()
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("journalctl", "--no-pager", "-n", "100", "-u", "hy-panel", "-u", "hy-panel-agent", "-u", defaultSvc, "-u", defaultXraySvc).CombinedOutput()
			t.Logf("systemd journal:\n%s", out)
		}
		_ = systemctl("disable", "--now", "hy-panel", "hy-panel-agent", defaultSvc, defaultXraySvc)
		for _, path := range owned {
			if err := os.RemoveAll(path); err != nil {
				t.Errorf("cleanup %s: %v", path, err)
			}
		}
		_ = systemctl("daemon-reload")
	})
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, candidate, args...).CombinedOutput()
		if password := readEnvNoFatal()["HYP_PASSWORD"]; password != "" {
			out = bytes.ReplaceAll(out, []byte(password), []byte("[test password]"))
		}
		return out, err
	}
	mustRun := func(args ...string) {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("hy-panel %v: %v\n%s", args, err, out)
		}
	}
	write := func(path string, b []byte, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(path, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{os.Getenv("HYSTERIA_BIN"), hysteriaBin}, {os.Getenv("XRAY_BIN"), xrayBin}} {
		b, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		write(pair[1], b, 0755)
	}
	if err := systemUser("hysteria", "/var/lib/hysteria", true); err != nil {
		t.Fatal(err)
	}
	if err := systemUser("xray", "", false); err != nil {
		t.Fatal(err)
	}
	write(hysteriaUnitPath, []byte(hysteriaUnit), 0644)
	write(xrayUnitPath, []byte(xrayUnit), 0644)
	if err := systemctl("daemon-reload"); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`[{"name":"legacy","password":"original-password","subToken":"original-token","enabled":true,"up":12}]`)
	write(dataPath, legacy, 0600)

	t.Log("install and migrate existing users")
	mustRun("install", "-host", "127.0.0.1", "-ui-port", "off")
	systemdWait(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return checkPanelReady(ctx) == nil
	})
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	request := func(method, path string, body any) (int, []byte, error) {
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		r, err := http.NewRequest(method, "http://"+panelAddr+path, bytes.NewReader(data))
		if err != nil {
			return 0, nil, err
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		res, err := client.Do(r)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		return res.StatusCode, b, err
	}
	mustRequest := func(method, path string, body any, code int) []byte {
		t.Helper()
		got, b, err := request(method, path, body)
		if err != nil || got != code {
			t.Fatalf("%s %s: code=%d err=%v body=%s", method, path, got, err, b)
		}
		return b
	}
	login := func() {
		mustRequest("POST", "/api/login", map[string]string{"password": readEnvNoFatal()["HYP_PASSWORD"]}, 204)
	}
	login()
	readState := func() struct {
		Users  []User
		Server struct {
			Port  string
			Vless *Vless
		}
	} {
		t.Helper()
		var state struct {
			Users  []User
			Server struct {
				Port  string
				Vless *Vless
			}
		}
		if err := json.Unmarshal(mustRequest("GET", "/api/state", nil, 200), &state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	state := readState()
	if len(state.Users) != 1 {
		t.Fatalf("migrated users: %d", len(state.Users))
	}
	original := state.Users[0]
	if original.Password != "original-password" || original.SubToken != "original-token" || original.UUID == "" || original.Up != 12 {
		t.Fatal("migration changed existing credentials/counters")
	}
	backup, err := os.ReadFile(dataPath + ".pre-v2")
	if err != nil || !bytes.Equal(backup, legacy) {
		t.Fatal("migration backup missing")
	}

	t.Log("start Hysteria and verify real root-agent access")
	hyPort := systemdPort(t, "udp")
	mustRun("settings", "-port", hyPort, "-cert", "self", "-obfs", "salamander")
	if readState().Server.Port != hyPort {
		t.Fatal("Hysteria settings did not become visible")
	}
	auth := mustRequest("POST", "/auth", map[string]string{"auth": "legacy:original-password"}, 200)
	if !bytes.Contains(auth, []byte(`"ok":true`)) {
		t.Fatalf("Hysteria authentication failed: %s", auth)
	}
	var started job
	if err := json.Unmarshal(mustRequest("POST", "/api/system/jobs", map[string]any{"action": "hysteria", "params": map[string]string{"port": hyPort}}, 200), &started); err != nil {
		t.Fatal(err)
	}
	systemdWait(t, func() bool {
		code, b, err := request("GET", "/api/system/job", nil)
		var j job
		if err != nil || code != 200 || json.Unmarshal(b, &j) != nil {
			return false
		}
		if j.ID == started.ID && !j.Running {
			if !j.OK {
				t.Fatalf("root agent failed: %s", j.Log)
			}
			return true
		}
		return false
	})
	if err := systemctl("restart", "hy-panel-agent"); err != nil {
		t.Fatal(err)
	}
	systemdWait(t, func() bool {
		code, b, err := request("GET", "/api/system/job", nil)
		var j job
		return err == nil && code == 200 && json.Unmarshal(b, &j) == nil && j.ID == started.ID && j.OK && !j.Running
	})

	rejectCandidate := func(cfg, svc, user string, args ...string) {
		t.Helper()
		before, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		envBefore, err := os.ReadFile(envPath)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := filepath.Join(smokeDir, user+"-config")
		write(snapshot, before, 0640)
		_, gid := userIDs(user)
		if err := os.Chown(snapshot, 0, gid); err != nil {
			t.Fatal(err)
		}
		unit := "/etc/systemd/system/" + svc + ".service"
		override := unit + ".d/hy-panel-smoke.conf"
		write(override, []byte(fmt.Sprintf("[Service]\nExecStartPre=/usr/bin/cmp -s %s %s\n", cfg, snapshot)), 0644)
		if err := systemctl("daemon-reload"); err != nil {
			t.Fatal(err)
		}
		if out, err := run(args...); err == nil {
			t.Fatalf("rejected configuration was accepted: %s", out)
		}
		after, _ := os.ReadFile(cfg)
		envAfter, _ := os.ReadFile(envPath)
		if !bytes.Equal(before, after) || !bytes.Equal(envBefore, envAfter) {
			t.Fatal("failed activation did not restore config and env")
		}
		for _, service := range []string{svc, "hy-panel"} {
			if err := systemctl("is-active", "--quiet", service); err != nil {
				t.Fatalf("service %s did not recover: %v", service, err)
			}
		}
		mustRequest("GET", "/api/state", nil, 200)
		if err := os.RemoveAll(unit + ".d"); err != nil {
			t.Fatal(err)
		}
		if err := systemctl("daemon-reload"); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("reject Hysteria candidate and recover previous configuration")
	rejectCandidate(defaultCfg, defaultSvc, "hysteria", "settings", "-port", systemdPort(t, "udp"))

	t.Log("start Xray with a local Reality target and managed users")
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "local Reality target") }))
	site.EnableHTTP2 = true
	site.StartTLS()
	defer site.Close()
	d, err := parseXrayDoc(freshXray(systemdPort(t, "tcp"), "www.example.org"))
	if err != nil {
		t.Fatal(err)
	}
	d.root.sub("api").set("listen", "127.0.0.1:"+systemdPort(t, "tcp"))
	d.inbound().sub("streamSettings").sub("realitySettings").set("target", strings.TrimPrefix(site.URL, "https://"))
	d.root.set("routing", newObj())
	b, err := d.bytes()
	if err != nil {
		t.Fatal(err)
	}
	write(defaultXrayCfg, b, 0640)
	_, gid := userIDs("xray")
	if err := os.Chown(defaultXrayCfg, 0, gid); err != nil {
		t.Fatal(err)
	}
	env := readEnvNoFatal()
	env["HYP_XRAY_CONFIG"] = defaultXrayCfg
	if err := writeEnv(env); err != nil {
		t.Fatal(err)
	}
	if err := systemctl("start", defaultXraySvc); err != nil {
		t.Fatal(err)
	}
	if err := systemctl("restart", "hy-panel"); err != nil {
		t.Fatal(err)
	}
	xs, err := readXray(defaultXrayCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitXrayReady(xs); err != nil {
		t.Fatal(err)
	}
	newVlessPort := systemdPort(t, "tcp")
	mustRun("xray", "-target", "www.example.org", "-port", newVlessPort)
	if v := readState().Server.Vless; v == nil || v.Port != newVlessPort {
		t.Fatal("VLESS settings did not become visible")
	}
	rejectCandidate(defaultXrayCfg, defaultXraySvc, "xray", "xray", "-target", "www.example.org", "-port", systemdPort(t, "tcp"))

	t.Log("Xray update activation refreshes panel client capabilities")
	panelPID := func() string {
		t.Helper()
		out, err := exec.Command("systemctl", "show", "hy-panel", "-p", "MainPID", "--value").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	beforePID := panelPID()
	// Exercise post-download activation with the verified binary already staged.
	if err := applyServerUpdate("xray", defaultXraySvc, xrayVersion, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	if after := panelPID(); after == "0" || after == beforePID {
		t.Fatal("panel did not refresh after Xray update")
	}
	mustRequest("GET", "/api/state", nil, 200)

	t.Log("password change revokes old session and reinstall preserves users")
	mustRun("passwd")
	systemdWait(t, func() bool { code, _, err := request("GET", "/api/state", nil); return err == nil && code == 401 })
	login()
	mustRun("uninstall", "-y")
	if b, err := os.ReadFile(dataPath); err != nil || len(b) == 0 {
		t.Fatal("uninstall lost retained users")
	}
	mustRun("install", "-host", "127.0.0.1", "-ui-port", "off")
	systemdWait(t, func() bool { code, _, err := request("GET", "/api/state", nil); return err == nil && code == 200 })
	final := readState().Users
	if len(final) != 1 || final[0].UUID != original.UUID || final[0].Password != original.Password || final[0].SubToken != original.SubToken || final[0].Up != original.Up {
		t.Fatal("reinstall changed user credentials/counters")
	}
	u, _ := url.Parse("http://" + panelAddr)
	oldCookies := jar.Cookies(u)
	mustRequest("POST", "/api/logout", nil, 204)
	if err := systemctl("restart", "hy-panel"); err != nil {
		t.Fatal(err)
	}
	systemdWait(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return checkPanelReady(ctx) == nil
	})
	copied, _ := http.NewRequest("GET", "http://"+panelAddr+"/api/state", nil)
	for _, c := range oldCookies {
		copied.AddCookie(c)
	}
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(copied)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("copied session survived logout/restart")
	}
}

func systemdPort(t *testing.T, network string) string {
	t.Helper()
	var addr string
	if network == "udp" {
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = l.LocalAddr().String()
		l.Close()
	} else {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = l.Addr().String()
		l.Close()
	}
	_, port, _ := net.SplitHostPort(addr)
	return port
}

func systemdWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for systemd/API")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
