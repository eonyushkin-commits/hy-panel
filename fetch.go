package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Official releases. "latest" skips pre-releases, like the official installers.
var (
	hysteriaURL = "https://github.com/apernet/hysteria/releases/latest/download/"
)

const (
	hysteriaUnitPath = "/etc/systemd/system/hysteria-server.service"
)

// The unit used by the official Hysteria installer (get.hy2.sh).
const hysteriaUnit = `[Unit]
Description=Hysteria Server Service (config.yaml)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
WorkingDirectory=/var/lib/hysteria
User=hysteria
Group=hysteria
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`

// runFetch installs or updates the official Hysteria release after verifying SHA-256.
func runFetch(args []string) {
	needRoot("fetch")
	if len(args) != 1 || args[0] != "hysteria" {
		log.Fatal("usage: hy-panel fetch hysteria")
	}
	_, svc := hyPaths(readEnvNoFatal())
	updateServer("hysteria", svc, hysteriaVersion, fetchHysteria)
}

// updateServer installs the latest release and, if it is new, restarts the
// running service so it takes effect.
func updateServer(name, svc string, version func() hyVersion, fetch func() (bool, error)) {
	before := version()
	changed, err := fetch()
	step(name+": официальный релиз", err)
	if !changed {
		fmt.Printf("✓ %s %s — уже последняя версия, перезапуск не нужен\n", name, before)
		return
	}
	fmt.Printf("✓ %s: %s → %s\n", name, before, version())
	if systemctl("is-active", "--quiet", svc) == nil {
		step("restart "+svc, systemctl("restart", svc))
	}
}

var httpGet = func(url string) ([]byte, error) {
	fmt.Println("→ " + url)
	// Slow mirrors are fine, a dead connection is not: it fails in a minute.
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 30 * time.Second, ResponseHeaderTimeout: time.Minute,
		DialContext: (&net.Dialer{Timeout: 30 * time.Second}).DialContext}
	c := &http.Client{Timeout: 5 * time.Minute, Transport: tr}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

// download fetches name from base and checks it against the SHA-256 that
// sum (the release's checksum file, already parsed) gives for it.
func download(base, name string, sum func(name string) (string, error)) ([]byte, error) {
	b, err := httpGet(base + name)
	if err != nil {
		return nil, err
	}
	want, err := sum(name)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(b)
	if hex.EncodeToString(got[:]) != strings.ToLower(want) {
		return nil, fmt.Errorf("%s: SHA-256 не совпал с опубликованным", name)
	}
	fmt.Println("✓ SHA-256 " + name)
	return b, nil
}

// hashesTxt reads Hysteria's hashes.txt: "<sha256>  build/<file>" lines.
func hashesTxt(b []byte) func(string) (string, error) {
	return func(name string) (string, error) {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 2 && filepath.Base(f[1]) == name {
				return f[0], nil
			}
		}
		return "", fmt.Errorf("%s: нет в hashes.txt", name)
	}
}

// fetchHysteria installs the latest release; false if the installed binary
// is that release already (nothing is downloaded then).
func fetchHysteria() (bool, error) {
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		return false, fmt.Errorf("архитектура %s не поддерживается", runtime.GOARCH)
	}
	name := "hysteria-linux-" + arch
	sums, err := httpGet(hysteriaURL + "hashes.txt")
	if err != nil {
		return false, err
	}
	want, err := hashesTxt(sums)(name)
	if err != nil {
		return false, err
	}
	changed := true
	if cur, err := os.ReadFile(hysteriaBin); err == nil && sha256hex(cur) == strings.ToLower(want) {
		changed = false
	} else {
		bin, err := download(hysteriaURL, name, hashesTxt(sums))
		if err != nil {
			return false, err
		}
		if err := writeAtomic(hysteriaBin, bin, 0o755); err != nil {
			return false, err
		}
	}
	if err := systemUser("hysteria", "/var/lib/hysteria", true); err != nil {
		return false, err
	}
	return changed, installUnit(hysteriaUnitPath, hysteriaUnit)
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// installUnit writes a unit only if there is none: an existing one
// (from the official installer, or edited by hand) stays.
func installUnit(path, unit string) error {
	if fileExists(path) {
		return nil
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return err
	}
	return systemctl("daemon-reload")
}

// systemUser creates a system account without login, if missing.
func systemUser(name, home string, mkHome bool) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	args := []string{"--system", "--shell", "/usr/sbin/nologin", "--user-group"}
	if mkHome {
		args = append(args, "--home-dir", home, "--create-home")
	} else {
		args = append(args, "--no-create-home")
	}
	if out, err := exec.Command("useradd", append(args, name)...).CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %v %s", name, err, bytes.TrimSpace(out))
	}
	return nil
}

func userIDs(name string) (int, int) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0
	}
	var uid, gid int
	fmt.Sscan(u.Uid, &uid)
	fmt.Sscan(u.Gid, &gid)
	return uid, gid
}
