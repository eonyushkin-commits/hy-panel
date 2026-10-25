package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
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
	xrayURL     = "https://github.com/XTLS/Xray-core/releases/latest/download/"
)

const (
	hysteriaUnitPath = "/etc/systemd/system/hysteria-server.service"
	xrayUnitPath     = "/etc/systemd/system/xray.service"
	xrayDatDir       = "/usr/local/share/xray"
)

// The units the official installers write (get.hy2.sh, XTLS/Xray-install).
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

const xrayUnit = `[Unit]
Description=Xray Service
Documentation=https://xtls.github.io/
After=network.target nss-lookup.target

[Service]
User=xray
Group=xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
UMask=0077
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
RuntimeDirectory=xray
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
`

// runFetch: `hy-panel fetch hysteria|xray` installs or updates the official
// server from its GitHub release, checking the published SHA-256.
func runFetch(args []string) {
	needRoot("fetch")
	if len(args) != 1 {
		log.Fatal("usage: hy-panel fetch hysteria|xray")
	}
	switch args[0] {
	case "hysteria":
		step("hysteria "+hysteriaVersion().String(), fetchHysteria())
	case "xray":
		step("xray "+xrayVersion().String(), fetchXray())
	default:
		log.Fatal("usage: hy-panel fetch hysteria|xray")
	}
}

var httpGet = func(url string) ([]byte, error) {
	c := &http.Client{Timeout: 5 * time.Minute}
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
	fmt.Println("→ " + base + name)
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

// dgst reads Xray's <file>.dgst: "SHA2-256= <sha256>" among other digests.
func dgst(b []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "SHA2-256="); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", errors.New("в .dgst нет SHA2-256")
}

func fetchHysteria() error {
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		return fmt.Errorf("архитектура %s не поддерживается", runtime.GOARCH)
	}
	sums, err := httpGet(hysteriaURL + "hashes.txt")
	if err != nil {
		return err
	}
	bin, err := download(hysteriaURL, "hysteria-linux-"+arch, hashesTxt(sums))
	if err != nil {
		return err
	}
	if err := writeAtomic(hysteriaBin, bin, 0o755); err != nil {
		return err
	}
	if err := systemUser("hysteria", "/var/lib/hysteria", true); err != nil {
		return err
	}
	return installUnit(hysteriaUnitPath, hysteriaUnit)
}

func fetchXray() error {
	arch := map[string]string{"amd64": "64", "arm64": "arm64-v8a"}[runtime.GOARCH]
	if arch == "" {
		return fmt.Errorf("архитектура %s не поддерживается", runtime.GOARCH)
	}
	name := "Xray-linux-" + arch + ".zip"
	d, err := httpGet(xrayURL + name + ".dgst")
	if err != nil {
		return err
	}
	z, err := download(xrayURL, name, func(string) (string, error) { return dgst(d) })
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		return err
	}
	if err := systemUser("xray", "", false); err != nil {
		return err
	}
	if err := os.MkdirAll(xrayDatDir, 0o755); err != nil {
		return err
	}
	for name, dst := range map[string]string{"xray": xrayBin, "geoip.dat": xrayDatDir + "/geoip.dat", "geosite.dat": xrayDatDir + "/geosite.dat"} {
		b, err := zipFile(zr, name)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if name == "xray" {
			mode = 0o755
		}
		if err := writeAtomic(dst, b, mode); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(defaultXrayCfg), 0o755); err != nil {
		return err
	}
	if !fileExists(defaultXrayCfg) {
		// Like the installer: root:xray 0640, the config holds the Reality key.
		if err := os.WriteFile(defaultXrayCfg, []byte("{}\n"), 0o640); err != nil {
			return err
		}
		if _, gid := userIDs("xray"); gid != 0 {
			os.Chown(defaultXrayCfg, 0, gid)
		}
	}
	return installUnit(xrayUnitPath, xrayUnit)
}

func zipFile(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name == name {
			r, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer r.Close()
			return io.ReadAll(io.LimitReader(r, 200<<20))
		}
	}
	return nil, fmt.Errorf("в архиве нет %s", name)
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
