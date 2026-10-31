package main

import (
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

//go:embed hy-panel.service
var unitFile string

const (
	binPath    = "/usr/local/bin/hy-panel"
	envPath    = "/etc/hy-panel.env" // the panel's only settings file
	unitPath   = "/etc/systemd/system/hy-panel.service"
	dataDir    = "/var/lib/hy-panel"
	dataPath   = dataDir + "/users.json"
	panelAddr  = "127.0.0.1:8090"
	authURL    = "http://" + panelAddr + "/auth"
	statsAddr  = "127.0.0.1:25413"
	backupExt  = ".bak-hy-panel"
	defaultCfg = "/etc/hysteria/config.yaml"
	defaultSvc = "hysteria-server"
	installCmd = "bash <(curl -fsSL https://raw.githubusercontent.com/eonyushkin-commits/hy-panel/main/install.sh)"
)

// runInstall: `hy-panel install` puts the panel and its agent on the
// server, or updates the program. It asks nothing: protocols are installed
// and set up in the panel, users are created there. A re-run keeps the
// panel's settings and users.
func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	host := fs.String("host", "", "public IP/domain for client links (default: autodetect)")
	name := fs.String("name", "", "profile name prefix shown in clients")
	ui := fs.String("ui-port", "", "public HTTPS port for the panel UI, \"off\" = SSH tunnel only (default 9443)")
	fs.Parse(args)
	needRoot("install")

	env := readEnv()
	update := installed(env)
	setIf := func(key, v string) {
		if v != "" {
			env[key] = v
		}
	}
	setIf("HYP_HOST", *host)
	setIf("HYP_NAME", *name)
	setIf("HYP_UI_PORT", *ui)
	if env["HYP_HOST"] == "" {
		if env["HYP_HOST"] = publicIP(); env["HYP_HOST"] == "" {
			log.Fatal("✗ не удалось определить публичный IP (NAT?) — укажи -host <IP или домен>")
		}
	}
	if env["HYP_UI_PORT"] == "" {
		env["HYP_UI_PORT"] = "9443"
	}
	// Like 3x-ui: random password and a secret URL path, kept across re-runs.
	if env["HYP_PASSWORD"] == "" {
		env["HYP_PASSWORD"] = randStr(16)
	}
	if env["HYP_UI_PATH"] == "" {
		env["HYP_UI_PATH"] = "/" + strings.ToLower(randStr(12)) + "/"
	}
	if err := checkEnv(env); err != nil {
		log.Fatal("✗ ", err)
	}
	if update {
		fmt.Println("Панель уже установлена — обновляю программу; настройки, пользователи и ссылки не меняются.")
	} else {
		fmt.Println("Ставлю панель. Протоколы ставятся и настраиваются в ней: раздел «Протоколы».")
	}
	noInterrupt()
	step("binary → "+binPath, copySelf(binPath))
	step("settings → "+envPath, writeEnv(env))
	_, err := OpenStore(dataPath)
	step("user database "+dataPath, err)
	step("user "+panelUser, systemUser(panelUser, "", false))
	step("systemd unit → "+unitPath, os.WriteFile(unitPath, []byte(unitFile), 0o644))
	step("systemd unit → "+agentUnitPath, os.WriteFile(agentUnitPath, []byte(agentUnit), 0o644))
	if port := env["HYP_UI_PORT"]; port != "off" {
		_, _, err = panelCert(dataDir, env["HYP_HOST"])
		step("panel HTTPS certificate", err)
		ufwAllow(port + "/tcp")
	}
	step("systemd daemon-reload", systemctl("daemon-reload"))
	step("enable hy-panel-agent", systemctl("enable", "hy-panel-agent"))
	step("restart hy-panel-agent", systemctl("restart", "hy-panel-agent"))
	step("enable hy-panel", systemctl("enable", "hy-panel"))
	cfgPath, svc := hyPaths(env)
	b, readErr := os.ReadFile(cfgPath)
	if _, kind := classify(b, readErr); kind == cfgPanel {
		_, changed := rewriteHyConfig(cfgPath, b, false, nil)
		if changed {
			step("apply Hysteria ACL", systemctl("try-restart", svc))
		}
	}
	step("restart hy-panel", systemctl("restart", "hy-panel")) // picks up the new binary and config
	fmt.Println("\nГотово.")
	printInfo(env)
}

// runUninstall removes the panel. Users and settings stay, so installing
// again brings everything back with the same links; -purge deletes them
// too. The protocols' servers (Hysteria, Xray) stay installed. Nothing is
// asked: without -y it only says what it would do.
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("y", false, "really remove")
	purge := fs.Bool("purge", false, "also delete users, panel password and URL")
	fs.Parse(args)
	needRoot("uninstall")
	if !*yes {
		if *purge {
			fmt.Println("Удалит панель вместе с пользователями, паролем и адресом панели. Подтверди: hy-panel uninstall -purge -y")
		} else {
			fmt.Println("Удалит панель; пользователи и настройки сохранятся — после повторной установки всё вернётся как было. Подтверди: hy-panel uninstall -y")
		}
		return
	}
	env := readEnv()
	_, xraySvc := xrayPaths(env)
	vless := env["HYP_XRAY_CONFIG"] != ""
	if err := removePanel(); err != nil {
		log.Fatalf("✗ %v\nПанель удалена не полностью; пользователи и настройки не тронуты.", err)
	}
	fmt.Println("✓ панель удалена")
	if !*purge {
		fmt.Printf("Пользователи и настройки остались (%s, %s).\n", dataDir, envPath)
		fmt.Println("Пока панели нет, Hysteria не пускает новых клиентов: проверять пароли некому.")
		if vless {
			fmt.Println("Xray держит пользователей VLESS до своего перезапуска, после него — никого, пока панель не вернётся.")
		}
		if fileExists(awgCfgPath) {
			fmt.Println("AmneziaWG встроен в панель и остановлен вместе с ней; после установки поднимется с теми же конфигами клиентов.")
		}
		fmt.Println("Установить снова — всё вернётся как было:\n    " + installCmd)
		return
	}
	if vless {
		// The users are gone: so is their VLESS access, also before Xray's next restart.
		if err := systemctl("restart", xraySvc); err != nil { // not fatal: the purge must go on
			fmt.Printf("  ✗ %v\n", err)
		} else {
			fmt.Println("✓ restart " + xraySvc)
		}
	}
	step("remove "+dataDir, os.RemoveAll(dataDir))
	step("remove "+envPath, os.RemoveAll(envPath))
	step("remove "+awgCfgPath, os.RemoveAll(awgCfgPath)) // its clients were the panel's users
	fmt.Println("Удалено вместе с пользователями. Hysteria и Xray остались установленными, но без панели никого не пускают;")
	fmt.Println("если они не нужны: systemctl disable --now hysteria-server xray")
}

// removePanel stops the service and deletes its unit and binary. Things
// already gone are fine, so a repeated uninstall succeeds.
func removePanel() error {
	var errs []error
	if fileExists(unitPath) {
		errs = append(errs, systemctl("disable", "--now", "hy-panel"))
	}
	// The AmneziaWG server is this binary too: it goes with it.
	for _, u := range []string{agentUnitPath, awgUnitPath} {
		if fileExists(u) {
			errs = append(errs, systemctl("disable", "--now", strings.TrimSuffix(filepath.Base(u), ".service")))
		}
	}
	for _, f := range []string{unitPath, agentUnitPath, awgUnitPath, binPath} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	errs = append(errs, systemctl("daemon-reload"))
	return errors.Join(errs...)
}

// printInfo prints how to open the panel (the `hy-panel info` command).
func printInfo(env map[string]string) {
	host := env["HYP_HOST"]
	if port := env["HYP_UI_PORT"]; port != "" && port != "off" {
		_, fp, _ := panelCert(dataDir, host)
		fmt.Printf("Панель:  https://%s%s\n", net.JoinHostPort(host, port), env["HYP_UI_PATH"])
		fmt.Printf("         браузер предупредит о self-signed сертификате, это нормально\n         SHA-256: %s\n", fp)
	} else {
		fmt.Printf("Панель:  ssh -L 8090:%s root@%s, затем http://localhost:8090\n", panelAddr, host)
	}
	fmt.Printf("Пароль:  %s\n\nhy-panel info | passwd | uninstall\n", env["HYP_PASSWORD"])
}

// runPasswd sets a new random panel password (`hy-panel passwd`).
func runPasswd() {
	needRoot("passwd")
	env := readEnv()
	env["HYP_PASSWORD"] = randStr(16)
	step("new password → "+envPath, writeEnv(env))
	step("restart hy-panel", systemctl("restart", "hy-panel"))
	printInfo(env)
}

// ---- /etc/hy-panel.env ----

var envKeys = []string{"HYP_PASSWORD", "HYP_UI_PATH", "HYP_UI_PORT", "HYP_HOST", "HYP_NAME", "HYP_HY_CONFIG", "HYP_HY_SERVICE",
	"HYP_SUB_LISTEN", "HYP_SUB_URL", "HYP_XRAY_CONFIG", "HYP_XRAY_SERVICE"}

func readEnv() map[string]string {
	env := map[string]string{}
	b, err := os.ReadFile(envPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// Never take an unreadable file for "not installed": install would
		// then replace the panel password and URL.
		log.Fatalf("✗ %v", err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && !strings.HasPrefix(k, "#") {
			env[k] = v
		}
	}
	return env
}

func writeEnv(env map[string]string) error {
	var b strings.Builder
	for _, k := range envKeys {
		if env[k] != "" {
			fmt.Fprintf(&b, "%s=%s\n", k, env[k])
		}
	}
	return writeAtomic(envPath, []byte(b.String()), 0o600)
}

// checkEnv validates the settings before anything is written or served.
func checkEnv(env map[string]string) error {
	var errs []error
	bad := func(k, why string) { errs = append(errs, fmt.Errorf("%s=%q: %s", k, env[k], why)) }
	if p := env["HYP_UI_PORT"]; p != "" && p != "off" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			bad("HYP_UI_PORT", "нужен порт 1–65535 или off")
		}
	}
	if h := env["HYP_HOST"]; h != "" && net.ParseIP(strings.Trim(h, "[]")) == nil && !validHostname(h) {
		bad("HYP_HOST", "нужен IP или домен")
	}
	if p := env["HYP_UI_PATH"]; p != "" && (!strings.HasPrefix(p, "/") || strings.ContainsAny(p, " ?#%")) {
		bad("HYP_UI_PATH", "нужен путь вида /secret/")
	}
	if s := env["HYP_SUB_LISTEN"]; s != "" {
		if _, _, err := net.SplitHostPort(s); err != nil {
			bad("HYP_SUB_LISTEN", "нужен адрес вида :8443 или 127.0.0.1:8443")
		}
	}
	if s := env["HYP_SUB_URL"]; s != "" {
		if u, err := url.Parse(s); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			bad("HYP_SUB_URL", "нужен адрес вида https://sub.example.com")
		}
	}
	if s := env["HYP_XRAY_CONFIG"]; s != "" && !filepath.IsAbs(s) {
		bad("HYP_XRAY_CONFIG", "нужен абсолютный путь к конфигу Xray")
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%s: %w", envPath, err)
	}
	return nil
}

func validHostname(h string) bool {
	if len(h) > 253 || h == "" {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// noInterrupt keeps Ctrl+C or a dropped SSH session from stopping a command
// between writing the config and restarting the services.
func noInterrupt() { signal.Ignore(os.Interrupt, syscall.SIGHUP) }

// installed: this version's settings exist (v0.1 kept the host in its unit,
// so its leftover env file has no HYP_HOST).
func installed(env map[string]string) bool {
	return env["HYP_PASSWORD"] != "" && env["HYP_HOST"] != ""
}

// hyPaths returns the Hysteria config path and service name.
func hyPaths(env map[string]string) (cfg, svc string) {
	return envOr(env, "HYP_HY_CONFIG", defaultCfg), envOr(env, "HYP_HY_SERVICE", defaultSvc)
}

func envOr(env map[string]string, key, def string) string {
	if v := env[key]; v != "" {
		return v
	}
	return def
}

// ---- system helpers ----

func needRoot(cmd string) {
	log.SetFlags(0)
	if os.Geteuid() != 0 {
		log.Fatalf("run as root: sudo hy-panel %s", cmd)
	}
}

func step(what string, err error) {
	if err != nil {
		log.Fatalf("✗ %s: %v", what, err)
	}
	fmt.Println("✓", what)
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func unitExists(svc string) bool {
	for _, d := range []string{"/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/"} {
		if fileExists(d + svc + ".service") {
			return true
		}
	}
	return false
}

func copySelf(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if src == dst {
		return nil
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeAtomic(dst, b, 0o755) // rename: works while the old binary is running
}

var cgnat = &net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}

// publicIP returns the source address of the default route if it is public.
func publicIP() string {
	c, err := net.Dial("udp", "1.1.1.1:53") // no packet is sent
	if err != nil {
		return ""
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip) {
		return ""
	}
	return ip.String()
}

// backupOnce keeps the original of path: later runs don't overwrite it.
func backupOnce(path string, b []byte) error {
	if fileExists(path + backupExt) {
		return nil
	}
	return os.WriteFile(path+backupExt, b, 0o600)
}

// ufwAllow opens the rules when ufw is active.
func ufwAllow(rules ...string) {
	if out, err := exec.Command("ufw", "status").Output(); err != nil || !strings.Contains(string(out), "Status: active") {
		return
	}
	for _, r := range rules {
		step("ufw allow "+r, exec.Command("ufw", "allow", r).Run())
	}
}
