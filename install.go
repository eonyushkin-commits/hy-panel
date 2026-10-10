package main

import (
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed hy-panel.service
var unitFile string

const (
	binPath    = "/usr/local/bin/hy-panel"
	envPath    = "/etc/hy-panel.env" // the panel's only settings file
	unitPath   = "/etc/systemd/system/hy-panel.service"
	dataDir    = "/var/lib/hy-panel"
	dataPath   = dataDir + "/users.json"
	authPath   = dataDir + "/hysteria-auth.yaml" // Hysteria's own auth before the panel, for -purge
	panelAddr  = "127.0.0.1:8090"
	authURL    = "http://" + panelAddr + "/auth"
	statsAddr  = "127.0.0.1:25413"
	backupExt  = ".bak-hy-panel"
	defaultCfg = "/etc/hysteria/config.yaml"
	defaultSvc = "hysteria-server"
	installCmd = "bash <(curl -fsSL https://raw.githubusercontent.com/eonyushkin-commits/hy-panel/main/install.sh)"
)

// facts is what install finds on the host. Whether Hysteria runs is not a
// fact here on purpose: it may only decide whether to restart it.
type facts struct {
	installed bool    // /etc/hy-panel.env of this version exists: this is an update
	v01       bool    // a v0.1 unit (ExecStart with flags)
	kind      cfgKind // Hysteria config, by content
	hysteria  bool    // official Hysteria binary and unit are present
}

// plan is what install does.
type plan struct {
	update  bool // re-run: panel settings and users stay, nothing is asked about them
	fresh   bool // write the Hysteria config from the answers
	connect bool // point the config's own auth at the panel, import its users
}

func planInstall(f facts) (plan, error) {
	if err := kindErr(f.kind); err != nil {
		return plan{}, err
	}
	switch {
	case f.v01:
		return plan{}, errors.New("стоит прежняя hy-panel v0.1 — сначала удали её: hy-panel uninstall")
	case f.kind == cfgNone && !f.hysteria:
		return plan{}, errors.New("Hysteria не установлена. Сначала официальный установщик:\n    bash <(curl -fsSL https://get.hy2.sh/)\n  затем снова установи панель")
	case f.kind == cfgNone:
		// No working config (first install, or it was deleted or reset to
		// the template): ask and write one. Panel settings stay as they are.
		return plan{update: f.installed, fresh: true}, nil
	}
	return plan{update: f.installed, connect: f.kind == cfgOwnAuth}, nil
}

// runInstall: `hy-panel install`. The first run connects the panel to
// Hysteria (or sets Hysteria up); every later run only updates the program.
func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	hyCfg := fs.String("hy-config", "", "Hysteria 2 server config (default "+defaultCfg+")")
	hySvc := fs.String("hy-service", "", "Hysteria systemd service (default "+defaultSvc+")")
	host := fs.String("host", "", "public IP/domain for client links (default: autodetect)")
	name := fs.String("name", "", "profile name prefix shown in clients")
	ui := fs.String("ui-port", "", "public HTTPS port for the panel UI, \"off\" = SSH tunnel only (default: ask)")
	hyPort := fs.String("hy-port", "", "UDP port or range for a new Hysteria config (default: ask)")
	fs.Parse(args)
	needRoot("install")

	env := readEnv()
	setIf := func(key, v string) {
		if v != "" {
			env[key] = v
		}
	}
	setIf("HYP_HY_CONFIG", *hyCfg)
	setIf("HYP_HY_SERVICE", *hySvc)
	cfgPath, svc := hyPaths(env)
	orig, readErr := os.ReadFile(cfgPath)
	cfg, kind := classify(orig, readErr)
	unit, _ := os.ReadFile(unitPath)
	pl, err := planInstall(facts{
		installed: installed(env),
		v01:       bytes.Contains(unit, []byte("hy-panel -")),
		kind:      kind,
		hysteria:  fileExists(hysteriaBin) && unitExists(svc),
	})
	if err != nil {
		log.Fatal("✗ ", err)
	}

	p := newPrompter()
	var opts hyOpts
	setIf("HYP_HOST", *host)
	setIf("HYP_NAME", *name)
	setIf("HYP_UI_PORT", *ui)
	if env["HYP_HOST"] == "" {
		if env["HYP_HOST"] = publicIP(); env["HYP_HOST"] == "" {
			log.Fatal("✗ не удалось определить публичный IP (NAT?) — укажи -host <IP или домен>")
		}
	}
	switch {
	case pl.fresh:
		fmt.Printf("Hysteria (%s) ещё не настроена — настроим её.\n", svc)
		opts = askHyOpts(p, nil, *hyPort, env["HYP_HOST"])
		if opts.Domain != "" && *host == "" {
			env["HYP_HOST"] = opts.Domain
		}
	case pl.update:
		fmt.Println("Панель уже установлена — обновляю программу; настройки, пользователи и ссылки не меняются.")
	default:
		fmt.Printf("Hysteria (%s) настроена — подключаю к ней панель: меняю в конфиге только auth и trafficStats.\n", svc)
	}
	if !pl.update && env["HYP_UI_PORT"] == "" {
		switch p.choose("Доступ к панели:", []string{
			"HTTPS на порту 9443",
			"HTTPS на случайном порту",
			"только через SSH-туннель",
		}, 0) {
		case 0:
			env["HYP_UI_PORT"] = "9443"
		case 1:
			env["HYP_UI_PORT"] = strconv.Itoa(10000 + mrand.IntN(50000))
		default:
			env["HYP_UI_PORT"] = "off"
		}
	}
	// Like 3x-ui: random password and a secret URL path, kept across re-runs.
	if env["HYP_PASSWORD"] == "" {
		env["HYP_PASSWORD"] = randStr(16)
	}
	if env["HYP_UI_PATH"] == "" {
		env["HYP_UI_PATH"] = "/" + strings.ToLower(randStr(12)) + "/"
	}

	step("binary → "+binPath, copySelf(binPath))
	step("settings → "+envPath, writeEnv(env))
	store, err := OpenStore(dataPath)
	step("user database "+dataPath, err)

	// Hysteria config: only what the plan says. An existing setup keeps its
	// port, obfs and certificate, so client links never change here.
	var edit func(*yamlDoc) error
	switch old := cfg; {
	case pl.fresh:
		edit = func(d *yamlDoc) error { return applyOpts(d, old, nil, opts, filepath.Dir(cfgPath)) }
	case pl.connect:
		// The config's current auth is Hysteria's own: keep it for -purge
		// and bring its users over (existing panel users stay as they are).
		importUsers(store, old)
		edit = func(d *yamlDoc) error { return saveOwnAuth(d, authPath) }
	}
	cfg, changed := rewriteHyConfig(cfgPath, orig, pl.fresh, edit)
	var created []User
	if !pl.update {
		created = askUsers(store, p) // before the service owns the file
	}

	step("systemd unit → "+unitPath, os.WriteFile(unitPath, []byte(unitFile), 0o644))
	if port := env["HYP_UI_PORT"]; port != "off" {
		_, _, err = panelCert(dataDir, env["HYP_HOST"])
		step("panel HTTPS certificate", err)
		ufwAllow(port + "/tcp")
	}
	step("systemd daemon-reload", systemctl("daemon-reload"))
	step("enable hy-panel", systemctl("enable", "hy-panel"))
	step("restart hy-panel", systemctl("restart", "hy-panel")) // picks up the new binary

	if pl.fresh {
		ufwAllow(opts.firewallRules()...)
		step("enable "+svc, systemctl("enable", svc))
	}
	// Restart Hysteria only if its config changed now, or it does not run
	// that config yet (a previous run stopped half-way, or Hysteria is down).
	if changed || !reachable(cfg) {
		step("restart "+svc, systemctl("restart", svc))
	}
	waitHysteria(cfg, svc, opts.Domain != "")

	fmt.Println("\nГотово.")
	printInfo(env)
	ep := endpointFor(cfg, env)
	for _, u := range created {
		uri := ep.URI(u)
		fmt.Printf("\n%s — ссылка для клиента:\n%s\n", u.Name, uri)
		if q, err := qrcode.New(uri, qrcode.Low); err == nil {
			fmt.Print(q.ToSmallString(false))
		}
	}
}

// saveOwnAuth keeps the config's own auth (and trafficStats, if any), so
// `uninstall -purge` can give it back.
func saveOwnAuth(d *yamlDoc, path string) error {
	keep, _ := parseDoc(nil)
	for _, k := range []string{"auth", "trafficStats"} {
		if n := d.get(k); n != nil {
			keep.set(k, n)
		}
	}
	b, err := keep.bytes()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func importUsers(s *Store, c *hyConfig) {
	add := func(name, pass string) {
		if _, ok := s.Get(strings.ToLower(name)); ok {
			return // already in the panel
		}
		if _, err := s.Create(User{Name: name, Password: pass, Enabled: true, Note: "imported"}, true); err != nil {
			fmt.Printf("  ✗ импорт %q: %v\n", name, err)
		} else {
			fmt.Printf("✓ пользователь %q перенесён из конфига Hysteria — его клиенты работают дальше\n", name)
		}
	}
	switch c.Auth.Type {
	case "password":
		if c.Auth.Password != "" {
			add("default", c.Auth.Password)
		}
	case "userpass":
		for n, p := range c.Auth.UserPass {
			add(n, p)
		}
	}
}

// askUsers offers to create users; without a terminal it creates nothing.
func askUsers(store *Store, p *prompter) []User {
	if p.in == nil {
		return nil
	}
	var out []User
	q, def := "\nСоздать пользователя?", store.Empty()
	if !def {
		q = "\nСоздать ещё пользователя?"
	}
	for p.yes(q, def) {
		for {
			n := p.line("Имя (a-z 0-9 _ . -): ", "")
			if n == "" {
				break
			}
			u, err := store.Create(User{Name: n, Enabled: true}, false)
			if err != nil {
				fmt.Println("  ✗", err)
				continue
			}
			fmt.Println("✓ пользователь", u.Name)
			out = append(out, u)
			break
		}
		q, def = "Создать ещё пользователя?", false
	}
	return out
}

// runUninstall removes the panel. Users and settings stay, so installing
// again brings everything back with the same links; -purge deletes them too.
// Hysteria's port, obfs and certificate are never touched.
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("y", false, "do not ask")
	purge := fs.Bool("purge", false, "also delete users, panel password and URL")
	fs.Parse(args)
	needRoot("uninstall")
	q := "Удалить панель? Пользователи и настройки сохранятся — после повторной установки всё вернётся как было"
	if *purge {
		q = "Удалить панель вместе с пользователями, паролем и адресом панели?"
	}
	if !*yes {
		p := newPrompter()
		if p.in == nil {
			log.Fatal("✗ нет терминала: подтверди флагом -y")
		}
		if !p.yes(q, false) {
			fmt.Println("Отменено.")
			return
		}
	}
	env := readEnv()
	cfgPath, svc := hyPaths(env)
	systemctl("disable", "--now", "hy-panel")
	os.Remove(unitPath)
	systemctl("daemon-reload")
	os.Remove(binPath)
	fmt.Println("✓ панель удалена")
	if !*purge {
		fmt.Printf("Пользователи и настройки остались (%s, %s).\n", dataDir, envPath)
		fmt.Println("Пока панели нет, Hysteria не пускает новых клиентов: проверять пароли некому.")
		fmt.Println("Установить снова — всё вернётся как было:\n    " + installCmd)
		return
	}
	if restored, err := restoreOwnAuth(cfgPath, authPath); err != nil {
		fmt.Printf("  ✗ вернуть auth в %s: %v\n", cfgPath, err)
	} else if restored {
		step("restart "+svc, systemctl("restart", svc))
		fmt.Println("✓ в конфиге Hysteria снова её собственный auth — прежние клиенты работают без панели")
	} else {
		fmt.Printf("• своего auth до панели у Hysteria не было: %s остаётся как есть\n", cfgPath)
	}
	step("remove "+dataDir, os.RemoveAll(dataDir))
	step("remove "+envPath, os.RemoveAll(envPath))
	fmt.Println("Удалено вместе с пользователями. Порт, obfs и сертификат Hysteria остались прежними.")
}

// restoreOwnAuth puts back the auth saved by saveOwnAuth and drops the
// trafficStats the panel added. Returns false if nothing was saved.
func restoreOwnAuth(cfgPath, savedPath string) (bool, error) {
	saved, err := os.ReadFile(savedPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	keep, err := parseDoc(saved)
	if err != nil {
		return false, err
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return false, err
	}
	d, err := parseDoc(b)
	if err != nil {
		return false, err
	}
	for _, k := range []string{"auth", "trafficStats"} {
		if n := keep.get(k); n != nil {
			d.set(k, n)
		} else {
			d.del(k)
		}
	}
	out, err := d.bytes()
	if err != nil {
		return false, err
	}
	return true, writeKeepingOwner(cfgPath, out)
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
	fmt.Printf("Пароль:  %s\n\nhy-panel info | passwd | settings | uninstall\n", env["HYP_PASSWORD"])
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

var envKeys = []string{"HYP_PASSWORD", "HYP_UI_PATH", "HYP_UI_PORT", "HYP_HOST", "HYP_NAME", "HYP_HY_CONFIG", "HYP_HY_SERVICE", "HYP_SUB_LISTEN", "HYP_SUB_URL"}

func readEnv() map[string]string {
	env := map[string]string{}
	b, _ := os.ReadFile(envPath)
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

// installed: this version's settings exist (v0.1 kept the host in its unit,
// so its leftover env file has no HYP_HOST).
func installed(env map[string]string) bool {
	return env["HYP_PASSWORD"] != "" && env["HYP_HOST"] != ""
}

// hyPaths returns the Hysteria config path and service name.
func hyPaths(env map[string]string) (cfg, svc string) {
	return envOr(env, "HYP_HY_CONFIG", defaultCfg), envOr(env, "HYP_HY_SERVICE", defaultSvc)
}

func reachable(cfg *hyConfig) bool {
	_, err := statsFor(cfg).Online()
	return err == nil
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
