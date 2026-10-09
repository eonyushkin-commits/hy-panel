package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"gopkg.in/yaml.v3"
)

//go:embed hy-panel.service
var unitTemplate string

const (
	binPath    = "/usr/local/bin/hy-panel"
	envPath    = "/etc/hy-panel.env"
	unitPath   = "/etc/systemd/system/hy-panel.service"
	dataPath   = "/var/lib/hy-panel/users.json"
	panelAddr  = "127.0.0.1:8090"
	statsAddr  = "127.0.0.1:25413"
	backupExt  = ".bak-hy-panel"
	defaultCfg = "/etc/hysteria/config.yaml"
)

// runInstall: `hy-panel install` sets everything up on a host with a working
// hysteria-server: binary, password, users import, config switch, systemd.
func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	hyCfg := fs.String("hy-config", defaultCfg, "Hysteria 2 server config")
	hySvc := fs.String("hy-service", "hysteria-server", "Hysteria systemd service")
	host := fs.String("host", "", "public IP/domain for client links (default: autodetect)")
	name := fs.String("name", "", "profile name prefix shown in clients")
	ui := fs.String("ui-port", "9443", "public HTTPS port for the panel UI, \"\" = SSH tunnel only")
	hyPort := fs.String("hy-port", "443", "UDP port when writing a new Hysteria config")
	force := fs.Bool("fresh", false, "write a new Hysteria config even if Hysteria is running")
	fs.Parse(args)
	log.SetFlags(0)
	if os.Geteuid() != 0 {
		log.Fatal("run as root: sudo hy-panel install")
	}

	if *host == "" {
		*host = publicIP()
		if *host == "" {
			log.Fatal("cannot detect a public IP (NAT?) — pass -host <IP or domain>")
		}
	}

	// A running Hysteria is adopted as is; otherwise (bare server, or the
	// official installer's template that never started) it is set up fresh.
	fresh := *force || !serviceActive(*hySvc)
	if fresh {
		fmt.Printf("Hysteria (%s) не запущена — пишу рабочий конфиг (UDP %s)\n", *hySvc, *hyPort)
		freshSetup(*hyCfg, *hySvc, *hyPort)
	} else {
		fmt.Printf("Hysteria (%s) работает — подключаю панель к ней\n", *hySvc)
	}
	cfg, err := loadHyConfig(*hyCfg)
	if err != nil {
		log.Fatal(err)
	}

	step("binary → "+binPath, copySelf(binPath))

	// Like 3x-ui: random password and a secret URL path, kept across re-runs.
	env := readEnv()
	if env["HYP_PASSWORD"] == "" {
		env["HYP_PASSWORD"] = randStr(16)
	}
	if env["HYP_UI_PATH"] == "" {
		env["HYP_UI_PATH"] = "/" + strings.ToLower(randStr(12)) + "/"
	}
	step("password and URL path → "+envPath, writeEnv(env))

	store, err := OpenStore(dataPath)
	step("user database "+dataPath, err)
	if fresh {
		// Users imported earlier from a config that never ran are meaningless.
		for _, u := range store.List() {
			if u.Note == "imported" {
				store.Delete(u.Name)
			}
		}
	} else if store.Empty() {
		importUsers(store, cfg) // while the config still has the old auth
	}
	// Ask now: the store file must be written before the panel service owns it.
	created := askUsers(store)

	changed, err := patchHyConfig(*hyCfg)
	step("hysteria config: auth → panel, trafficStats (backup: "+*hyCfg+backupExt+")", err)

	unit := strings.Replace(unitTemplate, "-host 203.0.113.10 -name AMS",
		strings.TrimSpace(fmt.Sprintf("-host %s -hy-config %s %s %s", *host, *hyCfg, uiFlag(*ui), nameFlag(*name))), 1)
	step("systemd unit → "+unitPath, os.WriteFile(unitPath, []byte(unit), 0o644))
	if *ui != "" {
		_, _, err = panelCert(filepath.Dir(dataPath), *host)
		step("panel HTTPS certificate", err)
		if out, err := exec.Command("ufw", "status").Output(); err == nil && strings.Contains(string(out), "Status: active") {
			step("ufw allow "+*ui+"/tcp", exec.Command("ufw", "allow", *ui+"/tcp").Run())
		}
	}
	step("systemd daemon-reload", systemctl("daemon-reload"))
	step("start hy-panel", systemctl("enable", "hy-panel"))
	step("restart hy-panel", systemctl("restart", "hy-panel")) // picks up a new binary on re-run

	// Restart Hysteria if its config changed now, or a previous run stopped
	// half-way (config patched, Hysteria still running the old one).
	cfg, _ = loadHyConfig(*hyCfg)
	sc := newStatsClient(cfg.TrafficStats.Listen, cfg.TrafficStats.Secret)
	if _, err := sc.Online(); fresh || changed || err != nil {
		step("restart "+*hySvc, systemctl("restart", *hySvc))
	}
	var verr error
	for i := 0; i < 20; i++ {
		if _, verr = sc.Online(); verr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	step("hysteria trafficStats reachable", verr)

	fmt.Println("\nГотово.")
	printInfo()
	ci, _ := readCert(cfg.TLS.Cert)
	ech, _ := readECH(cfg.ECH.KeyPath)
	ep := buildEndpoint(cfg, ci, ech, *host, "", "", *name)
	for _, u := range created {
		uri := ep.URI(u)
		fmt.Printf("\n%s — ссылка для клиента:\n%s\n", u.Name, uri)
		if q, err := qrcode.New(uri, qrcode.Low); err == nil {
			fmt.Print(q.ToSmallString(false))
		}
	}
}

// askUsers offers to create users interactively (like 3x-ui asks for its
// settings). Without a terminal it creates nothing.
func askUsers(store *Store) []User {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil
	}
	defer tty.Close()
	in := bufio.NewReader(tty)
	ask := func(q string) string {
		fmt.Print(q)
		l, _ := in.ReadString('\n')
		return strings.TrimSpace(l)
	}
	yes := func(a string, def bool) bool {
		if a == "" {
			return def
		}
		return strings.HasPrefix(strings.ToLower(a), "y") || strings.HasPrefix(strings.ToLower(a), "д")
	}
	var out []User
	q, def := "Создать пользователя? [Y/n]: ", store.Empty()
	if !def {
		q = "Создать ещё пользователя? [y/N]: "
	}
	for yes(ask("\n"+q), def) {
		for {
			n := ask("Имя (a-z 0-9 _ . -): ")
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
		q, def = "Создать ещё пользователя? [y/N]: ", false
	}
	return out
}

// printInfo prints how to open the panel (the `hy-panel info` command).
func printInfo() {
	env := readEnv()
	unit, _ := os.ReadFile(unitPath)
	host, ui := unitArg(string(unit), "-host"), unitArg(string(unit), "-ui-listen")
	if ui != "" {
		_, fp, _ := panelCert(filepath.Dir(dataPath), host)
		_, port, _ := net.SplitHostPort(ui)
		fmt.Printf("Панель:  https://%s%s\n", net.JoinHostPort(host, port), env["HYP_UI_PATH"])
		fmt.Printf("         браузер предупредит о self-signed сертификате, это нормально\n         SHA-256: %s\n", fp)
	} else {
		fmt.Printf("Панель:  ssh -L 8090:%s root@%s, затем http://localhost:8090\n", panelAddr, host)
	}
	fmt.Printf("Пароль:  %s\n\nhy-panel info | passwd | uninstall\n", env["HYP_PASSWORD"])
}

// runPasswd sets a new random panel password (`hy-panel passwd`).
func runPasswd() {
	env := readEnv()
	env["HYP_PASSWORD"] = randStr(16)
	step("new password → "+envPath, writeEnv(env))
	step("restart hy-panel", systemctl("restart", "hy-panel"))
	printInfo()
}

func readEnv() map[string]string {
	env := map[string]string{}
	b, _ := os.ReadFile(envPath)
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			env[k] = v
		}
	}
	return env
}

func writeEnv(env map[string]string) error {
	var b strings.Builder
	for _, k := range []string{"HYP_PASSWORD", "HYP_UI_PATH"} {
		fmt.Fprintf(&b, "%s=%s\n", k, env[k])
	}
	return os.WriteFile(envPath, []byte(b.String()), 0o600)
}

// unitArg returns the value of a flag in the unit's ExecStart line.
func unitArg(unit, flag string) string {
	f := strings.Fields(unit)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == flag {
			return f[i+1]
		}
	}
	return ""
}

// runUninstall restores the Hysteria config and removes the service; users.json stays.
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	hyCfg := fs.String("hy-config", defaultCfg, "Hysteria 2 server config")
	hySvc := fs.String("hy-service", "hysteria-server", "Hysteria systemd service")
	fs.Parse(args)
	log.SetFlags(0)
	if os.Geteuid() != 0 {
		log.Fatal("run as root: sudo hy-panel uninstall")
	}
	b, err := os.ReadFile(*hyCfg + backupExt)
	step("restore "+*hyCfg+" from backup", err)
	step("write "+*hyCfg, writeKeepingOwner(*hyCfg, b))
	step("restart "+*hySvc, systemctl("restart", *hySvc))
	systemctl("disable", "--now", "hy-panel")
	os.Remove(unitPath)
	systemctl("daemon-reload")
	fmt.Printf("Удалено. Данные остались в %s и %s, бинарник — %s.\n", dataPath, envPath, binPath)
}

func step(what string, err error) {
	if err != nil {
		log.Fatalf("✗ %s: %v", what, err)
	}
	fmt.Println("✓", what)
}

func uiFlag(port string) string {
	if port == "" {
		return ""
	}
	return "-ui-listen :" + port
}

func nameFlag(n string) string {
	if n == "" {
		return ""
	}
	return "-name " + n
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func copySelf(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if src == dst {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Close()
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, dst) // works while the old binary is running
}

// publicIP returns the source address of the default route if it is public.
func publicIP() string {
	c, err := net.Dial("udp", "1.1.1.1:53") // no packet is sent
	if err != nil {
		return ""
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || (ip[0] == 100 && ip[1]&0xc0 == 64) {
		return ""
	}
	return ip.String()
}

// patchHyConfig points auth at the panel and adds trafficStats if missing,
// editing the YAML tree so comments and other settings stay as they are.
// Returns false if nothing had to change.
func patchHyConfig(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return false, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return false, errors.New("config is not a YAML mapping")
	}
	root := doc.Content[0]
	changed := false

	wantAuth := map[string]any{"type": "http", "http": map[string]any{"url": "http://" + panelAddr + "/auth"}}
	if cur := mapGet(root, "auth"); cur == nil || !sameAuth(cur) {
		if err := mapSet(root, "auth", wantAuth); err != nil {
			return false, err
		}
		changed = true
	}
	if ts := mapGet(root, "trafficstats"); ts == nil || mapGet(ts, "listen") == nil {
		if err := mapSet(root, "trafficStats", map[string]any{"listen": statsAddr, "secret": randStr(32)}); err != nil {
			return false, err
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return false, err
	}
	if _, err := os.Stat(path + backupExt); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path+backupExt, b, 0o600); err != nil {
			return false, err
		}
	}
	return true, writeKeepingOwner(path, buf.Bytes())
}

func sameAuth(n *yaml.Node) bool {
	t, h := mapGet(n, "type"), mapGet(n, "http")
	if t == nil || !strings.EqualFold(t.Value, "http") || h == nil {
		return false
	}
	u := mapGet(h, "url")
	return u != nil && u.Value == "http://"+panelAddr+"/auth"
}

// mapGet finds a key case-insensitively, as Hysteria/viper does.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, key) {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapSet(m *yaml.Node, key string, v any) error {
	var val yaml.Node
	if err := val.Encode(v); err != nil {
		return err
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, key) {
			m.Content[i+1] = &val
			return nil
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &val)
	return nil
}

// writeKeepingOwner rewrites a file in place so owner and mode stay (Hysteria may run as its own user).
func writeKeepingOwner(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
