package main

import (
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// hyOpts are the Hysteria settings the panel asks about. They live only in
// Hysteria's own config: currentOpts reads them back from it.
type hyOpts struct {
	Port   string // "443" or a hopping range "20000-50000"
	Obfs   string // salamander, gecko, ""
	Domain string // Let's Encrypt via Hysteria's ACME; "" = certificate from tls
	Email  string
}

const hopRange = "20000-50000"

func currentOpts(c *hyConfig) hyOpts {
	o := hyOpts{Port: c.port(), Email: c.ACME.Email}
	o.Obfs, _ = c.obfs()
	if len(c.ACME.Domains) > 0 {
		o.Domain = c.ACME.Domains[0]
	}
	return o
}

func (o hyOpts) certLabel() string {
	if o.Domain != "" {
		return "домен " + o.Domain + " (Let's Encrypt)"
	}
	return "сертификат из tls (self-signed)"
}

func (o hyOpts) obfsLabel() string {
	if o.Obfs == "" {
		return "без обфускации"
	}
	return o.Obfs
}

// askHyOpts asks for the Hysteria settings. With cur (the `settings`
// command) every question starts with "keep as is"; port != "" (the -hy-port
// flag) skips the port question.
func askHyOpts(p *prompter, cur *hyOpts, port, host string) hyOpts {
	hv := hysteriaVersion()
	var o hyOpts
	keep := func(opts []string, label string) []string {
		if cur == nil {
			return opts
		}
		return append([]string{"оставить как есть: " + label}, opts...)
	}
	pick := func(title string, opts []string, label string) int {
		i := p.choose(title, keep(opts, label), 0)
		if cur != nil {
			i-- // -1 = keep
		}
		return i
	}
	if cur != nil {
		o = *cur
	}

	if port != "" {
		o.Port = port
	} else {
		switch pick("Порт Hysteria (UDP):", []string{
			"443 — выглядит как обычный HTTPS/QUIC",
			"случайный",
			"свой",
			"диапазон " + hopRange + " — port hopping, сложнее заблокировать (Hysteria ≥ 2.8)",
		}, o.Port) {
		case 0:
			o.Port = "443"
		case 1:
			o.Port = strconv.Itoa(20000 + rand.IntN(40000))
		case 2:
			o.Port = p.port("Порт: ")
		case 3:
			o.Port = needVersion(hv, hyVersion{2, 8, 0}, "диапазон портов", hopRange, "443")
		}
	}

	switch pick("Обфускация:", []string{
		"salamander — трафик не похож ни на что, рекомендую для РФ",
		"gecko — salamander + дробление рукопожатия (экспериментальная, Hysteria ≥ 2.9.2, mihomo тоже нужен свежий)",
		"без обфускации — выглядит как HTTP/3-сайт (маскировка под bing.com)",
	}, o.obfsLabel()) {
	case 0:
		o.Obfs = "salamander"
	case 1:
		o.Obfs = needVersion(hv, hyVersion{2, 9, 2}, "gecko", "gecko", "salamander")
	case 2:
		o.Obfs = ""
	}

	switch pick("Сертификат:", []string{
		"self-signed — домен не нужен, клиенты проверяют сертификат по отпечатку",
		"свой домен через Let's Encrypt — домен должен указывать на этот сервер, TCP 80/443 свободны",
	}, o.certLabel()) {
	case 0:
		o.Domain, o.Email = "", ""
	case 1:
		o.Domain = strings.ToLower(p.need("Домен: "))
		o.Email = p.line("E-mail для Let's Encrypt (Enter — без него): ", "")
		if !resolvesTo(o.Domain, host) && !p.yes(fmt.Sprintf("  %s не указывает на %s. Всё равно продолжить?", o.Domain, host), false) {
			log.Fatal("✗ сначала направь A-запись домена на сервер")
		}
	}
	return o
}

// needVersion returns want if Hysteria is new enough for the feature, else
// says why and returns fallback.
func needVersion(v, min hyVersion, feature, want, fallback string) string {
	if v.atLeast(min) {
		return want
	}
	fmt.Printf("  ✗ %s: нужна Hysteria ≥ %s, установлена %s — беру %s\n", feature, min, v, fallback)
	return fallback
}

// resolvesTo reports whether domain resolves to host (an IP, or a domain whose
// addresses are compared).
func resolvesTo(domain, host string) bool {
	if strings.EqualFold(domain, host) {
		return true
	}
	want, _ := net.LookupHost(host) // an IP comes back as is
	ips, _ := net.LookupHost(domain)
	return slices.ContainsFunc(ips, func(a string) bool { return slices.Contains(want, a) })
}

// applyOpts edits the config tree from cur to o, touching only what changed
// (everything when all is set, for a new config). The obfs password and an
// existing self-signed certificate are kept: they are in every client link.
func applyOpts(d *yamlDoc, cfg *hyConfig, cur, o hyOpts, cfgDir string, all bool) error {
	if all || o.Port != cur.Port {
		host, _, _ := net.SplitHostPort(cfg.Listen) // keep a listen address, change only the port
		if err := d.set("listen", net.JoinHostPort(host, o.Port)); err != nil {
			return err
		}
	}
	if all || o.Obfs != cur.Obfs {
		if o.Obfs == "" {
			d.del("obfs")
			if d.get("masquerade") == nil {
				// Without obfs Hysteria answers browsers like a normal HTTP/3 site.
				d.set("masquerade", map[string]any{"type": "proxy", "proxy": map[string]any{"url": "https://www.bing.com/", "rewriteHost": true}})
			}
		} else {
			_, pass := cfg.obfs()
			if pass == "" {
				pass = randStr(24)
			}
			if err := d.set("obfs", map[string]any{"type": o.Obfs, o.Obfs: map[string]any{"password": pass}}); err != nil {
				return err
			}
		}
	}
	if all || o.Domain != cur.Domain || o.Email != cur.Email {
		if o.Domain == "" {
			crt, key := filepath.Join(cfgDir, "server.crt"), filepath.Join(cfgDir, "server.key")
			if ci, err := readCert(crt); err != nil || !ci.SelfSigned || !keyPairOK(crt, key) {
				// The name only has to match the SNI (sniGuard); clients pin the cert.
				if err := newSelfSigned(crt, key, "bing.com"); err != nil {
					return err
				}
			}
			for _, f := range []string{crt, key} {
				chownHysteria(f)
				os.Chmod(f, 0o640)
			}
			d.del("acme")
			return d.set("tls", map[string]any{"cert": crt, "key": key})
		}
		// Explicit dir: by default ACME state goes to the unit's working directory.
		dir := filepath.Join(cfgDir, "acme")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		uid, gid := hysteriaIDs()
		os.Chown(dir, uid, gid) // the only place hysteria may write
		// Edit acme in place: keep the rest (DNS challenge, ca, …).
		acme := d.get("acme")
		if acme == nil || acme.Kind != yaml.MappingNode {
			acme = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			mapSet(acme, "dir", dir)
		}
		mapSet(acme, "domains", []string{o.Domain})
		if o.Email != "" {
			mapSet(acme, "email", o.Email)
		}
		d.del("tls")
		return d.set("acme", acme)
	}
	return nil
}

// linksChange reports whether moving from cur to o changes the client links.
func linksChange(cur, o hyOpts) bool { return cur != o }

// firewallRules are the ufw rules a Hysteria setup needs.
func (o hyOpts) firewallRules() []string {
	rules := []string{strings.Replace(o.Port, "-", ":", 1) + "/udp"}
	if o.Domain != "" {
		rules = append(rules, "80/tcp", "443/tcp") // ACME challenges
	}
	return rules
}

// runSettings changes the port, obfuscation or certificate of the current
// Hysteria config (`hy-panel settings`).
func runSettings() {
	needRoot("settings")
	env := readEnv()
	if env["HYP_PASSWORD"] == "" {
		log.Fatal("✗ панель не установлена: сначала hy-panel install")
	}
	cfgPath, svc := envOr(env, "HYP_HY_CONFIG", defaultCfg), envOr(env, "HYP_HY_SERVICE", defaultSvc)
	b, err := os.ReadFile(cfgPath)
	kind := classify(b, err)
	switch kind {
	case cfgBroken:
		log.Fatalf("✗ %s не читается как YAML — поправь его вручную", cfgPath)
	case cfgRealm:
		log.Fatal("✗ listen: realm:// не поддерживается")
	}
	cfg, _ := parseHyConfig(b)
	if cfg == nil {
		cfg = &hyConfig{}
	}
	p := newPrompter()
	if p.in == nil {
		log.Fatal("✗ нужен терминал: settings задаёт вопросы")
	}
	var cur *hyOpts
	if kind != cfgNone {
		c := currentOpts(cfg)
		cur = &c
		fmt.Printf("Сейчас: порт %s, %s, %s.\n", c.Port, c.obfsLabel(), c.certLabel())
	} else {
		fmt.Println("Конфиг Hysteria не настроен — настроим его.")
	}
	o := askHyOpts(p, cur, "", env["HYP_HOST"])
	before := hyOpts{}
	if cur != nil {
		before = *cur
	}
	if cur != nil && !linksChange(before, o) {
		fmt.Println("\nНичего не изменилось.")
		return
	}
	fmt.Printf("\nБудет: порт %s, %s, %s.\n", o.Port, o.obfsLabel(), o.certLabel())
	if cur != nil && !p.yes("Ссылки и QR всех клиентов изменятся — им нужно будет выдать новые (подписка обновится сама). Применить?", false) {
		fmt.Println("Отменено.")
		return
	}
	// Links name the domain when there is one, else the server's IP.
	if o.Domain != before.Domain {
		if o.Domain != "" {
			env["HYP_HOST"] = o.Domain
		} else if ip := publicIP(); ip != "" && env["HYP_HOST"] == before.Domain {
			env["HYP_HOST"] = ip
		}
		step("settings → "+envPath, writeEnv(env))
	}
	d, err := parseDoc(b)
	step("read "+cfgPath, err)
	step("directory "+filepath.Dir(cfgPath), hysteriaDir(filepath.Dir(cfgPath)))
	step("settings", applyOpts(d, cfg, before, o, filepath.Dir(cfgPath), cur == nil))
	_, err = d.connectPanel()
	step("auth → panel", err)
	out, err := d.bytes()
	step("render config", err)
	if len(b) > 0 {
		step("backup → "+cfgPath+backupExt, backupOnce(cfgPath, b))
	}
	step("hysteria config "+cfgPath, writeHysteriaConfig(cfgPath, out, cur == nil))
	// Links come from the config file: the panel shows the new ones right
	// away, whatever happens to Hysteria's restart below.
	step("restart hy-panel", systemctl("restart", "hy-panel"))
	ufwAllow(o.firewallRules()...)
	step("restart "+svc, systemctl("restart", svc))
	waitHysteria(cfgPath, svc, o.Domain != "")
	fmt.Println("\nГотово. Новые ссылки — в панели (кнопка QR).")
}

// hysteriaDir makes sure the config directory exists and Hysteria can enter it.
func hysteriaDir(dir string) error {
	if fileExists(dir) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	chownHysteria(dir)
	return nil
}

// writeHysteriaConfig writes the config; a config the panel creates (fresh)
// is root:hysteria 0640, since it holds the obfs password and stats secret.
func writeHysteriaConfig(path string, b []byte, fresh bool) error {
	if err := writeKeepingOwner(path, b); err != nil {
		return err
	}
	if fresh {
		chownHysteria(path)
		return os.Chmod(path, 0o640)
	}
	return nil
}

// hysteriaIDs returns the uid and gid of the hysteria user, 0 if absent.
func hysteriaIDs() (int, int) {
	u, err := user.Lookup("hysteria")
	if err != nil {
		return 0, 0
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid
}

// waitHysteria waits until Hysteria's trafficStats answers (up to 2 minutes
// with Let's Encrypt, which first has to get the certificate).
func waitHysteria(cfgPath, svc string, acme bool) {
	cfg, err := loadHyConfig(cfgPath)
	step("read "+cfgPath, err)
	sc := newStatsClient(cfg.TrafficStats.Listen, cfg.TrafficStats.Secret)
	tries := 20
	if acme {
		fmt.Println("… жду сертификат Let's Encrypt (до 2 минут)")
		tries = 240
	}
	var verr error
	for i := 0; i < tries; i++ {
		if _, verr = sc.Online(); verr == nil {
			step("hysteria trafficStats reachable", nil)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Fatalf("✗ Hysteria не поднялась: %v\n  смотри: journalctl -u %s -n 30 --no-pager", verr, svc)
}
