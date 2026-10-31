package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
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

// hyFlags are the settings given on the command line (by the panel's
// agent); an unset flag keeps the current value.
type hyFlags struct {
	port, obfs, cert, domain, email string
}

func (f *hyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.port, "port", "", "UDP port or range 20000-50000")
	fs.StringVar(&f.obfs, "obfs", "", "salamander, gecko or none")
	fs.StringVar(&f.cert, "cert", "", "self (self-signed) or acme (Let's Encrypt, needs -domain)")
	fs.StringVar(&f.domain, "domain", "", "domain for Let's Encrypt")
	fs.StringVar(&f.email, "email", "", "e-mail for Let's Encrypt")
}

func (f hyFlags) check() error {
	var errs []error
	if p := f.port; p != "" && p != hopRange {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			errs = append(errs, fmt.Errorf("-port %q: нужен порт 1–65535 или %s", p, hopRange))
		}
	}
	if f.obfs != "" && !slices.Contains([]string{"salamander", "gecko", "none"}, f.obfs) {
		errs = append(errs, fmt.Errorf("-obfs %q: salamander, gecko или none", f.obfs))
	}
	switch f.cert {
	case "", "self":
	case "acme":
		if !validHostname(f.domain) || !strings.Contains(f.domain, ".") {
			errs = append(errs, fmt.Errorf("-domain %q: нужен домен", f.domain))
		}
		if f.email != "" && !emailRe.MatchString(f.email) {
			errs = append(errs, fmt.Errorf("-email %q: неверный адрес", f.email))
		}
	default:
		errs = append(errs, fmt.Errorf("-cert %q: self или acme", f.cert))
	}
	return errors.Join(errs...)
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// hyOptsFrom applies the flags to the current settings (cur nil: a new
// config, which starts from 443, salamander and a self-signed certificate).
func hyOptsFrom(cur *hyOpts, f hyFlags, host string) hyOpts {
	o := hyOpts{Port: "443", Obfs: "salamander"}
	if cur != nil {
		o = *cur
	}
	switch f.port {
	case "":
	case hopRange:
		o.Port = needVersion(hyVersion{2, 8, 0}, "диапазон портов", hopRange, "443")
	default:
		o.Port = f.port
	}
	switch f.obfs {
	case "":
	case "none":
		o.Obfs = ""
	case "gecko":
		o.Obfs = needVersion(hyVersion{2, 9, 2}, "gecko", "gecko", "salamander")
	default:
		o.Obfs = f.obfs
	}
	switch f.cert {
	case "self":
		o.Domain, o.Email = "", ""
	case "acme":
		o.Domain, o.Email = strings.ToLower(f.domain), f.email
		if !resolvesTo(o.Domain, host) {
			fmt.Printf("  ✗ %s не указывает на %s: Let's Encrypt не выдаст сертификат, пока A-запись не исправлена\n", o.Domain, host)
		}
	}
	return o
}

// needVersion returns want if the installed Hysteria is new enough for the
// feature, else says why and returns fallback.
func needVersion(min hyVersion, feature, want, fallback string) string {
	v := hysteriaVersion()
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
// (everything when cur is nil: a new config). The obfs password and an
// existing self-signed certificate are kept: they are in every client link.
func applyOpts(d *yamlDoc, cfg *hyConfig, curp *hyOpts, o hyOpts, cfgDir string) error {
	all, cur := curp == nil, hyOpts{}
	if curp != nil {
		cur = *curp
	}
	if err := hysteriaDir(cfgDir); err != nil {
		return err
	}
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

// firewallRules are the ufw rules a Hysteria setup needs.
func (o hyOpts) firewallRules() []string {
	rules := []string{strings.Replace(o.Port, "-", ":", 1) + "/udp"}
	if o.Domain != "" {
		rules = append(rules, "80/tcp", "443/tcp") // ACME challenges
	}
	return rules
}

// runSettings sets Hysteria up, or changes its port, obfuscation or
// certificate (`hy-panel settings`, run by the agent from the panel). A
// config the panel did not write is replaced; the original stays in
// .bak-hy-panel.
func runSettings(args []string) {
	fs := flag.NewFlagSet("settings", flag.ExitOnError)
	var f hyFlags
	f.register(fs)
	fs.Parse(args)
	needRoot("settings")
	if err := f.check(); err != nil {
		log.Fatal("✗ ", err)
	}
	env := readEnv()
	if !installed(env) {
		log.Fatal("✗ панель не установлена: сначала hy-panel install")
	}
	if err := checkEnv(env); err != nil {
		log.Fatal("✗ ", err)
	}
	cfgPath, svc := hyPaths(env)
	b, err := os.ReadFile(cfgPath)
	cfg, kind := classify(b, err)
	if err := kindErr(kind); err != nil {
		log.Fatal("✗ ", err)
	}
	if !fileExists(hysteriaBin) || !unitExists(svc) {
		noInterrupt()
		_, err := fetchHysteria()
		step("hysteria: официальный релиз", err)
	}
	var cur *hyOpts
	switch kind {
	case cfgPanel:
		c := currentOpts(cfg)
		cur = &c
		fmt.Printf("Сейчас: порт %s, %s, %s.\n", c.Port, c.obfsLabel(), c.certLabel())
	case cfgOwnAuth:
		fmt.Printf("Конфиг Hysteria писала не панель — настраиваю заново, прежний сохранится в %s.\n", cfgPath+backupExt)
	default:
		fmt.Println("Конфиг Hysteria не настроен — настраиваю.")
	}
	o := hyOptsFrom(cur, f, env["HYP_HOST"])
	if cur != nil && *cur == o {
		_, changed := rewriteHyConfig(cfgPath, b, false, nil)
		if changed {
			step("apply Hysteria ACL", systemctl("restart", svc))
			step("restart hy-panel", systemctl("restart", "hy-panel"))
		} else {
			fmt.Println("\nНичего не изменилось.")
		}
		return
	}
	fmt.Printf("\nБудет: порт %s, %s, %s.\n", o.Port, o.obfsLabel(), o.certLabel())
	noInterrupt()
	// Links name the domain when there is one, else the server's IP.
	if oldDomain := currentOpts(cfg).Domain; o.Domain != oldDomain {
		if o.Domain != "" {
			env["HYP_HOST"] = o.Domain
		} else if ip := publicIP(); ip != "" && env["HYP_HOST"] == oldDomain {
			env["HYP_HOST"] = ip
		}
		step("settings → "+envPath, writeEnv(env))
	}
	old := cfg
	cfg, _ = rewriteHyConfig(cfgPath, b, cur == nil, func(d *yamlDoc) error {
		return applyOpts(d, old, cur, o, filepath.Dir(cfgPath))
	})
	// Links come from the config file: the panel shows the new ones right
	// away, whatever happens to Hysteria's restart below.
	step("restart hy-panel", systemctl("restart", "hy-panel"))
	ufwAllow(o.firewallRules()...)
	step("enable "+svc, systemctl("enable", svc))
	step("restart "+svc, systemctl("restart", svc))
	waitHysteria(cfg, svc, o.Domain != "")
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

func statsFor(cfg *hyConfig) *statsClient {
	return newStatsClient(cfg.TrafficStats.Listen, cfg.TrafficStats.Secret)
}

// waitHysteria waits until Hysteria's trafficStats answers (up to 2 minutes
// with Let's Encrypt, which first has to get the certificate).
func waitHysteria(cfg *hyConfig, svc string, acme bool) {
	sc := statsFor(cfg)
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
