package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	xrayClientsPath = dataDir + "/xray-clients.json" // the inbound's clients before the panel, for -purge
	xrayInstallCmd  = `bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install`
)

var minXray = hyVersion{25, 3, 6} // XHTTP, GetInboundUsers, per-user online stats

// xrayTemplate is a new Xray config: VLESS + Reality + XHTTP as in the
// usual hand-made setups, plus the API and statistics the panel needs. No
// clients: the panel puts its users in through the API.
const xrayTemplate = `{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "listen": %s, "services": ["HandlerService", "StatsService"]},
  "stats": {},
  "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}}},
  "inbounds": [{
    "tag": %s,
    "listen": "0.0.0.0",
    "port": %s,
    "protocol": "vless",
    "settings": {"clients": [], "decryption": "none"},
    "streamSettings": {
      "network": "xhttp",
      "xhttpSettings": {"path": %s, "mode": "auto"},
      "security": "reality",
      "realitySettings": {
        "target": %s,
        "serverNames": [%s],
        "privateKey": %s,
        "shortIds": [%s]
      }
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}
  }],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ],
  "routing": {"rules": [{"ip": ["geoip:private"], "outboundTag": "block"}]}
}
`

// freshXray fills the template: new Reality keys, short ID and XHTTP path.
func freshXray(port, domain string) []byte {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	return []byte(fmt.Sprintf(xrayTemplate, q(xrayAPIAddr), q(xrayTag), port, q("/"+randHex(6)),
		q(net.JoinHostPort(domain, "443")), q(domain), q(newRealityKey()), q(randHex(8))))
}

// ---- what kind of config this is ----

type xrayKind int

const (
	xrayNone       xrayKind = iota // missing, empty or no inbounds: set up from scratch
	xrayVless                      // has a VLESS + Reality inbound
	xrayOther                      // other inbounds only
	xrayBroken                     // not parseable
	xrayUnreadable                 // exists but cannot be read
)

// classifyXray decides by the config's content; the returned doc is never nil.
func classifyXray(b []byte, readErr error) (*xrayDoc, xrayKind) {
	empty := &xrayDoc{root: newObj()}
	if errors.Is(readErr, os.ErrNotExist) {
		return empty, xrayNone
	}
	if readErr != nil {
		return empty, xrayUnreadable
	}
	s := bytes.TrimSpace(stripComments(b))
	if len(s) == 0 {
		return empty, xrayNone
	}
	d, err := parseXrayDoc(b)
	var c xrayConfig
	if err != nil || json.Unmarshal(s, &c) != nil {
		return empty, xrayBroken
	}
	switch {
	case c.vlessInbound() != nil:
		return d, xrayVless
	case len(c.Inbounds) > 0:
		return d, xrayOther
	}
	return d, xrayNone
}

// ---- editing the config as ordered JSON (key order stays) ----

// jobj is a JSON object that keeps its key order.
type jobj struct {
	keys []string
	vals map[string]any
}

func newObj() *jobj { return &jobj{vals: map[string]any{}} }

// key finds a key case-insensitively, as Xray's encoding/json does.
func (o *jobj) key(k string) (string, bool) {
	if o == nil {
		return "", false
	}
	if _, ok := o.vals[k]; ok {
		return k, true
	}
	for _, x := range o.keys {
		if strings.EqualFold(x, k) {
			return x, true
		}
	}
	return "", false
}

func (o *jobj) get(k string) any {
	if x, ok := o.key(k); ok {
		return o.vals[x]
	}
	return nil
}

func (o *jobj) obj(k string) *jobj { m, _ := o.get(k).(*jobj); return m }

func (o *jobj) str(k string) string { s, _ := o.get(k).(string); return s }

// sub returns the object under k, creating it if there is none.
func (o *jobj) sub(k string) *jobj {
	if m := o.obj(k); m != nil {
		return m
	}
	m := newObj()
	o.set(k, m)
	return m
}

// set replaces the value of k, keeping its position, or appends it.
func (o *jobj) set(k string, v any) {
	if x, ok := o.key(k); ok {
		o.vals[x] = v
		return
	}
	o.keys = append(o.keys, k)
	o.vals[k] = v
}

func (o *jobj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := encodeJSON(&b, k, ""); err != nil {
			return nil, err
		}
		b.WriteByte(':')
		if err := encodeJSON(&b, o.vals[k], ""); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// encodeJSON writes v without escaping <>& (paths and URLs read as written).
func encodeJSON(w io.Writer, v any, indent string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(v); err != nil {
		return err
	}
	b := buf.Bytes()
	if indent == "" {
		b = bytes.TrimSuffix(b, []byte("\n"))
	}
	_, err := w.Write(b)
	return err
}

func decodeJSON(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		o := newObj()
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, err
			}
			v, err := decodeJSON(dec)
			if err != nil {
				return nil, err
			}
			o.set(k.(string), v)
		}
		_, err := dec.Token()
		return o, err
	case json.Delim('['):
		a := []any{}
		for dec.More() {
			v, err := decodeJSON(dec)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, err := dec.Token()
		return a, err
	}
	return t, nil // string, json.Number, bool or nil
}

// xrayDoc is an Xray config as ordered JSON; root is its top-level object.
type xrayDoc struct{ root *jobj }

func parseXrayDoc(b []byte) (*xrayDoc, error) {
	b = bytes.TrimSpace(stripComments(b))
	if len(b) == 0 {
		return &xrayDoc{root: newObj()}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeJSON(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("лишние данные после JSON")
	}
	root, ok := v.(*jobj)
	if !ok {
		return nil, errors.New("конфиг Xray — не JSON-объект")
	}
	return &xrayDoc{root}, nil
}

func (d *xrayDoc) bytes() ([]byte, error) {
	var b bytes.Buffer
	err := encodeJSON(&b, d.root, "  ")
	return b.Bytes(), err
}

func (d *xrayDoc) inbounds() []*jobj {
	var out []*jobj
	ins, _ := d.root.get("inbounds").([]any)
	for _, x := range ins {
		if in, ok := x.(*jobj); ok {
			out = append(out, in)
		}
	}
	return out
}

// inbound returns the VLESS + Reality inbound: the first, as parseXray picks it.
func (d *xrayDoc) inbound() *jobj {
	for _, in := range d.inbounds() {
		if strings.EqualFold(in.str("protocol"), "vless") && strings.EqualFold(in.obj("streamSettings").str("security"), "reality") {
			return in
		}
	}
	return nil
}

// connectPanel readies the config for the panel: the inbound gets a tag, the
// API and per-user statistics are switched on, and the clients move out (the
// panel puts its users in through the API). Returns the clients taken out.
func (d *xrayDoc) connectPanel() []any {
	in := d.inbound()
	if in.str("tag") == "" {
		in.set("tag", xrayTag)
	}
	api := d.root.sub("api")
	if api.str("tag") == "" {
		api.set("tag", "api")
	}
	legacy := slices.ContainsFunc(d.inbounds(), func(o *jobj) bool { return o.str("tag") == api.str("tag") })
	if api.str("listen") == "" && !legacy {
		api.set("listen", xrayAPIAddr)
	}
	services, _ := api.get("services").([]any)
	for _, s := range []string{"HandlerService", "StatsService"} {
		if !slices.Contains(services, any(s)) {
			services = append(services, s)
		}
	}
	api.set("services", services)
	d.root.sub("stats")
	lv := d.root.sub("policy").sub("levels").sub("0")
	for _, k := range []string{"statsUserUplink", "statsUserDownlink", "statsUserOnline"} {
		lv.set(k, true)
	}
	settings := in.sub("settings")
	clients, _ := settings.get("clients").([]any)
	settings.set("clients", []any{})
	return clients
}

// setTarget points Reality at another site (the key it is written under stays).
func (d *xrayDoc) setTarget(domain string) {
	r := d.inbound().sub("streamSettings").sub("realitySettings")
	k := "target"
	if _, ok := r.key(k); !ok {
		if _, ok := r.key("dest"); ok {
			k = "dest"
		}
	}
	r.set(k, net.JoinHostPort(domain, "443"))
	r.set("serverNames", []any{domain})
}

// ---- hy-panel xray ----

// runXray sets up VLESS + Reality in Xray next to Hysteria, connects the
// panel to an existing setup, or changes the site Reality impersonates.
// Users stay the panel's: each of them gets both protocols.
func runXray(args []string) {
	fs := flag.NewFlagSet("xray", flag.ExitOnError)
	cfgFlag := fs.String("config", "", "Xray config (default "+defaultXrayCfg+")")
	svcFlag := fs.String("service", "", "Xray systemd service (default "+defaultXraySvc+")")
	target := fs.String("target", "", "site Reality impersonates (SNI), e.g. www.example.com")
	port := fs.String("port", "", "TCP port for VLESS (default: ask, 443)")
	yes := fs.Bool("y", false, "no questions: flags and defaults only")
	fs.Parse(args)
	needRoot("xray")
	env := readEnv()
	if !installed(env) {
		log.Fatal("✗ панель не установлена: сначала hy-panel install")
	}
	if err := checkEnv(env); err != nil {
		log.Fatal("✗ ", err)
	}
	cur := env["HYP_XRAY_CONFIG"]
	if *cfgFlag != "" {
		abs, err := filepath.Abs(*cfgFlag) // the panel's settings need an absolute path
		if err != nil {
			log.Fatal("✗ ", err)
		}
		env["HYP_XRAY_CONFIG"] = abs
	}
	managed := cur != "" && cur == env["HYP_XRAY_CONFIG"] // the panel runs this config already
	if *svcFlag != "" {
		env["HYP_XRAY_SERVICE"] = *svcFlag
	}
	cfgPath, svc := xrayPaths(env)
	if *target != "" && !validHostname(strings.TrimSuffix(*target, ".")) {
		log.Fatalf("✗ -target %q: нужен домен", *target)
	}
	if !fileExists(xrayBin) || !unitExists(svc) {
		step("xray: официальный релиз", fetchXray())
	}
	if v := xrayVersion(); !v.atLeast(minXray) {
		log.Fatalf("✗ нужен Xray ≥ %s, установлен %s — обнови: hy-panel fetch xray", minXray, v)
	}
	orig, readErr := os.ReadFile(cfgPath)
	d, kind := classifyXray(orig, readErr)
	p := newPrompter()
	if *yes {
		p.in = nil
	}
	switch kind {
	case xrayUnreadable:
		log.Fatalf("✗ %v", readErr)
	case xrayBroken:
		log.Fatalf("✗ %s не читается как JSON — поправь его вручную", cfgPath)
	case xrayOther:
		if !p.yes(fmt.Sprintf("В %s нет VLESS + Reality, но есть другие inbounds. Переписать конфиг Xray? Старый сохранится в %s", cfgPath, cfgPath+backupExt), false) {
			log.Fatal("✗ отменено: конфиг Xray не тронут")
		}
	}

	var out []byte
	var clients []any
	connect, retarget := false, false
	switch {
	case kind == xrayVless && managed:
		if out = changeTarget(p, orig, d, *target, env["HYP_HOST"]); out == nil {
			return
		}
		retarget = true
	case kind == xrayVless && keepXrayConfig(p, orig):
		connect, clients = true, d.connectPanel()
		var err error
		out, err = d.bytes()
		step("render "+cfgPath, err)
	default:
		if kind == xrayVless {
			fmt.Println("Настраиваю VLESS + Reality заново: новые ключи, прежние ссылки VLESS перестанут работать.")
		}
		vp := askXrayPort(p, *port, svc)
		domain := askTarget(p, *target, env["HYP_HOST"])
		out = freshXray(vp, domain)
	}
	xs, err := parseXray(out)
	step("check new xray config", err)

	noInterrupt()
	if connect {
		// Saved before the config loses them: -purge puts them back.
		step("clients → "+xrayClientsPath, saveXrayClients(clients))
	}
	writeXrayConfig(cfgPath, orig, out)
	ufwAllow(xs.Link.Port + "/tcp")
	step("enable "+svc, systemctl("enable", svc))
	env["HYP_XRAY_CONFIG"] = cfgPath
	var importErr error
	if connect {
		// The running panel would overwrite users.json with its copy: it is
		// stopped for the import and started again below, whatever happens.
		step("stop hy-panel", systemctl("stop", "hy-panel"))
		importErr = importXray(clients)
	}
	envErr := writeEnv(env)
	xrayErr := systemctl("restart", svc)
	panelErr := systemctl("restart", "hy-panel") // the panel puts its users into Xray
	if connect {
		step("import xray clients", importErr)
	}
	step("settings → "+envPath, envErr)
	step("restart "+svc, xrayErr)
	step("restart hy-panel", panelErr)
	waitXray(xs, svc)

	if retarget {
		fmt.Printf("\nГотово. Сайт для маскировки теперь %s: подписка обновится сама, остальным клиентам — новые ссылки VLESS (кнопка QR в панели).\n", xs.Link.SNI)
		return
	}
	fmt.Printf("\nГотово. VLESS + Reality: порт %s/tcp, %s, сайт для маскировки %s.\n", xs.Link.Port, xs.Link.Network, xs.Link.SNI)
	fmt.Println("У каждого пользователя теперь две ссылки — Hysteria и VLESS (кнопка QR в панели); подписка и mihomo отдают обе.")
}

// keepXrayConfig asks whether to connect the panel to a VLESS + Reality
// inbound it does not manage yet, or to set it up anew. Without a terminal it
// connects: nothing that works gets rewritten by a script.
func keepXrayConfig(p *prompter, b []byte) bool {
	var c xrayConfig
	json.Unmarshal(stripComments(b), &c)
	in := c.vlessInbound()
	v, err := vlessLink(in)
	if err != nil {
		fmt.Printf("\nVLESS + Reality в конфиге Xray панели не подходит: %v.\n", err)
		if !p.yes("Настроить его заново? Старый конфиг сохранится в "+backupExt, false) {
			log.Fatal("✗ отменено: конфиг Xray не тронут")
		}
		return false
	}
	var names []string
	for _, cl := range in.Settings.Clients {
		names = append(names, cl.Email)
	}
	fmt.Printf("\nНайден VLESS + Reality: порт %s/tcp, %s, сайт для маскировки %s; клиенты станут пользователями панели: %s.\n",
		v.Port, v.Network, v.SNI, strings.Join(names, ", "))
	if p.in == nil {
		return true
	}
	return p.choose("Что сделать с ним?", []string{
		"подключить к нему панель — ключи и сайт прежние, ссылки клиентов работают дальше",
		"настроить заново (новые ключи) — прежние ссылки VLESS перестанут работать",
	}, 0) == 0
}

// changeTarget offers to point Reality at another site, as when the old one
// went away. Returns the new config, nil if nothing is to change.
func changeTarget(p *prompter, orig []byte, d *xrayDoc, flagTarget, host string) []byte {
	var c xrayConfig
	json.Unmarshal(stripComments(orig), &c)
	cur, err := vlessLink(c.vlessInbound())
	if err != nil {
		log.Fatalf("✗ VLESS в конфиге Xray: %v", err)
	}
	fmt.Printf("Сейчас: VLESS + Reality, порт %s/tcp, %s, сайт для маскировки %s.\n", cur.Port, cur.Network, cur.SNI)
	if flagTarget == "" {
		if p.in == nil {
			log.Fatal("✗ нужен терминал или -target: hy-panel xray задаёт вопросы")
		}
		if p.choose("Что сделать?", []string{
			"оставить как есть",
			"сменить сайт для маскировки — если прежний перестал отвечать",
		}, 0) == 0 {
			fmt.Println("Ничего не изменилось.")
			return nil
		}
	}
	domain := askTarget(p, flagTarget, host)
	if domain == cur.SNI {
		fmt.Println("Ничего не изменилось.")
		return nil
	}
	if p.in != nil && !p.yes("В ссылках VLESS изменится sni — подписка обновится сама, остальным клиентам нужно выдать новые ссылки. Применить?", false) {
		fmt.Println("Отменено.")
		return nil
	}
	d.setTarget(domain)
	out, err := d.bytes()
	step("render xray config", err)
	return out
}

func askXrayPort(p *prompter, flagPort, svc string) string {
	port := flagPort
	if port == "" {
		port = "443"
		if p.choose("Порт VLESS (TCP):", []string{
			"443 — как у обычного HTTPS-сайта (Hysteria на UDP 443 не мешает)",
			"свой",
		}, 0) == 1 {
			port = p.port("Порт: ")
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		log.Fatalf("✗ -port %q: нужен порт 1–65535", port)
	}
	// An old Xray setup may hold the port itself; anything else is a conflict.
	if l, err := net.Listen("tcp", ":"+port); err == nil {
		l.Close()
	} else if systemctl("is-active", "--quiet", svc) != nil {
		log.Fatalf("✗ порт %s/tcp занят: посмотри, кем — ss -tlnp | grep ':%s '", port, port)
	}
	return port
}

// askTarget asks for the site Reality impersonates and checks it the way a
// browser connects. Without a terminal a failed check stops the command.
func askTarget(p *prompter, flagTarget, host string) string {
	fmt.Println("\nСайт для маскировки: чужой сайт с TLS 1.3 и HTTP/2, лучше из той же подсети /24, что и сервер (найти: RealiTLScanner). Проверки ТСПУ увидят его вместо панели.")
	for {
		t := flagTarget
		if t == "" {
			t = p.need("Домен сайта: ")
		}
		t = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(t), "https://"), "/"))
		if h, _, err := net.SplitHostPort(t); err == nil {
			t = h
		}
		err := checkTarget(net.JoinHostPort(t, "443"), t)
		if err == nil {
			fmt.Printf("✓ %s: TLS 1.3, HTTP/2%s\n", t, subnetNote(t, host))
			return t
		}
		fmt.Printf("  ✗ %s: %v\n", t, err)
		if flagTarget != "" || p.in == nil {
			log.Fatal("✗ возьми другой сайт")
		}
		if p.yes("  Всё равно взять его?", false) {
			return t
		}
	}
}

// subnetNote says whether the site lives next to the server: a site from
// another network on this IP is easier to spot.
func subnetNote(domain, host string) string {
	mine, _ := net.LookupHost(host)
	theirs, _ := net.LookupHost(domain)
	net24 := func(a string) string {
		if ip := net.ParseIP(a).To4(); ip != nil {
			return ip.Mask(net.CIDRMask(24, 32)).String()
		}
		return ""
	}
	for _, a := range theirs {
		if n := net24(a); n != "" && slices.ContainsFunc(mine, func(m string) bool { return net24(m) == n }) {
			return ", в той же /24, что и сервер"
		}
	}
	return "; он в другой подсети, сосед по /24 был бы незаметнее"
}

// writeXrayConfig writes the new config after Xray's own check passed;
// otherwise the old one stays.
func writeXrayConfig(path string, orig, out []byte) {
	if len(orig) > 0 {
		step("backup → "+path+backupExt, backupOnce(path, orig))
	}
	// 0644 like the official installer: Xray runs as nobody.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err == nil {
		err = writeSync(f, out)
	}
	step("xray config "+path, err)
	if res, err := exec.Command(xrayBin, "run", "-test", "-c", path).CombinedOutput(); err != nil {
		left := "прежний конфиг Xray оставлен"
		var werr error
		if len(orig) > 0 {
			if f, werr = os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0); werr == nil {
				werr = writeSync(f, orig)
			}
		} else {
			left, werr = "конфиг Xray не записан", os.Remove(path)
		}
		if werr != nil {
			left = fmt.Sprintf("вернуть прежний конфиг не удалось (%v): он в %s", werr, path+backupExt)
		}
		log.Fatalf("✗ xray run -test: %v\n%s\n%s", err, bytes.TrimSpace(res), left)
	}
	step("xray run -test", nil)
}

// waitXray waits until Xray's API answers and the panel has put its users in.
func waitXray(xs *xraySetup, svc string) {
	// Read, not OpenStore: the starting panel owns the file now.
	var list []User
	b, _ := os.ReadFile(dataPath)
	json.Unmarshal(b, &list)
	want := 0
	for _, u := range list {
		if u.Blocked(time.Now()) == "" {
			want++
		}
	}
	api := newXrayAPI(xs.API)
	var users map[string]string
	var err error
	for i := 0; i < 30; i++ {
		if users, err = api.Users(xs.Tag); err == nil && len(users) >= want {
			step(fmt.Sprintf("xray: пользователей в VLESS: %d", len(users)), nil)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		log.Fatalf("✗ Xray не отвечает: %v\n  смотри: journalctl -u %s -n 30 --no-pager", err, svc)
	}
	fmt.Printf("  ✗ в Xray %d из %d пользователей — смотри journalctl -u hy-panel -n 30 --no-pager\n", len(users), want)
}

// ---- clients from before the panel ----

func saveXrayClients(clients []any) error {
	if fileExists(xrayClientsPath) {
		return nil // the first connect saved the originals
	}
	var b bytes.Buffer
	if err := encodeJSON(&b, clients, "  "); err != nil {
		return err
	}
	return writeAtomic(xrayClientsPath, b.Bytes(), 0o600)
}

// importXray brings the inbound's clients into the panel; with none in the
// config (a re-run after an interrupted connect), the saved ones.
func importXray(clients []any) error {
	store, err := OpenStore(dataPath)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(clients)
	if len(clients) == 0 {
		if b, err = os.ReadFile(xrayClientsPath); err != nil {
			return err
		}
	}
	var cs []xrayUser
	if err := json.Unmarshal(b, &cs); err != nil {
		return err
	}
	importXrayClients(store, cs)
	return nil
}

// importXrayClients makes the inbound's former clients panel users with
// their UUIDs, so their links work on: a panel user of the same name takes
// the client's UUID, the others are created.
func importXrayClients(s *Store, clients []xrayUser) {
	for _, c := range clients {
		id, err := xrayUUID(c.ID)
		if err != nil {
			fmt.Printf("  ✗ клиент Xray %q: %v\n", c.Email, err)
			continue
		}
		name := xrayName(c.Email, id)
		if u, ok := s.Get(name); ok {
			if u.UUID == id {
				continue // imported before
			}
			if _, err := s.Update(name, func(u *User) error { u.UUID = id; return nil }); err != nil {
				fmt.Printf("  ✗ клиент Xray %q: %v\n", c.Email, err)
			} else {
				fmt.Printf("✓ клиент Xray %q — это пользователь %q: его ссылка VLESS работает дальше\n", c.Email, name)
			}
			continue
		}
		if _, err := s.Create(User{Name: name, UUID: id, Enabled: true, Note: "imported (xray)"}, false); err != nil {
			fmt.Printf("  ✗ клиент Xray %q: %v\n", c.Email, err)
		} else {
			fmt.Printf("✓ клиент Xray %q перенесён как пользователь %q — его ссылка VLESS работает дальше\n", c.Email, name)
		}
	}
}

// xrayName is the panel name for a client: its e-mail (the part before @),
// else one made from the UUID.
func xrayName(email, id string) string {
	n, _, _ := strings.Cut(strings.ToLower(email), "@")
	if nameRe.MatchString(n) {
		return n
	}
	return "xray-" + id[:8]
}

// restoreXrayClients puts the clients saved by connectPanel back into the
// inbound (`uninstall -purge`). Returns false if none were saved.
func restoreXrayClients(cfgPath, savedPath string) (bool, error) {
	saved, err := os.ReadFile(savedPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var clients []any
	dec := json.NewDecoder(bytes.NewReader(saved))
	dec.UseNumber()
	v, err := decodeJSON(dec)
	if err != nil {
		return false, err
	}
	clients, _ = v.([]any)
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return false, err
	}
	d, err := parseXrayDoc(b)
	if err != nil {
		return false, err
	}
	in := d.inbound()
	if in == nil {
		return false, errors.New("нет inbound VLESS + Reality")
	}
	in.sub("settings").set("clients", clients)
	out, err := d.bytes()
	if err != nil {
		return false, err
	}
	return true, writeKeepingOwner(cfgPath, out)
}

// xrayPaths returns the Xray config path and service name.
func xrayPaths(env map[string]string) (cfg, svc string) {
	return envOr(env, "HYP_XRAY_CONFIG", defaultXrayCfg), envOr(env, "HYP_XRAY_SERVICE", defaultXraySvc)
}
