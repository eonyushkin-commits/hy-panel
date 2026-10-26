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
	"slices"
	"strconv"
	"strings"
	"time"
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

// runXray sets up VLESS + Reality in Xray, or points Reality at another
// site (`hy-panel xray`, run by the agent from the panel). Users stay the
// panel's: it puts them in through Xray's API. A config the panel did not
// write is replaced; the original stays in .bak-hy-panel.
func runXray(args []string) {
	fs := flag.NewFlagSet("xray", flag.ExitOnError)
	target := fs.String("target", "", "site Reality impersonates (SNI), e.g. www.example.com")
	port := fs.String("port", "443", "TCP port for VLESS, for a new setup")
	fs.Parse(args)
	needRoot("xray")
	env := readEnv()
	if !installed(env) {
		log.Fatal("✗ панель не установлена: сначала hy-panel install")
	}
	if err := checkEnv(env); err != nil {
		log.Fatal("✗ ", err)
	}
	site := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(*target), "https://"), "/"))
	if !validHostname(strings.TrimSuffix(site, ".")) || !strings.Contains(site, ".") {
		log.Fatalf("✗ -target %q: нужен домен сайта для маскировки", *target)
	}
	managed := env["HYP_XRAY_CONFIG"] != "" // the panel runs a config it wrote
	cfgPath, svc := xrayPaths(env)
	if !fileExists(xrayBin) || !unitExists(svc) {
		_, err := fetchXray()
		step("xray: официальный релиз", err)
	}
	if v := xrayVersion(); !v.atLeast(minXray) {
		log.Fatalf("✗ нужен Xray ≥ %s, установлен %s — обнови: hy-panel fetch xray", minXray, v)
	}
	orig, readErr := os.ReadFile(cfgPath)
	d, kind := classifyXray(orig, readErr)
	switch kind {
	case xrayUnreadable:
		log.Fatalf("✗ %v", readErr)
	case xrayBroken:
		log.Fatalf("✗ %s не читается как JSON — поправь его вручную", cfgPath)
	}
	if err := checkTarget(net.JoinHostPort(site, "443"), site); err != nil {
		log.Fatalf("✗ %s: %v — возьми другой сайт", site, err)
	}
	fmt.Printf("✓ %s: TLS 1.3, HTTP/2%s\n", site, subnetNote(site, env["HYP_HOST"]))

	var out []byte
	retarget := kind == xrayVless && managed
	if retarget {
		var c xrayConfig
		json.Unmarshal(stripComments(orig), &c)
		cur, err := vlessLink(c.vlessInbound())
		if err != nil {
			log.Fatalf("✗ VLESS в конфиге Xray: %v", err)
		}
		if cur.SNI == site {
			fmt.Println("Ничего не изменилось.")
			return
		}
		d.setTarget(site)
		out, err = d.bytes()
		step("render xray config", err)
	} else {
		if kind != xrayNone {
			fmt.Printf("Конфиг Xray писала не панель — настраиваю заново, прежний сохранится в %s.\n", cfgPath+backupExt)
		}
		out = freshXray(xrayPort(*port, svc), site)
	}
	xs, err := parseXray(out)
	step("check new xray config", err)

	noInterrupt()
	writeXrayConfig(cfgPath, orig, out)
	ufwAllow(xs.Link.Port + "/tcp")
	step("enable "+svc, systemctl("enable", svc))
	env["HYP_XRAY_CONFIG"] = cfgPath
	step("settings → "+envPath, writeEnv(env))
	step("restart "+svc, systemctl("restart", svc))
	step("restart hy-panel", systemctl("restart", "hy-panel")) // the panel puts its users into Xray
	waitXray(xs, svc)

	if retarget {
		fmt.Printf("\nГотово. Сайт для маскировки теперь %s: подписка обновится сама, остальным клиентам — новые ссылки VLESS (кнопка QR в панели).\n", xs.Link.SNI)
		return
	}
	fmt.Printf("\nГотово. VLESS + Reality: порт %s/tcp, %s, сайт для маскировки %s.\n", xs.Link.Port, xs.Link.Network, xs.Link.SNI)
	fmt.Println("Ссылки VLESS пользователей — в панели (кнопка QR); подписка и mihomo отдают их вместе с остальными.")
}

// xrayPort checks the port for a new setup: free, or held by Xray itself.
func xrayPort(port, svc string) string {
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		log.Fatalf("✗ -port %q: нужен порт 1–65535", port)
	}
	if l, err := net.Listen("tcp", ":"+port); err == nil {
		l.Close()
	} else if systemctl("is-active", "--quiet", svc) != nil {
		log.Fatalf("✗ порт %s/tcp занят: посмотри, кем — ss -tlnp | grep ':%s '", port, port)
	}
	return port
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

// xrayPaths returns the Xray config path and service name.
func xrayPaths(env map[string]string) (cfg, svc string) {
	return envOr(env, "HYP_XRAY_CONFIG", defaultXrayCfg), envOr(env, "HYP_XRAY_SERVICE", defaultXraySvc)
}
