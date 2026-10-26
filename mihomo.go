package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// A complete mihomo config for a user: a template with routing rules
// (groups, rule-providers, rules) into which the panel puts the user's
// proxies. Groups take the proxies with include-all, in the order they
// stand: the panel's fallback order. The template is edited as text, a
// few top-level keys only, so its comments and layout stay as written.

//go:embed mihomo.yaml
var mihomoBuiltin []byte

// mihomoTemplatePath is the admin's own template; if present it replaces
// the built-in one (own rules, own domains stay off the repository).
var mihomoTemplatePath = "/etc/hy-panel/mihomo.yaml"

// mihomoRouterOnly are what a router (XKeen) needs and a computer does
// without: XKeen's ports and mark, and the controller Clash Verge runs itself.
var mihomoRouterOnly = []string{"redir-port", "tproxy-port", "routing-mark", "external-controller", "secret", "external-ui", "external-ui-url"}

func mihomoTemplate() ([]byte, error) {
	b, err := os.ReadFile(mihomoTemplatePath)
	if errors.Is(err, os.ErrNotExist) {
		return mihomoBuiltin, nil
	}
	return b, err
}

// MihomoFull is u's complete config from tmpl: the template's proxies are
// replaced by u's, the first rule sends the server itself direct (devices
// behind the router may run their own client to it), and the controller's
// secret is u's own. For a computer the router-only keys go.
func (e Endpoint) MihomoFull(tmpl []byte, u User, router bool) ([]byte, error) {
	t := topKeys(string(tmpl))

	direct := "DOMAIN," + e.Host + ",DIRECT"
	if ip := net.ParseIP(strings.Trim(e.Host, "[]")); ip != nil {
		bits := "/32"
		if ip.To4() == nil {
			bits = "/128"
		}
		direct = "IP-CIDR," + ip.String() + bits + ",DIRECT,no-resolve"
	}
	rules, ok := t.span("rules")
	if !ok || t.inline(rules) {
		return nil, errors.New("шаблон mihomo: нужен список rules в блочном виде (rules: и строки «  - …»)")
	}
	indent := "  "
	for _, l := range t.lines[rules.from+1 : rules.to] {
		if s := strings.TrimLeft(l, " "); strings.HasPrefix(s, "- ") {
			indent = l[:len(l)-len(s)]
			break
		}
	}
	t.insert(rules.from+1, indent+"- "+direct+" # свой сервер напрямую")

	if router {
		if s, ok := t.span("secret"); ok {
			sum := sha256.Sum256([]byte("mihomo-secret:" + u.SubToken))
			t.replace(s, "secret: '"+hex.EncodeToString(sum[:])[:16]+"' # пароль панели управления (zashboard)")
		}
	} else {
		for _, k := range mihomoRouterOnly {
			if s, ok := t.span(k); ok {
				t.replace(s)
			}
		}
	}

	doc := strings.TrimSuffix(e.MihomoDoc(u), "\n")
	if s, ok := t.span("proxies"); ok {
		t.replace(s, doc)
	} else if s, ok := t.span("proxy-groups"); ok {
		t.insert(s.from, doc, "")
	} else {
		t.lines = append(t.lines, doc)
	}

	out := []byte(strings.Join(t.lines, "\n"))
	// What the edits made must be what mihomo will read.
	var check struct {
		Proxies []struct{ Name string }
		Rules   []string
	}
	if err := yaml.Unmarshal(out, &check); err != nil {
		return nil, fmt.Errorf("шаблон mihomo: %v", err)
	}
	if len(check.Proxies) != len(e.userProtos(u)) || len(check.Rules) == 0 || check.Rules[0] != direct {
		return nil, errors.New("шаблон mihomo: proxies или rules не на верхнем уровне")
	}
	return out, nil
}

// yamlText is a YAML file as lines, with its top-level keys found by
// their place: a key at the start of a line.
type yamlText struct{ lines []string }

type textSpan struct{ from, to int } // lines [from, to) of one top-level key

func topKeys(s string) *yamlText { return &yamlText{strings.Split(s, "\n")} }

func topKey(l string) string {
	if l == "" || strings.ContainsRune(" \t#-", rune(l[0])) {
		return ""
	}
	k, _, ok := strings.Cut(l, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(k)
}

// span finds key's lines: up to the next top-level key, without the blank
// lines and comments that lead into it.
func (t *yamlText) span(key string) (textSpan, bool) {
	from := slices.IndexFunc(t.lines, func(l string) bool { return topKey(l) == key })
	if from < 0 {
		return textSpan{}, false
	}
	to := from + 1
	for to < len(t.lines) && topKey(t.lines[to]) == "" {
		to++
	}
	for to > from+1 && (strings.TrimSpace(t.lines[to-1]) == "" || strings.HasPrefix(t.lines[to-1], "#")) {
		to--
	}
	return textSpan{from, to}, true
}

// inline reports whether the key has its value on its own line (rules: []).
func (t *yamlText) inline(s textSpan) bool {
	_, v, _ := strings.Cut(t.lines[s.from], ":")
	v, _, _ = strings.Cut(v, "#")
	return strings.TrimSpace(v) != ""
}

func (t *yamlText) replace(s textSpan, with ...string) {
	t.lines = slices.Concat(t.lines[:s.from], with, t.lines[s.to:])
}

func (t *yamlText) insert(at int, lines ...string) {
	t.lines = slices.Concat(t.lines[:at], lines, t.lines[at:])
}
