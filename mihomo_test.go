package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func fullFixture() (Endpoint, User) {
	xs, _ := parseXray(freshXray("443", "lurkpro.tech"))
	e := Endpoint{Host: "203.0.113.7", Port: "443", Name: "NL", Vless: &xs.Link, AWG: newAWGConfig(51820)}
	u := User{Name: "u", Password: "secret123", UUID: newUUID(), AWGKey: newWGKey(), AWGIndex: 2, SubToken: "tok-u"}
	return e, u
}

func TestMihomoFull(t *testing.T) {
	e, u := fullFixture()
	var cfg struct {
		Proxies []struct{ Name string }
		Rules   []string
		Secret  *string
		Tproxy  *int                    `yaml:"tproxy-port"`
		Groups  []struct{ Name string } `yaml:"proxy-groups"`
	}
	read := func(router bool) {
		t.Helper()
		b, err := e.MihomoFull(mihomoBuiltin, u, router)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Secret, cfg.Tproxy = nil, nil
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
	}
	read(true)
	if len(cfg.Proxies) != 3 || cfg.Proxies[0].Name != "NL-u" || cfg.Proxies[1].Name != "NL-u-awg" || cfg.Proxies[2].Name != "NL-u-vless" {
		t.Fatalf("proxies not in fallback order: %+v", cfg.Proxies)
	}
	if cfg.Rules[0] != "IP-CIDR,203.0.113.7/32,DIRECT,no-resolve" || cfg.Rules[len(cfg.Rules)-1] != "MATCH,DIRECT" {
		t.Fatalf("rules: %q … %q", cfg.Rules[0], cfg.Rules[len(cfg.Rules)-1])
	}
	if cfg.Secret == nil || len(*cfg.Secret) != 16 || cfg.Tproxy == nil || len(cfg.Groups) == 0 {
		t.Fatalf("router keys: secret=%v tproxy=%v groups=%d", cfg.Secret, cfg.Tproxy, len(cfg.Groups))
	}
	secret := *cfg.Secret
	read(true)
	if *cfg.Secret != secret {
		t.Fatal("secret changes between downloads")
	}
	u2 := u
	u2.SubToken = "tok-other"
	if b, _ := e.MihomoFull(mihomoBuiltin, u2, true); strings.Contains(string(b), secret) {
		t.Fatal("two users, one secret")
	}
	read(false)
	if cfg.Secret != nil || cfg.Tproxy != nil || len(cfg.Proxies) != 3 {
		t.Fatalf("desktop kept router keys: secret=%v tproxy=%v", cfg.Secret, cfg.Tproxy)
	}

	// A domain host, an IPv6 one; a user with some protocols off.
	for host, want := range map[string]string{"vpn.example.com": "DOMAIN,vpn.example.com,DIRECT", "2001:db8::1": "IP-CIDR,2001:db8::1/128,DIRECT,no-resolve"} {
		e2 := e
		e2.Host = host
		b, err := e2.MihomoFull(mihomoBuiltin, u, false)
		if err != nil || !strings.Contains(string(b), "\n  - "+want+" #") {
			t.Errorf("%s: %v", host, err)
		}
	}
	u3 := u
	u3.ProtoOff = []string{protoHy2, protoAWG}
	if b, err := e.MihomoFull(mihomoBuiltin, u3, false); err != nil || strings.Count(string(b), "\n  - name: \"NL-u") != 1 {
		t.Fatalf("one protocol: %v", err)
	}
}

func TestMihomoTemplates(t *testing.T) {
	e, u := fullFixture()
	// No proxies key: they go before the groups; comments and layout stay.
	tmpl := "# mine\nmode: rule\n\nproxy-groups:\n  - {name: G, type: select, include-all: true}\n\nrules:\n    - MATCH,G # all\n"
	b, err := e.MihomoFull([]byte(tmpl), u, true)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "# mine\nmode: rule\n\nproxies:\n  - name: \"NL-u\"") || !strings.Contains(s, "\n\nproxy-groups:\n") ||
		!strings.Contains(s, "rules:\n    - IP-CIDR,203.0.113.7/32,DIRECT,no-resolve # свой сервер напрямую\n    - MATCH,G # all\n") {
		t.Fatalf("%s", s)
	}
	for name, bad := range map[string]string{
		"flow rules": "proxies: []\nrules: [MATCH,DIRECT]\n",
		"no rules":   "proxies: []\nmode: rule\n",
		"broken":     "proxies: []\nrules:\n  - MATCH,DIRECT\n  bad: [\n",
	} {
		if _, err := e.MihomoFull([]byte(bad), u, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The admin's own template replaces the built-in one.
	defer func(p string) { mihomoTemplatePath = p }(mihomoTemplatePath)
	mihomoTemplatePath = filepath.Join(t.TempDir(), "mihomo.yaml")
	if b, err := mihomoTemplate(); err != nil || string(b) != string(mihomoBuiltin) {
		t.Fatalf("no file: %v", err)
	}
	os.WriteFile(mihomoTemplatePath, []byte(tmpl), 0o644)
	if b, err := mihomoTemplate(); err != nil || string(b) != tmpl {
		t.Fatalf("own template not taken: %v", err)
	}
}
