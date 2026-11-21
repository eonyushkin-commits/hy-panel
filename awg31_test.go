package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAWG31OptionsRoundTrip(t *testing.T) {
	c := freshAWG()
	c.RandomTrailers = true
	c.DisableCookies = true
	c.H = [4]string{"100-199", "200-299", "300-399", "400-499"}
	c.I2 = "<b 0x01020304>"
	c.I3 = "<t>"
	c.I4 = "<rc 16>"
	c.I5 = "<rd 20>"
	c.PersistentKeepalive = "15-25"
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(c.awgObfuscation)
	var parsed awgObfuscation
	if err := parseAWGObfuscation(string(encoded), &parsed); err != nil || parsed != c.awgObfuscation {
		t.Fatal("JSON round trip lost options", err)
	}
	args, err := jobArgs("awg", map[string]string{"port": c.Port, "obfuscation": string(encoded)})
	if err != nil || args[len(args)-1] != "-obfuscation-stdin" || strings.Contains(strings.Join(args, " "), c.HeaderProtectionKey) {
		t.Fatal("agent lost options", args, err)
	}
	u := User{Name: "phone", AWGKey: newAWGTestKey(), AWGIndex: 2}
	e := Endpoint{Host: "203.0.113.7", AWG: c}
	server, err := awgServerConf(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range c.awgObfuscation.strings() {
		if pair[1] != "" {
			for _, text := range []string{server, e.AWGConf(u)} {
				if !strings.Contains(text, pair[0]+" = "+pair[1]) {
					t.Fatal("missing native option", pair[0])
				}
			}
		}
	}
	var mihomo struct {
		Proxies []struct {
			Options map[string]any `yaml:"amnezia-wg-option"`
		}
	}
	if err := yaml.Unmarshal([]byte(e.MihomoDoc(u)), &mihomo); err != nil {
		t.Fatal(err)
	}
	options := mihomo.Proxies[0].Options
	if options["version"] != 3 || options["random-trailers"] != true || options["disable-cookies"] != true || options["header-protection-key"] != c.HeaderProtectionKey || options["h1"] != "100-199" || options["i5"] != c.I5 {
		t.Fatal("Mihomo lost AWG 3.1 fields", options)
	}
	public := c.publicSettings()
	if !strings.Contains(e.AWGConf(u), "PersistentKeepalive = 15-25") || !strings.Contains(e.MihomoDoc(u), "persistent-keepalive: 15") {
		t.Fatal("keepalive range not exported correctly")
	}
	if _, exists := public["privateKey"]; exists {
		t.Fatal("server private key leaked into settings")
	}
	if public["headerProtectionKey"] != c.HeaderProtectionKey || public["s4"] != float64(24) {
		t.Fatal("settings lost options")
	}
}

func TestAWG31RejectsInconsistentOptions(t *testing.T) {
	for _, edit := range []func(*awgConfig){
		func(c *awgConfig) { c.RandomTrailers = true; c.S2++ },
		func(c *awgConfig) { c.S4 = 0 },
		func(c *awgConfig) { c.H[1] = "1-4294967295" },
		func(c *awgConfig) { c.H[1] = c.H[0] },
		func(c *awgConfig) { c.HeaderProtectionKey = "short" },
		func(c *awgConfig) { c.ContentPaddingAddition = "64" },
		func(c *awgConfig) { c.RekeyAfterTime = "250-300" },
		func(c *awgConfig) { c.RekeyTimeout = "7-4" },
		func(c *awgConfig) { c.MaxHandshakeAttempts = "0" },
		func(c *awgConfig) { c.I1 = "<r -1>" },
		func(c *awgConfig) { c.I2 = "<r 1000><r 1000>" },
		func(c *awgConfig) { c.I3 = "<unknown 10>" },
		func(c *awgConfig) { c.I4 = "<b 0xz1>" },
		func(c *awgConfig) { c.I5 = "<r 10>\nPostUp=id" },
	} {
		c := freshAWG()
		edit(c)
		if c.check() == nil {
			t.Fatalf("invalid AWG 3.1 options accepted: %+v", c.awgObfuscation)
		}
	}
	c := freshAWG()
	c.RandomTrailers = true
	if c.check() != nil {
		t.Fatal("generator is not suitable for random trailers")
	}
	if err := parseAWGObfuscation(`{"privateKey":"forbidden"}`, new(awgObfuscation)); err == nil {
		t.Fatal("untrusted server key accepted")
	}
}

func TestAWGJobKeepsSecretsOutOfArguments(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "stdin.json")
	t.Setenv("AWG_TEST_STDIN", capture)
	bin := filepath.Join(dir, "fake")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\"\ncat > \"$AWG_TEST_STDIN\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c := freshAWG()
	body, _ := json.Marshal(c.awgObfuscation)
	args, err := jobArgs("awg", map[string]string{"port": c.Port, "obfuscation": string(body)})
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{bin: bin}
	a.run(args, string(body))
	got, err := os.ReadFile(capture)
	if err != nil || string(got) != string(body) || !a.current().OK {
		t.Fatal("AWG options not delivered through stdin", err)
	}
	if strings.Contains(a.current().Log, c.HeaderProtectionKey) {
		t.Fatal("AWG shared key leaked into job log")
	}
}
