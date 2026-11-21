//go:build e2e

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eonyushkin-commits/hy-panel/internal/model"
)

func TestE2EAWGNativeConfig(t *testing.T) {
	bin := os.Getenv("AWG_TOOL_BIN")
	if bin == "" {
		t.Skip("AWG_TOOL_BIN not set")
	}
	if os.Geteuid() == 0 {
		t.Skip("native parser check runs without root and never changes a real interface")
	}
	c := freshAWG()
	c.RandomTrailers = true
	c.DisableCookies = true
	c.H = [4]string{"100-199", "200-299", "300-399", "400-499"}
	c.I2 = "<b 0x01020304>"
	c.I3 = "<t>"
	c.I4 = "<rc 16>"
	c.I5 = "<rd 20>"
	c.PersistentKeepalive = "15-25"
	u := User{Name: "phone", AWGKey: newAWGTestKey(), AWGIndex: 2}
	pub, _ := model.AWGPublicKey(u.AWGKey)
	// Server peers and the client use the panel's actual exporters.
	server, err := awgServerConf(c, []awgPeer{{Name: u.Name, PublicKey: pub, Index: u.AWGIndex}})
	if err != nil {
		t.Fatal(err)
	}
	client := (Endpoint{Host: "203.0.113.7", AWG: c}).AWGConf(u)
	var nativeClient []string
	for _, line := range strings.Split(client, "\n") {
		if !strings.HasPrefix(line, "Address =") && !strings.HasPrefix(line, "DNS =") && !strings.HasPrefix(line, "MTU =") {
			nativeClient = append(nativeClient, line)
		}
	}
	for name, text := range map[string]string{"server": server, "client": strings.Join(nativeClient, "\n")} {
		path := filepath.Join(t.TempDir(), name+".conf")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "setconf", "hyp-awg-check", path).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "Unable to modify interface") {
			t.Fatalf("native parser rejected %s config before kernel access: %v\n%s", name, err, out)
		}
	}
}

func TestE2EAWGFirewall(t *testing.T) {
	if os.Getenv("HYP_AWG_NFT_CHECK") != "1" {
		t.Skip("opt-in nftables check")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if self == init || os.Geteuid() != 0 {
		t.Fatal("run this test as root inside a disposable network namespace")
	}
	c := freshAWG()
	run := func(check bool, rules string) {
		args := []string{"-f", "-"}
		if check {
			args = append([]string{"-c"}, args...)
		}
		cmd := exec.Command("nft", args...)
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
	}
	run(true, awgFirewall(c, "eth0", false))
	run(false, awgFirewall(c, "eth0", false))
	run(true, awgFirewall(c, "eth0", true))
}
