package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/model"
)

func newAWGTestKey() string { return model.NewAWGKey() }

func TestAWGMigrationAndRekey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	key := model.NewAWGKey()
	legacy := fmt.Sprintf(`[{"name":"old","password":"original-password","subToken":"original-token","enabled":true,"awgKey":%q,"awgIndex":2,"protoOff":["awg","vless"]},{"name":"new","password":"other-password","enabled":true}]`, key)
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get("old")
	other, _ := s.Get("new")
	if u.AWGKey != key || u.AWGIndex != 2 || u.Uses(protoAWG) || u.Uses(protoVlessTCP) || other.AWGIndex != 3 {
		t.Fatal("migration changed access or address", u, other)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := reopened.Get("new")
	if again.AWGKey != other.AWGKey || again.AWGIndex != other.AWGIndex {
		t.Fatal("AWG identity changed after restart")
	}
	(userPatch{NewKey: true}).apply(&u, time.Now())
	if u.AWGKey == key || u.AWGIndex != 2 {
		t.Fatal("rekey did not rotate only the key")
	}
	_, err = s.Update("new", func(p *User) error { p.AWGIndex = 2; return nil })
	if err == nil {
		t.Fatal("duplicate address accepted")
	}
	if _, err := os.Stat(path + ".pre-v2"); err != nil {
		t.Fatal("no migration backup", err)
	}
	if backup, err := os.ReadFile(path + ".pre-protocols-v3"); err != nil || string(backup) != legacy {
		t.Fatal("protocol migration backup missing or changed", err)
	}
}

func TestAWGProfilesAndValidation(t *testing.T) {
	c := freshAWG()
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	u := User{Name: "phone", AWGKey: model.NewAWGKey(), AWGIndex: 258}
	e := Endpoint{Host: "2001:db8::1", AWG: c}
	conf := e.AWGConf(u)
	for _, part := range []string{"Address = 10.77.1.2/32, fd77:77::102/128", "Endpoint = [2001:db8::1]:51820", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25", c.obfuscation()} {
		if !strings.Contains(conf, part) {
			t.Fatalf("missing %q", part)
		}
	}
	if !strings.Contains(conf, "RandomTrailers = off") || !strings.Contains(conf, "DisableCookies = off") || !strings.Contains(conf, "HeaderProtectionKey = ") {
		t.Fatal("AWG 3.1 defaults missing or unsafe")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix((awgProto{}).Link(e, u), "vpn://"))
	if err != nil || string(decoded) != conf {
		t.Fatal("share link differs from .conf")
	}
	for _, edit := range []func(*awgConfig){
		func(c *awgConfig) { c.Port = "443\nPostUp=id" }, func(c *awgConfig) { c.Subnet = "0.0.0.0/16" }, func(c *awgConfig) { c.Subnet = "10.0.0.1/16" }, func(c *awgConfig) { c.MTU = 9000 }, func(c *awgConfig) { c.H[1] = c.H[0] }, func(c *awgConfig) { c.S2 = c.S1 + 56 }, func(c *awgConfig) { c.DNS = "1.1.1.1\nPostUp=id" }, func(c *awgConfig) { c.DNS = "127.0.0.1" },
	} {
		bad := *c
		edit(&bad)
		if bad.check() == nil {
			t.Fatal("invalid config accepted", bad)
		}
	}
	pub, _ := model.AWGPublicKey(u.AWGKey)
	peers := []awgPeer{{"phone", pub, 258}}
	text, err := awgServerConf(c, peers)
	if err != nil || !strings.Contains(text, "AllowedIPs = 10.77.1.2/32, fd77:77::102/128") {
		t.Fatal(text, err)
	}
	if _, err := awgServerConf(c, append(peers, peers[0])); err == nil {
		t.Fatal("duplicate peer accepted")
	}
	peers[0].PublicKey += "\nPostUp=id"
	if _, err := awgServerConf(c, peers); err == nil {
		t.Fatal("config injection accepted")
	}
}

func TestAWGCountersAndAccess(t *testing.T) {
	u := User{Name: "phone", AWGKey: model.NewAWGKey(), AWGIndex: 2, Enabled: true}
	pub, _ := model.AWGPublicKey(u.AWGKey)
	now := time.Now()
	snapshot := awgSnapshot{Epoch: "first", Peers: map[string]awgCounter{pub: {Rx: 100, Tx: 200, Handshake: now.Unix()}}}
	var pushed []awgPeer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			writeJSON(w, snapshot)
		} else {
			json.NewDecoder(r.Body).Decode(&pushed)
			writeJSON(w, struct{}{})
		}
	}))
	defer srv.Close()
	b := &awgBackend{agent: &agentClient{hc: &http.Client{Transport: rewriteAgentTransport{srv.URL}}}}
	tr, on, err := b.stats(now, []User{u})
	if err != nil || len(tr) != 0 || on.users[u.Name] != 1 {
		t.Fatal(tr, on, err)
	}
	snapshot.Peers[pub] = awgCounter{Rx: 160, Tx: 290, Handshake: now.Unix()}
	tr, _, err = b.stats(now, []User{u})
	if err != nil || tr[u.Name].Tx != 60 || tr[u.Name].Rx != 90 {
		t.Fatal(tr, err)
	}
	tr, _, _ = b.stats(now, []User{u})
	if tr[u.Name].Tx != 0 || tr[u.Name].Rx != 0 {
		t.Fatal("double charged", tr)
	}
	snapshot.Peers[pub] = awgCounter{Rx: 5, Tx: 9}
	tr, _, _ = b.stats(now, []User{u})
	if tr[u.Name].Tx != 5 || tr[u.Name].Rx != 9 {
		t.Fatal("counter reset lost", tr)
	}
	snapshot.Epoch = "restart"
	snapshot.Peers[pub] = awgCounter{Rx: 500, Tx: 900}
	tr, _, _ = b.stats(now, []User{u})
	if len(tr) != 0 {
		t.Fatal("adopted counters double charged", tr)
	}
	if err := b.push(now, []User{u}); err != nil || len(pushed) != 1 {
		t.Fatal(pushed, err)
	}
	for _, edit := range []func(*User){func(u *User) { u.Enabled = false }, func(u *User) { u.ProtoOff = []string{protoAWG} }, func(u *User) { u.ExpiresAt = now.Unix() }, func(u *User) { u.QuotaBytes = 1; u.Up = 1 }} {
		blocked := u
		edit(&blocked)
		if err := b.push(now, []User{blocked}); err != nil || len(pushed) != 0 {
			t.Fatal("blocked peer retained", pushed, err)
		}
	}
	if err := b.push(now, nil); err != nil || len(pushed) != 0 {
		t.Fatal("deleted peer retained", err)
	}
}

// The agent client uses a fixed URL with a Unix transport in production.
type rewriteAgentTransport struct{ base string }

func (tr rewriteAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	copyURL := *r.URL
	r.URL = &copyURL
	parts := strings.SplitN(strings.TrimPrefix(tr.base, "http://"), "/", 2)
	r.URL.Host = parts[0]
	return http.DefaultTransport.RoundTrip(r)
}

type fakeAWGOS struct {
	config        *awgConfig
	exists, table bool
	alias         string
	commands      []string
	confs         []string
	fail          string
}

func (f *fakeAWGOS) run(input, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	f.commands = append(f.commands, command)
	if f.fail != "" && strings.Contains(command, f.fail) {
		return nil, errors.New("injected failure")
	}
	switch {
	case strings.HasPrefix(command, "ip -j link show"):
		if !f.exists {
			return nil, errors.New("Device does not exist")
		}
		b, _ := json.Marshal([]map[string]string{{"ifalias": f.alias}})
		return b, nil
	case strings.Contains(command, " public-key"):
		pub, _ := model.AWGPublicKey(f.config.PrivateKey)
		return []byte(pub), nil
	case command == "ip -j route get 1.1.1.1":
		return []byte(`[{"dev":"eth0"}]`), nil
	case command == "ip -j route show table all":
		return []byte(`[{"dst":"default","dev":"eth0"}]`), nil
	case strings.HasPrefix(command, "ip link add"):
		f.exists = true
	case strings.HasPrefix(command, "ip link del"):
		f.exists = false
	case strings.Contains(command, " alias "):
		f.alias = args[len(args)-1]
	case strings.Contains(command, "awg syncconf"):
		b, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		f.confs = append(f.confs, string(b))
	case command == "nft -j list table inet "+awgTable:
		if !f.table {
			return nil, errors.New("No such file or directory")
		}
		return []byte(`{"nftables":[{"table":{"comment":"hy-panel AWG"}}]}`), nil
	case command == "nft -f -":
		if !strings.Contains(input, "meta nfproto ipv6 drop") || !strings.Contains(input, "169.254.0.0/16") {
			return nil, errors.New("missing private/IPv6 isolation")
		}
		f.table = true
	case strings.HasPrefix(command, "nft delete"):
		f.table = false
	case strings.HasPrefix(command, "iptables -w 5 -C"):
		return nil, errors.New("rule absent")
	}
	return nil, nil
}

func fakeAWGCommands(t *testing.T, c *awgConfig) *fakeAWGOS {
	t.Helper()
	original, dir := awgExec, awgRuntimeDir
	awgRuntimeDir = t.TempDir()
	f := &fakeAWGOS{config: c}
	awgExec = f.run
	t.Cleanup(func() { awgExec = original; awgRuntimeDir = dir })
	return f
}

func TestAWGOwnershipFirewallAndRecovery(t *testing.T) {
	c := freshAWG()
	f := fakeAWGCommands(t, c)
	m := &awgRuntime{}
	u := User{Name: "phone", AWGKey: model.NewAWGKey(), AWGIndex: 2}
	pub, _ := model.AWGPublicKey(u.AWGKey)
	if err := m.ensure(c, []awgPeer{{u.Name, pub, 2}}); err != nil {
		t.Fatal(err)
	}
	if !f.exists || !f.table || !m.ready || len(f.confs) != 2 || strings.Contains(f.confs[0], "[Peer]") || !strings.Contains(f.confs[1], pub) {
		t.Fatal("unsafe startup order", f.commands)
	}
	epoch := m.epoch
	if err := m.ensure(c, nil); err != nil {
		t.Fatal(err)
	}
	if m.epoch != epoch {
		t.Fatal("sync restarted interface")
	}
	f.alias = "foreign"
	f.commands = nil
	if err := m.ensure(c, nil); err == nil {
		t.Fatal("foreign interface adopted")
	}
	if err := m.revoke(); err == nil {
		t.Fatal("foreign ownership mismatch hidden")
	}
	if err := m.down(); err == nil {
		t.Fatal("foreign interface removed")
	}
	for _, command := range f.commands {
		if !strings.HasPrefix(command, "ip -j link show") {
			t.Fatal("foreign interface modified", command)
		}
	}
	f.alias = awgAlias(c)
	if err := m.revoke(); err != nil || strings.Contains(f.confs[len(f.confs)-1], "[Peer]") {
		t.Fatal("lease revocation failed", err)
	}
	if err := m.down(); err != nil || f.exists || f.table {
		t.Fatal("cleanup failed", err)
	}
	f.fail = "nft -f -"
	if err := m.ensure(c, []awgPeer{{u.Name, pub, 2}}); err == nil {
		t.Fatal("firewall failure hidden")
	}
	if strings.Contains(f.confs[len(f.confs)-1], "[Peer]") {
		t.Fatal("peers enabled before firewall was ready")
	}
}

func TestAWGDumpRejectsBadCounters(t *testing.T) {
	dump := "private\tpublic\t51820\toff\npeer\t(none)\tendpoint\t10.77.0.2/32\t100\t20\t30\t0\n"
	peers, err := parseAWGDump(dump)
	if err != nil || peers["peer"] != (awgCounter{Rx: 20, Tx: 30, Handshake: 100}) {
		t.Fatal(peers, err)
	}
	for _, bad := range []string{"", strings.Replace(dump, "\t20\t", "\t-1\t", 1), strings.Replace(dump, "\t30\t", "\toverflow\t", 1), "private public 51820 off\nbroken"} {
		if _, err := parseAWGDump(bad); err == nil {
			t.Fatal("bad dump accepted", bad)
		}
	}
}

func TestSeparateVlessProfiles(t *testing.T) {
	xhttp, err := parseXray(freshXray("443", "example.org"))
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := parseXray(freshTCPXray("8443", "example.org"))
	if err != nil {
		t.Fatal(err)
	}
	if xhttp.API == tcp.API || xhttp.Tag == tcp.Tag || tcp.Link.Flow != visionFlow || xhttp.Link.Flow != "" {
		t.Fatal("profiles are not independent")
	}
	_, apiA := newFakeXray(t)
	_, apiB := newFakeXray(t)
	a, b := &xrayBackend{api: apiA, tag: "in"}, &xrayBackend{api: apiB, tag: "in", id: protoVlessTCP, flow: visionFlow}
	u := User{Name: "phone", Enabled: true, UUID: newUUID(), ProtoOff: []string{protoVless}}
	if err := a.push(time.Now(), []User{u}); err != nil {
		t.Fatal(err)
	}
	if err := b.push(time.Now(), []User{u}); err != nil {
		t.Fatal(err)
	}
	haveA, _ := apiA.usersContext(t.Context(), "in")
	haveB, _ := apiB.usersContext(t.Context(), "in")
	if len(haveA) != 0 || !reflect.DeepEqual(haveB, map[string]string{u.Name: u.UUID}) {
		t.Fatal(haveA, haveB)
	}
}
