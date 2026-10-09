package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustCreate(t *testing.T, s *Store, u User, legacy bool) User {
	t.Helper()
	u.Enabled = true
	got, err := s.Create(u, legacy)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestResolve(t *testing.T) {
	s := newStore(t)
	mustCreate(t, s, User{Name: "Phone", Password: "secret123"}, false)
	mustCreate(t, s, User{Name: "default", Password: "old:legacy pw"}, true)

	cases := map[string]string{
		"phone:secret123": "phone",
		"PHONE:secret123": "phone", // Hysteria userpass: names are case-insensitive
		"secret123":       "phone", // bare password
		"old:legacy pw":   "default",
		"phone:wrong":     "",
		"":                "",
		"default:":        "",
	}
	for auth, want := range cases {
		u, ok := s.Resolve(auth)
		if got := map[bool]string{true: u.Name}[ok]; got != want {
			t.Errorf("Resolve(%q) = %q, want %q", auth, got, want)
		}
	}
}

func TestPasswordRules(t *testing.T) {
	s := newStore(t)
	a := mustCreate(t, s, User{Name: "a"}, false)
	if len(a.Password) != 20 {
		t.Fatalf("generated password %q", a.Password)
	}
	for _, pw := range []string{"short", "has:colon1", "has space1", a.Password} {
		if _, err := s.Create(User{Name: "b", Password: pw}, false); err == nil {
			t.Errorf("Create with password %q succeeded", pw)
		}
	}
	if _, err := s.Create(User{Name: "Bad Name"}, false); err == nil {
		t.Error("bad name accepted")
	}
	b := mustCreate(t, s, User{Name: "b"}, false)
	// Duplicate on update is rejected and leaves the user untouched.
	if _, err := s.Update("b", func(u *User) error { u.Password = a.Password; u.Note = "x"; return nil }); err == nil {
		t.Fatal("duplicate password accepted on update")
	}
	if got, _ := s.Get("b"); got.Password != b.Password || got.Note != "" {
		t.Fatalf("failed update changed user: %+v", got)
	}
	// Persisted and reloadable.
	s2, err := OpenStore(s.path)
	if err != nil || len(s2.List()) != 2 {
		t.Fatalf("reload: %v %d", err, len(s2.List()))
	}
}

func TestBlockedAndMonthlyReset(t *testing.T) {
	s := newStore(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.Local)
	mustCreate(t, s, User{Name: "q", QuotaBytes: 100}, false)
	s.Tick(now, map[string]trafficEntry{"q": {Tx: 40, Rx: 60}}, nil)
	if u, _ := s.Get("q"); u.Blocked(now) != "quota" || u.Up != 40 || u.Down != 60 {
		t.Fatalf("quota: %+v %q", u, u.Blocked(now))
	}
	// Enabling monthly reset mid-month must not reset right away...
	s.Update("q", func(u *User) error {
		on := true
		userPatch{ResetMonthly: &on}.apply(u, now)
		return nil
	})
	s.Tick(now, nil, nil)
	if u, _ := s.Get("q"); u.Up+u.Down != 100 {
		t.Fatalf("reset too early: %+v", u)
	}
	// ...but on the next month.
	s.Tick(now.AddDate(0, 1, -8), nil, nil)
	if u, _ := s.Get("q"); u.Up+u.Down != 0 || u.Blocked(now) != "" {
		t.Fatalf("no monthly reset: %+v", u)
	}
	exp := User{Enabled: true, ExpiresAt: now.Unix()}
	if exp.Blocked(now) != "expired" || exp.Blocked(now.Add(-time.Second)) != "" {
		t.Fatal("expiry boundary")
	}
}

// ---- certificates & links ----

func writeCert(t *testing.T, dir string, selfSigned bool, dns ...string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	parent, signer := tmpl, key
	if !selfSigned {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		parent = &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		signer = caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "cert.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return p
}

func TestReadCertAndEndpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := &hyConfig{Listen: ":8443"}
	cfg.Obfs.Type, cfg.Obfs.Salamander.Password = "salamander", "ob"

	// Self-signed with a DNS SAN: pinned, and SNI must be the SAN (sniGuard dns-san).
	p := writeCert(t, dir, true, "bing.com")
	ci, err := readCert(p)
	if err != nil || !ci.SelfSigned || ci.DNSName != "bing.com" {
		t.Fatalf("self-signed: %+v %v", ci, err)
	}
	b, _ := os.ReadFile(p)
	blk, _ := pem.Decode(b)
	sum := sha256.Sum256(blk.Bytes)
	if ci.Pin != hex.EncodeToString(sum[:]) {
		t.Fatal("pin is not sha256 of leaf DER")
	}
	ep := buildEndpoint(cfg, ci, "", "203.0.113.7", "", "", "AMS")
	if ep.SNI != "bing.com" || ep.Port != "8443" || ep.Pin == "" {
		t.Fatalf("endpoint: %+v", ep)
	}

	// CA-issued (e.g. Let's Encrypt): never pinned; domain becomes host, SNI implied.
	ci, _ = readCert(writeCert(t, dir, false, "vpn.example.com"))
	if ci.SelfSigned || ci.Pin != "" {
		t.Fatalf("CA cert pinned: %+v", ci)
	}
	ep = buildEndpoint(cfg, ci, "", "", "", "", "")
	if ep.Host != "vpn.example.com" || ep.SNI != "" {
		t.Fatalf("CA endpoint: %+v", ep)
	}
}

func TestURIAndMihomo(t *testing.T) {
	ep := Endpoint{Host: "203.0.113.7", Port: "8443", SNI: "bing.com", ObfsType: "salamander", ObfsPass: "o&b=f", Pin: strings.Repeat("ab", 32), Name: "AMS"}
	u := User{Name: "phone", Password: "Pw123456"}

	// Parse the way Hysteria's parseURI does.
	v, err := url.Parse(ep.URI(u))
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := v.User.Password()
	q := v.Query()
	if v.Scheme != "hysteria2" || v.User.Username()+":"+pw != "phone:Pw123456" || v.Host != "203.0.113.7:8443" ||
		q.Get("obfs") != "salamander" || q.Get("obfs-password") != "o&b=f" || q.Get("sni") != "bing.com" ||
		q.Get("insecure") != "1" || q.Get("pinSHA256") != ep.Pin || v.Fragment != "AMS-phone" {
		t.Fatalf("URI: %s", ep.URI(u))
	}

	ep.Port = "20000-50000"
	if !strings.Contains(ep.URI(u), "@203.0.113.7:20000-50000/") {
		t.Fatalf("hop URI: %s", ep.URI(u))
	}
	var doc struct{ Proxies []map[string]any }
	if err := yaml.Unmarshal([]byte(ep.MihomoDoc(u)), &doc); err != nil || len(doc.Proxies) != 1 {
		t.Fatalf("mihomo yaml: %v\n%s", err, ep.Mihomo(u))
	}
	m := doc.Proxies[0]
	if m["password"] != "phone:Pw123456" || m["port"] != 20000 || m["ports"] != "20000-50000" ||
		m["fingerprint"] != ep.Pin || m["obfs-password"] != "o&b=f" || m["skip-cert-verify"] != nil || m["sni"] != "bing.com" {
		t.Fatalf("mihomo: %v", m)
	}
}

func TestLoadHyConfigKeysCaseInsensitive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte(`
listen: :8443
TrafficStats: {Listen: 127.0.0.1:25413, secret: s}
auth:
  type: userpass
  userpass: {Evo: "p:1", 42: two}
`), 0o600)
	c, err := loadHyConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.TrafficStats.Listen != "127.0.0.1:25413" || c.Auth.UserPass["evo"] != "p:1" || c.Auth.UserPass["42"] != "two" {
		t.Fatalf("%+v", c)
	}
}

// ---- enforcement against an exact model of Hysteria's trafficStats ----

// fakeHy mirrors extras/trafficlogger/http.go: OnlineMap counts sessions per ID,
// KickMap holds one-shot flags consumed by the next traffic of any session.
type fakeHy struct {
	mu      sync.Mutex
	conns   map[string]int
	kick    map[string]bool
	traffic map[string]trafficEntry
	kicks   int
	failOn  bool
	race    bool // consume a pending kick right after answering /online (traffic between our two calls)
}

func newFakeHy(t *testing.T) (*fakeHy, *statsClient) {
	f := &fakeHy{conns: map[string]int{}, kick: map[string]bool{}, traffic: map[string]trafficEntry{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/traffic":
			json.NewEncoder(w).Encode(f.traffic)
			f.traffic = map[string]trafficEntry{}
		case "/online":
			if f.failOn {
				http.Error(w, "boom", 500)
				return
			}
			on := map[string]int{}
			for id, n := range f.conns {
				if n > 0 {
					on[id] = n
				}
			}
			json.NewEncoder(w).Encode(on)
			for id := range f.kick {
				if f.race && f.conns[id] > 0 {
					delete(f.kick, id)
					f.conns[id]--
				}
			}
		case "/kick":
			var ids []string
			json.NewDecoder(r.Body).Decode(&ids)
			for _, id := range ids {
				f.kick[id] = true
			}
			f.kicks++
		}
	}))
	t.Cleanup(srv.Close)
	return f, &statsClient{base: srv.URL, hc: srv.Client()}
}

func (f *fakeHy) connect(id string) { f.mu.Lock(); f.conns[id]++; f.mu.Unlock() }

// send: a session of id moves bytes; a pending kick closes it instead.
func (f *fakeHy) send(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.kick[id] {
		delete(f.kick, id)
		f.conns[id]--
		return
	}
	e := f.traffic[id]
	e.Rx += 1000
	f.traffic[id] = e
}

func (f *fakeHy) state() (conns, kicks int, flag bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.conns {
		n += c
	}
	return n, f.kicks, len(f.kick) > 0
}

func newApp(t *testing.T, sc *statsClient) *App {
	return &App{store: newStore(t), stats: sc, online: map[string]int{}, revoked: map[string]revocation{},
		kicked: map[string]int{}, poke: make(chan struct{}, 1)}
}

func TestEnforceLeavesNoStaleKicks(t *testing.T) {
	f, sc := newFakeHy(t)
	a := newApp(t, sc)
	mustCreate(t, a.store, User{Name: "u"}, false)
	tick := func() { a.syncOnce(time.Now()) }

	// Two active sessions, user disabled: one kick at a time, both closed, no flag left.
	f.connect("u")
	f.connect("u")
	tick()
	a.store.Update("u", func(u *User) error { u.Enabled = false; return nil })
	for i := 0; i < 6; i++ {
		tick()
		f.send("u")
	}
	tick()
	if conns, kicks, flag := f.state(); conns != 0 || flag || kicks != 2 {
		t.Fatalf("active: conns=%d kicks=%d staleFlag=%v", conns, kicks, flag)
	}

	// Idle session: kicked once, not re-kicked every tick.
	f.connect("u")
	for i := 0; i < 5; i++ {
		tick()
	}
	if _, kicks, _ := f.state(); kicks != 3 {
		t.Fatalf("idle session re-kicked: kicks=%d", kicks)
	}
	f.send("u") // idle session wakes up and is closed
	tick()
	if conns, _, flag := f.state(); conns != 0 || flag {
		t.Fatalf("idle: conns=%d flag=%v", conns, flag)
	}

	// The pending kick is consumed between our /online and /kick calls: the
	// stale online count must not trigger a kick that nothing will consume.
	f.connect("u")
	tick() // kick #4
	f.race = true
	tick() // sees 1 online, but that session closes right after
	f.race = false
	tick()
	if conns, kicks, flag := f.state(); conns != 0 || flag || kicks != 4 {
		t.Fatalf("race: conns=%d kicks=%d staleFlag=%v", conns, kicks, flag)
	}

	// Re-enabled user: new sessions live.
	a.store.Update("u", func(u *User) error { u.Enabled = true; return nil })
	f.connect("u")
	tick()
	f.send("u")
	tick()
	if conns, kicks, _ := f.state(); conns != 1 || kicks != 4 {
		t.Fatalf("re-enabled user affected: conns=%d kicks=%d", conns, kicks)
	}
}

func TestPasswordChangeRevokesSessions(t *testing.T) {
	f, sc := newFakeHy(t)
	a := newApp(t, sc)
	mustCreate(t, a.store, User{Name: "u"}, false)
	mustCreate(t, a.store, User{Name: "off"}, false)
	f.connect("u")
	a.syncOnce(time.Now())

	patch := func(name string) {
		r := httptest.NewRequest("PATCH", "/api/users/"+name, strings.NewReader(`{"newKey":true}`))
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		a.handlePatch(w, r)
		if w.Code != 200 {
			t.Fatalf("patch: %d %s", w.Code, w.Body)
		}
	}
	patch("u")
	patch("off") // offline user: nothing to drop, and no flag may be left
	a.syncOnce(time.Now().Add(time.Millisecond))
	f.send("u")
	a.syncOnce(time.Now().Add(2 * time.Millisecond))
	if conns, kicks, flag := f.state(); conns != 0 || kicks != 1 || flag {
		t.Fatalf("revoke: conns=%d kicks=%d flag=%v", conns, kicks, flag)
	}
	// Client with the new key connects: not touched.
	f.connect("u")
	a.syncOnce(time.Now().Add(3 * time.Millisecond))
	f.send("u")
	if conns, _, _ := f.state(); conns != 1 {
		t.Fatal("new session after re-key was kicked")
	}
}

func TestTrafficKeptWhenOnlineFails(t *testing.T) {
	f, sc := newFakeHy(t)
	a := newApp(t, sc)
	mustCreate(t, a.store, User{Name: "u"}, false)
	f.connect("u")
	f.send("u")
	f.failOn = true
	a.syncOnce(time.Now())
	if u, _ := a.store.Get("u"); u.Down != 1000 {
		t.Fatalf("traffic lost when /online failed: %+v", u)
	}
	if a.hyErr == "" {
		t.Fatal("error not reported")
	}
}

func TestAuthEndpoint(t *testing.T) {
	_, sc := newFakeHy(t)
	a := newApp(t, sc)
	u := mustCreate(t, a.store, User{Name: "u", MaxDevices: 1}, false)
	call := func(remote, auth string, hdr ...string) (int, map[string]any) {
		r := httptest.NewRequest("POST", "/auth", strings.NewReader(`{"addr":"1.2.3.4:5","auth":"`+auth+`","tx":0}`))
		r.RemoteAddr = remote
		if len(hdr) == 2 {
			r.Header.Set(hdr[0], hdr[1])
		}
		w := httptest.NewRecorder()
		a.handleAuth(w, r)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := call("127.0.0.1:4000", "u:"+u.Password); code != 200 || out["ok"] != true || out["id"] != "u" {
		t.Fatalf("valid auth: %d %v", code, out)
	}
	if code, _ := call("192.0.2.1:4000", "u:"+u.Password); code != 403 {
		t.Fatalf("non-loopback: %d", code)
	}
	if code, _ := call("127.0.0.1:4000", "u:"+u.Password, "X-Forwarded-For", "8.8.8.8"); code != 403 {
		t.Fatalf("proxied: %d", code)
	}
}

func TestReadECH(t *testing.T) {
	dir := t.TempDir()
	cfg := []byte{0xfe, 0x0d, 0x00, 0x03, 1, 2, 3} // opaque config bytes
	priv := []byte{9, 9}
	keys := binary.BigEndian.AppendUint16(nil, uint16(len(priv)))
	keys = append(keys, priv...)
	keys = binary.BigEndian.AppendUint16(keys, uint16(len(cfg)))
	keys = append(keys, cfg...)
	want := base64.StdEncoding.EncodeToString(append(binary.BigEndian.AppendUint16(nil, uint16(len(cfg))), cfg...))

	p := filepath.Join(dir, "keys.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: keys}), 0o600)
	if got, err := readECH(p); err != nil || got != want {
		t.Fatalf("from ECH KEYS: %q %v", got, err)
	}
	if got, _ := readECH(""); got != "" {
		t.Fatal("no ech.keyPath must give empty")
	}
	ep := Endpoint{Host: "h", Port: "443", ECH: want}
	u := User{Name: "a", Password: "Pw123456"}
	if v, _ := url.Parse(ep.URI(u)); v.Query().Get("ech") != want {
		t.Fatalf("URI: %s", ep.URI(u))
	}
	var doc struct{ Proxies []map[string]any }
	yaml.Unmarshal([]byte(ep.MihomoDoc(u)), &doc)
	if o, _ := doc.Proxies[0]["ech-opts"].(map[string]any); o["enable"] != true || o["config"] != want {
		t.Fatalf("mihomo ech-opts: %v", doc.Proxies[0])
	}
}

func TestPortRangeListen(t *testing.T) {
	c := &hyConfig{Listen: ":20000-50000"} // Hysteria 2.8+ listens on a UDP range itself
	if ep := buildEndpoint(c, certInfo{}, "", "1.2.3.4", "", "", ""); ep.Port != "20000-50000" {
		t.Fatalf("port %q", ep.Port)
	}
}

func TestPatchHyConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	orig := "# my server\nlisten: :8443 # port\nobfs:\n  type: salamander\n  salamander:\n    password: ob\nAuth:\n  type: password\n  password: old\n"
	os.WriteFile(p, []byte(orig), 0o640)
	changed, err := patchHyConfig(p)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	c, err := loadHyConfig(p)
	if err != nil || c.Auth.Type != "http" || c.Auth.HTTP.URL != "http://127.0.0.1:8090/auth" ||
		c.TrafficStats.Listen != "127.0.0.1:25413" || len(c.TrafficStats.Secret) != 32 || c.Obfs.Salamander.Password != "ob" {
		t.Fatalf("%+v %v", c, err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# my server") || strings.Count(strings.ToLower(string(b)), "auth:") != 1 {
		t.Fatalf("comments/dup keys:\n%s", b)
	}
	if bak, _ := os.ReadFile(p + backupExt); string(bak) != orig {
		t.Fatal("backup")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatal("mode changed")
	}
	if changed, _ := patchHyConfig(p); changed {
		t.Fatal("second run must be a no-op")
	}
}

func TestUnderPath(t *testing.T) {
	h := underPath("/secret12/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.URL.Path)) }))
	for path, want := range map[string]int{"/": 404, "/api/state": 404, "/secret12": 302, "/secret12/": 200, "/secret12/api/state": 200, "/secret123/": 404} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Errorf("%s: %d, want %d", path, w.Code, want)
		}
	}
}

func TestNeedsFreshConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	cases := map[string]bool{
		filepath.Join(dir, "missing.yaml"): true,
		write("template.yaml", "# listen: :443\n\nacme:\n  domains:\n    - your.domain.net\n  email: your@email.com\n"): true,
		write("generated.yaml", generatedMark+"\nlisten: :443\n\nobfs:\n  type: salamander\n"):                          false,
		write("custom.yaml", "listen: :8443\nacme:\n  domains:\n    - vpn.example.com\n"):                               false,
	}
	for p, want := range cases {
		if got := needsFreshConfig(p); got != want {
			t.Errorf("needsFreshConfig(%s) = %v, want %v", filepath.Base(p), got, want)
		}
	}
}
