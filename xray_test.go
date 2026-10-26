package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// docConfig is the hand-made setup from the usual VLESS + Reality + XHTTP
// guide: one client, no API, no statistics.
const docConfig = `{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "2b1c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d", "email": "router" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "xhttpSettings": { "path": "/a1b2c3d4e5f6", "mode": "auto" },
      "security": "reality",
      "realitySettings": {
        "target": "lurkpro.tech:443",
        "serverNames": ["lurkpro.tech"],
        "privateKey": "-BVYrlVsLzsIPyIbW600E9Vaag234BXJaAM4vMqUU3o",
        "shortIds": ["0123456789abcdef"]
      }
    },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }
  }],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": { "rules": [{ "ip": ["geoip:private"], "outboundTag": "block" }] }
}`

// ---- a model of Xray's API as the panel uses it ----

// fakeXray serves HandlerService and StatsService over cleartext HTTP/2
// gRPC with the semantics of Xray's: e-mails are unique (case-insensitively),
// QueryStats with reset zeroes counters, unknown online maps are NotFound.
type fakeXray struct {
	mu      sync.Mutex
	users   map[string]string // inbound "in": e-mail → UUID
	flows   map[string]string
	traffic map[string]trafficEntry
	online  map[string]int
	down    bool
	oldErr  bool // GetStatsOnline answers like Xray before NotFound
}

func newFakeXray(t *testing.T) (*fakeXray, *xrayAPI) {
	f := &fakeXray{users: map[string]string{}, flows: map[string]string{}, traffic: map[string]trafficEntry{}, online: map[string]int{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return f, newXrayAPI(srv.Listener.Addr().String())
}

func (f *fakeXray) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.ProtoMajor != 2 || r.Header.Get("Content-Type") != "application/grpc" || len(body) < 5 ||
		int(binary.BigEndian.Uint32(body[1:])) != len(body)-5 {
		http.Error(w, "not grpc", http.StatusBadRequest)
		return
	}
	msg := body[5:]
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	fail := func(code int, m string) { // trailers-only, like grpc-go
		h.Set("Grpc-Status", strconv.Itoa(code))
		h.Set("Grpc-Message", url.PathEscape(m))
	}
	reply := func(b []byte) {
		h.Set("Trailer", "Grpc-Status")
		w.Write(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(b))))
		w.Write(b)
		h.Set("Grpc-Status", "0")
	}
	if f.down {
		fail(14, "unavailable")
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/xray.app.") {
	case "proxyman.command.HandlerService/AlterInbound":
		if string(pbGet(msg, 1)) != "in" {
			fail(2, "failed to get handler")
			return
		}
		op := pbGet(msg, 2)
		switch string(pbGet(op, 1)) {
		case "xray.app.proxyman.command.AddUserOperation":
			user := pbGet(pbGet(op, 2), 1)
			email, account := string(pbGet(user, 2)), pbGet(user, 3)
			if string(pbGet(account, 1)) != "xray.proxy.vless.Account" {
				fail(2, "bad account")
				return
			}
			for e := range f.users {
				if strings.EqualFold(e, email) {
					fail(2, "User "+email+" already exists.")
					return
				}
			}
			f.users[email] = string(pbGet(pbGet(account, 2), 1))
			f.flows[email] = string(pbGet(pbGet(account, 2), 2))
		case "xray.app.proxyman.command.RemoveUserOperation":
			email := string(pbGet(pbGet(op, 2), 1))
			if _, ok := f.users[email]; !ok {
				fail(2, "User "+email+" not found.")
				return
			}
			delete(f.users, email)
		default:
			fail(2, "unknown operation")
			return
		}
		reply(nil)
	case "proxyman.command.HandlerService/GetInboundUsers":
		var out []byte
		for e, id := range f.users {
			acct := typedMessage("xray.proxy.vless.Account", pbString(nil, 1, id))
			out = pbBytes(out, 1, pbBytes(pbString(nil, 2, e), 3, acct))
		}
		reply(out)
	case "stats.command.StatsService/QueryStats":
		var out []byte
		stat := func(name string, v int64) {
			out = pbBytes(out, 1, binary.AppendUvarint(append(pbString(nil, 1, name), 2<<3), uint64(v)))
		}
		for e, tr := range f.traffic {
			stat("user>>>"+e+">>>traffic>>>uplink", tr.Tx)
			stat("user>>>"+e+">>>traffic>>>downlink", tr.Rx)
		}
		stat("inbound>>>in>>>traffic>>>uplink", 999) // not a user's: ignored
		reset := false
		pbFields(msg, func(f int, v uint64, _ []byte) error {
			reset = reset || f == 2 && v == 1
			return nil
		})
		if reset {
			f.traffic = map[string]trafficEntry{}
		}
		reply(out)
	case "stats.command.StatsService/GetStatsOnline":
		name := string(pbGet(msg, 1))
		e := strings.TrimSuffix(strings.TrimPrefix(name, "user>>>"), ">>>online")
		n, ok := f.online[e]
		if !ok {
			if f.oldErr {
				fail(2, "app/stats/command: "+name+" not found.")
			} else {
				fail(grpcNotFound, name+" not found.")
			}
			return
		}
		reply(pbBytes(nil, 1, binary.AppendUvarint(append(pbString(nil, 1, name), 2<<3), uint64(n))))
	default:
		fail(12, "unimplemented")
	}
}

func (f *fakeXray) snapshot() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := map[string]string{}
	for k, v := range f.users {
		m[k] = v
	}
	return m
}

func xrayApp(t *testing.T) (*App, *fakeHy, *fakeXray) {
	hy, sc := newFakeHy(t)
	fx, api := newFakeXray(t)
	a := testApp(t, sc)
	a.addBackend(&xrayBackend{api: api, tag: "in"})
	return a, hy, fx
}

func TestXrayUsersFollowPanel(t *testing.T) {
	a, _, fx := xrayApp(t)
	alice := mustCreate(t, a.store, User{Name: "alice"}, false)
	bob := mustCreate(t, a.store, User{Name: "bob"}, false)
	mustCreate(t, a.store, User{Name: "off"}, false)
	a.store.Update("off", func(u *User) error { u.Enabled = false; return nil })
	// Xray's own leftovers: a stranger, a disabled user, alice with an old key.
	fx.users["stranger"], fx.users["off"], fx.users["alice"] = newUUID(), "x", newUUID()

	a.syncOnce(time.Now())
	if syncState(a, protoVless).err != "" {
		t.Fatal(syncState(a, protoVless).err)
	}
	want := map[string]string{"alice": alice.UUID, "bob": bob.UUID}
	if got := fx.snapshot(); !mapsEqual(got, want) {
		t.Fatalf("xray users %v, want %v", got, want)
	}

	// Re-key: the old UUID is gone, the new one is in.
	patch(t, a, "alice", `{"newKey":true}`)
	a.syncOnce(time.Now())
	if u, _ := a.store.Get("alice"); u.UUID == alice.UUID || fx.snapshot()["alice"] != u.UUID {
		t.Fatalf("re-key: %v", fx.snapshot())
	}
	// Quota used up over VLESS: out at the same sync that counted it.
	a.store.Update("bob", func(u *User) error { u.QuotaBytes = 100; return nil })
	fx.traffic["bob"] = trafficEntry{Tx: 60, Rx: 60}
	a.syncOnce(time.Now())
	if _, in := fx.snapshot()["bob"]; in {
		t.Fatal("over-quota user still in Xray")
	}
	// Deleted.
	a.store.Delete("alice")
	a.syncOnce(time.Now())
	// Xray restarted: its config lists nobody, the panel puts users back.
	a.store.Update("bob", func(u *User) error { u.QuotaBytes = 0; return nil })
	fx.users = map[string]string{}
	a.syncOnce(time.Now())
	if got := fx.snapshot(); !mapsEqual(got, map[string]string{"bob": bob.UUID}) {
		t.Fatalf("after restart %v", got)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func patch(t *testing.T, a *App, name, body string) {
	t.Helper()
	r := httptest.NewRequest("PATCH", "/api/users/"+name, strings.NewReader(body))
	r.SetPathValue("name", name)
	w := httptest.NewRecorder()
	a.handlePatch(w, r)
	if w.Code != 200 {
		t.Fatalf("patch: %d %s", w.Code, w.Body)
	}
}

func TestXrayTrafficAndOnline(t *testing.T) {
	for _, old := range []bool{false, true} {
		a, hy, fx := xrayApp(t)
		fx.oldErr = old
		mustCreate(t, a.store, User{Name: "u"}, false)
		mustCreate(t, a.store, User{Name: "idle"}, false)
		hy.connect("u")
		hy.send("u") // Rx 1000 over Hysteria
		fx.traffic["u"] = trafficEntry{Tx: 5, Rx: 7}
		fx.online["u"] = 2
		a.syncOnce(time.Now())
		if syncState(a, protoVless).err != "" {
			t.Fatalf("old=%v: %s", old, syncState(a, protoVless).err)
		}
		u, _ := a.store.Get("u")
		if u.Up != 5 || u.Down != 1007 || a.onlineOf(protoVless)["u"] != 2 || a.onlineOf(protoHy2)["u"] != 1 || len(a.onlineOf(protoVless)) != 1 {
			t.Fatalf("old=%v: %+v xonline=%v online=%v", old, u, a.onlineOf(protoVless), a.onlineOf(protoHy2))
		}
		// Counters were reset by the read: nothing is counted twice.
		a.syncOnce(time.Now())
		if u, _ := a.store.Get("u"); u.Up != 5 {
			t.Fatalf("counted twice: %+v", u)
		}
	}
}

func TestXrayDownKeepsHysteria(t *testing.T) {
	a, hy, fx := xrayApp(t)
	mustCreate(t, a.store, User{Name: "u"}, false)
	fx.down = true
	hy.connect("u")
	hy.send("u")
	a.syncOnce(time.Now())
	a.syncOnce(time.Now())
	if u, _ := a.store.Get("u"); u.Down != 1000 || syncState(a, protoHy2).err != "" || !strings.Contains(syncState(a, protoVless).err, "unavailable") {
		t.Fatalf("%+v hyErr=%q xrayErr=%q", u, syncState(a, protoHy2).err, syncState(a, protoVless).err)
	}
	fx.down = false
	a.syncOnce(time.Now())
	if syncState(a, protoVless).err != "" || len(fx.snapshot()) != 1 {
		t.Fatalf("after recovery: %q %v", syncState(a, protoVless).err, fx.snapshot())
	}
}

func TestXrayAPIErrors(t *testing.T) {
	_, api := newFakeXray(t)
	err := api.RemoveUser("in", "nobody")
	var ge *grpcError
	if !strings.Contains(err.Error(), "User nobody not found.") || !errors.As(err, &ge) || ge.code != 2 {
		t.Fatalf("%v", err)
	}
	if err := api.AddUser("other", "a", newUUID(), ""); err == nil {
		t.Fatal("unknown inbound accepted")
	}
	if _, err := newXrayAPI("127.0.0.1:1").Users("in"); err == nil {
		t.Fatal("no error without a server")
	}
}

func TestProtobufRoundTrip(t *testing.T) {
	b := pbBool(pbString(pbBytes(nil, 3, []byte{}), 1, strings.Repeat("ж", 100)), 2, true)
	b = append(b, 5<<3|5, 1, 2, 3, 4) // fixed32 field: skipped
	got := map[int]string{}
	if err := pbFields(b, func(f int, v uint64, d []byte) error {
		got[f] = string(d) + strconv.FormatUint(v, 10)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got[1] != strings.Repeat("ж", 100)+"0" || got[2] != "1" || got[3] != "0" || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	for _, bad := range [][]byte{{0x0a, 5, 'a'}, {0x80}, {0x0f}} {
		if pbFields(bad, func(int, uint64, []byte) error { return nil }) == nil {
			t.Errorf("malformed %x accepted", bad)
		}
	}
}

// ---- config, keys, links ----

func TestRealityKeysAndUUIDs(t *testing.T) {
	// Vectors from `xray x25519 -i` and `xray uuid -i`.
	for priv, pub := range map[string]string{
		"-BVYrlVsLzsIPyIbW600E9Vaag234BXJaAM4vMqUU3o": "wLjgv5mWQQe69yuB1ZhFEXLu1bs1NTUH12NJDlHzb0c",
		"aGVsbG8taHktcGFuZWwtcmVhbGl0eS10ZXN0LWtleTE": "vYxQN3KPVtPhLk_hN_ckeUWn5w3rPERyCMlFgRvAfnE", // unclamped: same as Xray
	} {
		if got, err := realityPublicKey(priv); err != nil || got != pub {
			t.Errorf("public key of %s = %s, %v", priv, got, err)
		}
	}
	if _, err := realityPublicKey("c2hvcnQ"); err == nil {
		t.Error("short key accepted")
	}
	if _, err := realityPublicKey(newRealityKey()); err != nil {
		t.Error(err)
	}
	for id, want := range map[string]string{
		"my-secret":                            "b9fedf3b-ab02-5906-b6de-c5b0af9884b4",
		"router":                               "a90a1c2f-d1c0-5dad-bc5e-3b0a0352a8cd",
		"2B1C3D4E-5F60-4A7B-8C9D-0E1F2A3B4C5D": "2b1c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
		"2b1c3d4e5f604a7b8c9d0e1f2a3b4c5d":     "2b1c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
	} {
		if got, err := xrayUUID(id); err != nil || got != want {
			t.Errorf("xrayUUID(%q) = %s, %v", id, got, err)
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", 31), "zz1c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"} {
		if _, err := xrayUUID(bad); err == nil {
			t.Errorf("xrayUUID(%q) accepted", bad)
		}
	}
	if u := newUUID(); len(u) != 36 || u[14] != '4' {
		t.Errorf("uuid %s", u)
	}
}

func TestParseXray(t *testing.T) {
	// The guide's config is not usable as is: no tag, no API.
	if _, err := parseXray([]byte(docConfig)); err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("doc config: %v", err)
	}
	xs, err := parseXray(freshXray("8443", "lurkpro.tech"))
	if err != nil {
		t.Fatal(err)
	}
	l := xs.Link
	if xs.Tag != xrayTag || xs.API != xrayAPIAddr || xs.Warn != "" || l.Port != "8443" || l.SNI != "lurkpro.tech" ||
		l.Target != "lurkpro.tech:443" || l.Network != "xhttp" || l.Flow != "" || l.Mode != "auto" ||
		len(l.Path) != 13 || len(l.ShortID) != 16 || len(l.PublicKey) != 43 {
		t.Fatalf("%+v", xs)
	}

	edit := func(f func(d *xrayDoc)) []byte {
		d, err := parseXrayDoc(freshXray("443", "a.example"))
		if err != nil {
			t.Fatal(err)
		}
		f(d)
		b, _ := d.bytes()
		return b
	}
	stream := func(d *xrayDoc) *jobj { return d.inbound().obj("streamSettings") }
	for name, c := range map[string]struct {
		cfg  []byte
		want string // error, or "" for ok
	}{
		"vless encryption": {edit(func(d *xrayDoc) { d.inbound().obj("settings").set("decryption", "mlkem768x25519plus.native.0rtt.x") }), "decryption"},
		"grpc":             {edit(func(d *xrayDoc) { stream(d).set("network", "grpc") }), "network"},
		"port range":       {edit(func(d *xrayDoc) { d.inbound().set("port", "1000-2000") }), "port"},
		"no api":           {edit(func(d *xrayDoc) { d.root.obj("api").set("listen", ""); d.root.obj("api").set("tag", "") }), "api"},
		"no stats service": {edit(func(d *xrayDoc) { d.root.obj("api").set("services", []any{"HandlerService"}) }), "StatsService"},
		"vision on xhttp": {edit(func(d *xrayDoc) {
			d.inbound().obj("settings").set("clients", []any{newObjKV("id", newUUID(), "flow", visionFlow)})
		}), "flow"},
		"bad key":         {edit(func(d *xrayDoc) { stream(d).obj("realitySettings").set("privateKey", "nope") }), "privateKey"},
		"tcp gets vision": {edit(func(d *xrayDoc) { stream(d).set("network", "raw") }), ""},
		"legacy api inbound": {edit(func(d *xrayDoc) {
			d.root.obj("api").set("listen", "")
			ins, _ := d.root.get("inbounds").([]any)
			d.root.set("inbounds", append(ins, newObjKV("tag", "api", "listen", "127.0.0.1", "port", json.Number("10086"), "protocol", "dokodemo-door")))
		}), ""},
	} {
		xs, err := parseXray(c.cfg)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", name, err, c.want)
		case name == "tcp gets vision" && (xs.Link.Network != "tcp" || xs.Link.Flow != visionFlow):
			t.Errorf("%s: %+v", name, xs.Link)
		case name == "legacy api inbound" && xs.API != "127.0.0.1:10086":
			t.Errorf("%s: %s", name, xs.API)
		}
	}
	noStats := edit(func(d *xrayDoc) { d.root.obj("policy").obj("levels").obj("0").set("statsUserOnline", false) })
	if xs, err := parseXray(noStats); err != nil || !strings.Contains(xs.Warn, "статистика") {
		t.Fatalf("no online stats: %v %+v", err, xs)
	}
}

func newObjKV(kv ...any) *jobj {
	o := newObj()
	for i := 0; i+1 < len(kv); i += 2 {
		o.set(kv[i].(string), kv[i+1])
	}
	return o
}

func TestConnectPanelEditsInPlace(t *testing.T) {
	src := strings.Replace(docConfig, `"log": { "loglevel": "warning" },`, "// managed by hand\n  \"log\": { \"loglevel\": \"warning\" }, /* level */", 1)
	d, kind := classifyXray([]byte(src), nil)
	if kind != xrayVless {
		t.Fatalf("kind %d", kind)
	}
	clients := d.connectPanel()
	out, _ := d.bytes()
	xs, err := parseXray(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if xs.Tag != xrayTag || xs.API != xrayAPIAddr || xs.Warn != "" || xs.Link.SNI != "lurkpro.tech" || xs.Link.Path != "/a1b2c3d4e5f6" {
		t.Fatalf("%+v", xs)
	}
	var c xrayConfig
	json.Unmarshal(out, &c)
	if n := len(c.vlessInbound().Settings.Clients); n != 0 || len(clients) != 1 {
		t.Fatalf("clients left in config: %d, taken: %d", n, len(clients))
	}
	// Key order stays: the original keys first, in their order; new ones after.
	keys := d.root.keys
	if !slices.Equal(keys, []string{"log", "inbounds", "outbounds", "routing", "api", "stats", "policy"}) {
		t.Fatalf("top-level keys %v", keys)
	}
	if k := d.inbound().keys; !slices.Equal(k, []string{"listen", "port", "protocol", "settings", "streamSettings", "sniffing", "tag"}) {
		t.Fatalf("inbound keys %v", k)
	}
	if !strings.Contains(string(out), `"geoip:private"`) {
		t.Fatalf("%s", out)
	}

	// The site changes under the key the config uses.
	dest := strings.Replace(docConfig, `"target"`, `"dest"`, 1)
	d2, _ := classifyXray([]byte(dest), nil)
	d2.setTarget("api.ilexa.online")
	b, _ := d2.bytes()
	if s := string(b); strings.Contains(s, `"target"`) || !strings.Contains(s, `"dest": "api.ilexa.online:443"`) || !strings.Contains(s, `"api.ilexa.online"`) {
		t.Fatalf("%s", b)
	}
}

func TestClassifyXray(t *testing.T) {
	other := `{"inbounds": [{"port": 1080, "protocol": "socks"}]}`
	for src, want := range map[string]xrayKind{
		"":                           xrayNone,
		"{}":                         xrayNone,
		"// nothing yet\n":           xrayNone,
		`{"inbounds": []}`:           xrayNone,
		other:                        xrayOther,
		docConfig:                    xrayVless,
		"{":                          xrayBroken,
		"[1]":                        xrayBroken,
		`{"inbounds": 5}`:            xrayBroken,
		`{"a": 1} {"b": 2}`:          xrayBroken,
		`{"x": "#not // a comment"}`: xrayNone,
	} {
		if _, got := classifyXray([]byte(src), nil); got != want {
			t.Errorf("classify %q = %d, want %d", src, got, want)
		}
	}
	if _, k := classifyXray(nil, os.ErrNotExist); k != xrayNone {
		t.Error("missing file")
	}
	if _, k := classifyXray(nil, os.ErrPermission); k != xrayUnreadable {
		t.Error("unreadable file")
	}
}

func TestStripComments(t *testing.T) {
	src := "{\"a\": \"x // y # z /* w */\", // c1\n# c2\n\"b\": /* c3 */ 1, \"c\": \"q\\\"//\"}"
	var m map[string]any
	if err := json.Unmarshal(stripComments([]byte(src)), &m); err != nil || m["a"] != "x // y # z /* w */" || m["b"] != 1.0 || m["c"] != `q"//` {
		t.Fatalf("%v %v: %s", m, err, stripComments([]byte(src)))
	}
}

func TestVlessLinks(t *testing.T) {
	xs, err := parseXray(freshXray("443", "lurkpro.tech"))
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{Host: "195.63.134.68", Port: "443", Name: "NL", Vless: &xs.Link}
	u := User{Name: "phone", Password: "Pw123456", UUID: newUUID()}

	// The link as the guide builds it by hand.
	v, err := url.Parse(ep.VlessURI(u))
	if err != nil {
		t.Fatal(err)
	}
	q := v.Query()
	if v.Scheme != "vless" || v.User.Username() != u.UUID || v.Host != "195.63.134.68:443" || v.Fragment != "NL-phone-vless" ||
		q.Get("encryption") != "none" || q.Get("security") != "reality" || q.Get("sni") != "lurkpro.tech" || q.Get("fp") != "safari" ||
		q.Get("pbk") != xs.Link.PublicKey || q.Get("sid") != xs.Link.ShortID || q.Get("type") != "xhttp" ||
		q.Get("path") != xs.Link.Path || q.Get("mode") != "auto" || q.Has("flow") {
		t.Fatalf("%s", ep.VlessURI(u))
	}
	if !strings.Contains(ep.VlessURI(u), "path=%2F") {
		t.Fatalf("path not escaped: %s", ep.VlessURI(u))
	}

	// mihomo: both proxies in one provider document.
	ep.Vless.ShortID = "12345678" // digits only: must stay a string
	var doc struct{ Proxies []map[string]any }
	if err := yaml.Unmarshal([]byte(ep.MihomoDoc(u)), &doc); err != nil || len(doc.Proxies) != 2 {
		t.Fatalf("%v\n%s", err, ep.MihomoDoc(u))
	}
	m := doc.Proxies[1]
	xo, _ := m["xhttp-opts"].(map[string]any)
	ro, _ := m["reality-opts"].(map[string]any)
	if m["type"] != "vless" || m["name"] != "NL-phone-vless" || m["uuid"] != u.UUID || m["port"] != 443 || m["servername"] != "lurkpro.tech" ||
		m["network"] != "xhttp" || m["tls"] != true || m["client-fingerprint"] != "safari" || m["flow"] != nil ||
		xo["path"] != xs.Link.Path || ro["public-key"] != xs.Link.PublicKey || ro["short-id"] != "12345678" {
		t.Fatalf("%v", m)
	}

	// tcp: Vision flow in both.
	tcp := *ep.Vless
	tcp.Network, tcp.Flow = "tcp", visionFlow
	ep.Vless = &tcp
	if q := mustQuery(t, ep.VlessURI(u)); q.Get("flow") != visionFlow || q.Get("type") != "tcp" || q.Has("path") {
		t.Fatalf("%s", ep.VlessURI(u))
	}
	if s := ep.MihomoVless(u); !strings.Contains(s, "flow: "+visionFlow) || strings.Contains(s, "xhttp") {
		t.Fatal(s)
	}

	// VLESS off: nothing of it anywhere.
	ep.Vless = nil
	if ep.VlessURI(u) != "" || ep.MihomoVless(u) != "" || len(ep.URIs(u)) != 1 {
		t.Fatal("VLESS parts without VLESS")
	}
}

func TestSubscriptionHasBothProtocols(t *testing.T) {
	a, _, _ := xrayApp(t)
	xs, _ := parseXray(freshXray("443", "lurkpro.tech"))
	a.ep = Endpoint{Host: "203.0.113.7", Port: "443", ObfsType: "salamander", ObfsPass: "o", Vless: &xs.Link}
	u := mustCreate(t, a.store, User{Name: "u"}, false)
	get := func(q, ua string) string {
		r := httptest.NewRequest("GET", "/sub/"+u.SubToken+q, nil)
		r.SetPathValue("token", u.SubToken)
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		a.handleSub(w, r)
		return w.Body.String()
	}
	b, _ := base64.StdEncoding.DecodeString(get("", "Happ/1.0"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "hysteria2://") || lines[1] != a.ep.VlessURI(u) {
		t.Fatalf("%q", lines)
	}
	if raw := get("?format=raw", ""); strings.Count(raw, "\n") != 2 {
		t.Fatalf("raw: %q", raw)
	}
	if y := get("", "clash.meta/1.19"); !strings.Contains(y, "type: hysteria2") || !strings.Contains(y, "type: vless") {
		t.Fatalf("mihomo: %s", y)
	}

	// A broken Xray config: no links at all, clients keep what works.
	a.cfgErr = "конфиг Xray: boom"
	if w := httptest.NewRecorder(); a.noLinks(w) == false || w.Code != 503 {
		t.Fatal("links served with a broken config")
	}
}

func TestStateShowsVless(t *testing.T) {
	a, _, fx := xrayApp(t)
	xs, _ := parseXray(freshXray("443", "lurkpro.tech"))
	a.ep = Endpoint{Host: "203.0.113.7", Port: "443", Vless: &xs.Link}
	mustCreate(t, a.store, User{Name: "u"}, false)
	fx.online["u"] = 1
	a.syncOnce(time.Now())
	w := httptest.NewRecorder()
	a.handleState(w, httptest.NewRequest("GET", "/api/state", nil))
	var st struct {
		Users []struct {
			Online map[string]int `json:"online"`
			Links  []link         `json:"links"`
		}
		Server struct{ Vless map[string]any }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || len(st.Users) != 1 || len(st.Users[0].Links) != 2 ||
		!strings.HasPrefix(st.Users[0].Links[1].URI, "vless://") || st.Users[0].Online[protoVless] != 1 ||
		len(st.Users[0].Online) != 1 || st.Server.Vless["sni"] != "lurkpro.tech" {
		t.Fatalf("%v %s", err, w.Body)
	}
}

// ---- users: UUIDs, import ----

func TestStoreGivesOldUsersUUIDs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "users.json")
	os.WriteFile(p, []byte(`[{"name":"old","password":"pw123456","enabled":true}]`), 0o600)
	s, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get("old")
	s2, _ := OpenStore(p) // written at once: the key must not change on the next start
	if u2, _ := s2.Get("old"); len(u.UUID) != 36 || u2.UUID != u.UUID {
		t.Fatalf("%q %q", u.UUID, u2.UUID)
	}
	if _, err := s.Create(User{Name: "dup", UUID: u.UUID}, false); err == nil {
		t.Fatal("duplicate UUID accepted")
	}
}

func TestImportXrayClients(t *testing.T) {
	s := newStore(t)
	router := mustCreate(t, s, User{Name: "router"}, false) // also a Hysteria user
	id1 := "2b1c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"
	id3 := newUUID()
	clients := []xrayUser{{ID: id1, Email: "Router"}, {ID: "my-secret", Email: "phone@home"}, {ID: id3}, {ID: "bad id that is far too long to be a uuid"}}
	importXrayClients(s, clients)
	importXrayClients(s, clients) // a re-run changes nothing
	r, _ := s.Get("router")
	p, _ := s.Get("phone")
	x, ok := s.Get("xray-" + id3[:8])
	if r.UUID != id1 || r.Password != router.Password || p.UUID != "b9fedf3b-ab02-5906-b6de-c5b0af9884b4" || !ok || x.UUID != id3 || len(s.List()) != 3 {
		t.Fatalf("%+v %+v %+v %v", r, p, x, s.List())
	}
}

func TestRestoreXrayClients(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	d, _ := classifyXray([]byte(docConfig), nil)
	clients := d.connectPanel()
	out, _ := d.bytes()
	os.WriteFile(cfg, out, 0o644)
	saved := filepath.Join(dir, "clients.json")
	var b strings.Builder
	encodeJSON(&b, clients, "  ")
	os.WriteFile(saved, []byte(b.String()), 0o600)

	ok, err := restoreXrayClients(cfg, saved)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	var c xrayConfig
	nb, _ := os.ReadFile(cfg)
	json.Unmarshal(nb, &c)
	if cl := c.vlessInbound().Settings.Clients; len(cl) != 1 || cl[0].Email != "router" {
		t.Fatalf("%s", nb)
	}
	if ok, err := restoreXrayClients(cfg, filepath.Join(dir, "none.json")); ok || err != nil {
		t.Fatal("nothing saved: nothing to restore")
	}
}

func TestCheckEnvXray(t *testing.T) {
	if checkEnv(map[string]string{"HYP_XRAY_CONFIG": "config.json"}) == nil {
		t.Fatal("relative path accepted")
	}
	if err := checkEnv(map[string]string{"HYP_XRAY_CONFIG": defaultXrayCfg}); err != nil {
		t.Fatal(err)
	}
}

// ---- protocols per user ----

func TestUserProtocolsOff(t *testing.T) {
	a, hy, fx := xrayApp(t)
	xs, _ := parseXray(freshXray("443", "lurkpro.tech"))
	a.ep = Endpoint{Host: "203.0.113.7", Port: "443", Name: "NL", Vless: &xs.Link}
	u := mustCreate(t, a.store, User{Name: "u", Password: "secret123"}, false)
	hy.connect("u")
	a.syncOnce(time.Now())
	if _, in := fx.snapshot()["u"]; !in {
		t.Fatal("u not in xray")
	}

	// Hysteria off: no new sessions, the open one is kicked; VLESS stays.
	patch(t, a, "u", `{"protoOff":["hysteria2"]}`)
	if ok, _, why := a.authorize("u:secret123"); ok || !strings.Contains(why, "hysteria off") {
		t.Fatalf("authorize: %v %s", ok, why)
	}
	a.syncOnce(time.Now())
	hy.send("u")
	a.syncOnce(time.Now())
	if conns, kicks, _ := hy.state(); conns != 0 || kicks != 1 {
		t.Fatalf("hysteria session left: conns=%d kicks=%d", conns, kicks)
	}
	u, _ = a.store.Get("u")
	if _, in := fx.snapshot()["u"]; !in || !slices.Equal(a.ep.UserProtocols(u), []string{protoVless}) {
		t.Fatalf("vless lost: %v", a.ep.UserProtocols(u))
	}
	if ls := a.ep.URIs(u); len(ls) != 1 || !strings.HasPrefix(ls[0], "vless://") {
		t.Fatalf("links %v", ls)
	}
	if d := a.ep.MihomoDoc(u); strings.Contains(d, "hysteria2") || !strings.Contains(d, "type: vless") {
		t.Fatal(d)
	}

	// VLESS off too: out of Xray. All on again: both back.
	patch(t, a, "u", `{"protoOff":["vless","hysteria2","vless"]}`)
	a.syncOnce(time.Now())
	if _, in := fx.snapshot()["u"]; in {
		t.Fatal("vless-off user still in xray")
	}
	if u, _ = a.store.Get("u"); !slices.Equal(u.ProtoOff, []string{"hysteria2", "vless"}) || len(a.ep.URIs(u)) != 0 {
		t.Fatalf("%v %v", u.ProtoOff, a.ep.URIs(u))
	}
	patch(t, a, "u", `{"protoOff":[]}`)
	a.syncOnce(time.Now())
	if u, _ = a.store.Get("u"); u.ProtoOff != nil || len(a.ep.URIs(u)) != 2 {
		t.Fatalf("%v", u.ProtoOff)
	}
	if ok, _, _ := a.authorize("u:secret123"); !ok {
		t.Fatal("hysteria still off")
	}

	r := httptest.NewRequest("PATCH", "/api/users/u", strings.NewReader(`{"protoOff":["openvpn"]}`))
	r.SetPathValue("name", "u")
	w := httptest.NewRecorder()
	a.handlePatch(w, r)
	if w.Code != 400 {
		t.Fatalf("unknown protocol accepted: %d", w.Code)
	}
}

func TestMihomoFallback(t *testing.T) {
	xs, _ := parseXray(freshXray("443", "lurkpro.tech"))
	ep := Endpoint{Host: "203.0.113.7", Port: "443", Name: "NL", Vless: &xs.Link}
	u := User{Name: "phone", Password: "Pw123456", UUID: newUUID()}
	var doc struct {
		Proxies     []map[string]any
		ProxyGroups []struct {
			Name, Type, URL string
			Proxies         []string
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal([]byte(ep.MihomoFallback(u)), &doc); err != nil {
		t.Fatalf("%v\n%s", err, ep.MihomoFallback(u))
	}
	g := doc.ProxyGroups
	if len(doc.Proxies) != 2 || len(g) != 1 || g[0].Name != "NL" || g[0].Type != "fallback" ||
		!slices.Equal(g[0].Proxies, []string{"NL-phone", "NL-phone-vless"}) {
		t.Fatalf("%+v", doc)
	}
	// One protocol: still a valid group.
	u.ProtoOff = []string{protoHy2}
	if err := yaml.Unmarshal([]byte(ep.MihomoFallback(u)), &doc); err != nil || !slices.Equal(doc.ProxyGroups[0].Proxies, []string{"NL-phone-vless"}) {
		t.Fatalf("%v %+v", err, doc)
	}
}
