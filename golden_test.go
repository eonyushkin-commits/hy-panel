package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// TestLinksGolden pins everything clients get — share links, subscriptions
// in every format, mihomo documents, AmneziaWG configs and QR codes — for
// two fixed servers and three users. A change in links changes clients'
// profiles: it must be on purpose (go test -run LinksGolden -update).
func TestLinksGolden(t *testing.T) {
	awg := &awgConfig{Port: 51820, PrivateKey: "YAnz8UHVPqIoBqA9xbrmWkzZ6W6U6V0b3n1h1E3vC2Y=", MTU: 1280, DNS: "1.1.1.1, 1.0.0.1",
		Jc: 5, Jmin: 40, Jmax: 70, S1: 20, S2: 30, S3: 14, S4: 16, H1: "1", H2: "2", H3: "3", H4: "4",
		I1:                  "<r 2><b 0x01000001000000000000><b 0x0a><rc 10><b 0x03636f6d00><b 0x00010001>",
		HeaderProtectionKey: "oMRI6+Tm1S0ET5tEaZoiAn4uqiGfs+x+CZs2UltEXGE=", ContentPaddingAddition: "0-32"}
	servers := []struct {
		name string
		ep   Endpoint
	}{
		{"full", Endpoint{Host: "203.0.113.10", Port: "20000-50000", SNI: "vpn.example.com", ObfsType: "salamander", ObfsPass: "obfs-pass",
			Pin: "ab12cd34", ECH: "AEX+DQBB", Name: "NL", AWG: awg,
			Vless: &Vless{Port: "443", SNI: "www.example.org", PublicKey: "pbk-xhttp", ShortID: "1187d00c55ca4d4c", Network: "xhttp", Path: "/2b1f2de74ce6", Mode: "auto"}}},
		{"plain", Endpoint{Host: "vpn.example.net", Port: "443",
			Vless: &Vless{Port: "8443", SNI: "www.example.com", PublicKey: "pbk-tcp", Network: "tcp", Flow: visionFlow}}},
	}
	users := []User{
		{Name: "alice", Password: "alice-pass-1", UUID: "46d502e8-e63c-4b3e-893f-519135ad1de3", AWGKey: "8Pm2s6Oz1VRrWEc0bNKIhPpz3e0YVxUJsS0Ywr0lE1s=", AWGIndex: 2, SubToken: "tok-alice"},
		{Name: "bob", Password: "bob-pass-12", UUID: "0b5e3b1a-6a8e-4c39-9d1f-2f1c6c0f2b7e", AWGKey: "GKl3f0Wd1pW0vXq9Kpj6zv8ZfP4Vb9oQ3sXh2nL5mGc=", AWGIndex: 3, SubToken: "tok-bob",
			ProtoOff: []string{protoVless}},
		{Name: "carol", Password: "carol-pass-1", UUID: "9c3f1a77-2d4b-4e8a-b6c5-71e0d3f9a2b4", AWGKey: "eHk1c2VjcmV0LWtleS0zMi1ieXRlcy1sb25nLWFiY2Q=", AWGIndex: 4, SubToken: "tok-carol",
			ProtoOff: []string{protoHy2, protoAWG}},
	}

	var out strings.Builder
	call := func(title string, h http.HandlerFunc, path string, set func(*http.Request)) {
		r := httptest.NewRequest("GET", path, nil)
		if set != nil {
			set(r)
		}
		w := httptest.NewRecorder()
		h(w, r)
		fmt.Fprintf(&out, "--- %s: %d\n", title, w.Code)
		for _, k := range []string{"Content-Disposition", "Subscription-Userinfo", "Profile-Title"} {
			if v := w.Header().Get(k); v != "" {
				fmt.Fprintf(&out, "%s: %s\n", k, v)
			}
		}
		if w.Header().Get("Content-Type") == "image/png" {
			fmt.Fprintf(&out, "png sha256 %x\n", sha256.Sum256(w.Body.Bytes()))
		} else {
			out.WriteString(w.Body.String())
		}
		out.WriteString("\n")
	}
	for _, sv := range servers {
		a := testApp(t, nil)
		a.ep = sv.ep
		for _, u := range users {
			u.Enabled = true
			if _, err := a.store.Create(u, true); err != nil {
				t.Fatal(err)
			}
			a.store.Update(u.Name, func(s *User) error { s.SubToken = u.SubToken; s.AWGKey, s.AWGIndex = u.AWGKey, u.AWGIndex; return nil })
		}

		fmt.Fprintf(&out, "=== server %s\n", sv.name)
		var st struct {
			Users []struct {
				Name  string            `json:"name"`
				Links []json.RawMessage `json:"links"`
			} `json:"users"`
			Server struct {
				Protocols json.RawMessage `json:"protocols"`
			} `json:"server"`
		}
		w := httptest.NewRecorder()
		a.handleState(w, httptest.NewRequest("GET", "/api/state", nil))
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&out, "protocols %s\n", st.Server.Protocols)
		for _, u := range st.Users {
			for _, l := range u.Links {
				fmt.Fprintf(&out, "state %s link %s\n", u.Name, l)
			}
		}
		for _, u := range users {
			name := func(r *http.Request) { r.SetPathValue("name", u.Name) }
			tok := func(r *http.Request) { r.SetPathValue("token", u.SubToken) }
			fmt.Fprintf(&out, "== %s / %s\n", sv.name, u.Name)
			for _, f := range []string{"raw", "mihomo", ""} {
				call("sub format="+f, a.handleSub, "/sub/x?format="+f, tok)
			}
			call("sub clash UA", a.handleSub, "/sub/x", func(r *http.Request) { tok(r); r.Header.Set("User-Agent", "clash.meta/1.19") })
			call("mihomo", a.handleMihomo, "/m", name)
			call("mihomo fallback", a.handleMihomo, "/m?fallback=1", name)
			for _, p := range []string{protoHy2, protoAWG, protoVless} {
				call("mihomo proto="+p, a.handleMihomo, "/m?proto="+p, name)
				call("qr proto="+p, a.handleQR, "/q?proto="+p, name)
			}
			call("qr", a.handleQR, "/q", name)
			call("awg.conf", a.handleAWGConf, "/c", name)
		}
	}

	path := "testdata/links.golden"
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got := out.String(); got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) || i < len(wl); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("links changed at line %d:\n got: %s\nwant: %s", i+1, g, w)
			}
		}
	}
}
