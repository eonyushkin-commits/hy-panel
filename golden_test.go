package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

var tmplHead, _, _ = strings.Cut(string(mihomoBuiltin), "\n")

// lineDiff lists the lines b adds to a ("+ ") and drops from it ("- "),
// each in its order: enough to see what a template became.
func lineDiff(a, b string) string {
	count := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(s, "\n") {
			m[l]++
		}
		return m
	}
	ca, cb := count(a), count(b)
	var out strings.Builder
	for _, l := range strings.Split(b, "\n") {
		if ca[l] > 0 {
			ca[l]--
		} else {
			out.WriteString("+ " + l + "\n")
		}
	}
	for _, l := range strings.Split(a, "\n") {
		if cb[l] > 0 {
			cb[l]--
		} else {
			out.WriteString("- " + l + "\n")
		}
	}
	return out.String()
}

// pixels fingerprints a PNG by its size and pixels: the encoder's bytes
// differ between Go versions, the picture does not.
func pixels(t *testing.T, b []byte) string {
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	r := img.Bounds()
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			c := color.GrayModel.Convert(img.At(x, y)).(color.Gray)
			h.Write([]byte{c.Y})
		}
	}
	return fmt.Sprintf("%dx%d sha256 %x", r.Dx(), r.Dy(), h.Sum(nil))
}

// TestLinksGolden pins everything clients get — share links, subscriptions
// in every format, mihomo documents, QR codes — for
// two fixed servers and three users. A change in links changes clients'
// profiles: it must be on purpose (go test -run LinksGolden -update).
func TestLinksGolden(t *testing.T) {
	servers := []struct {
		name string
		ep   Endpoint
	}{
		{"full", Endpoint{Host: "203.0.113.10", Port: "20000-50000", SNI: "vpn.example.com", ObfsType: "salamander", ObfsPass: "obfs-pass",
			Pin: "ab12cd34", ECH: "AEX+DQBB", Name: "NL"}},
		{"plain", Endpoint{Host: "vpn.example.net", Port: "443"}},
	}
	users := []User{
		{Name: "alice", Password: "alice-pass-1", SubToken: "tok-alice"},
		{Name: "bob", Password: "bob-pass-12", SubToken: "tok-bob"},
		{Name: "carol", Password: "carol-pass-1", SubToken: "tok-carol"},
	}

	// The built-in mihomo template, whatever this machine has in /etc.
	defer func(p string) { mihomoTemplatePath = p }(mihomoTemplatePath)
	mihomoTemplatePath = "testdata/no-such-template.yaml"

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
			fmt.Fprintf(&out, "png %s\n", pixels(t, w.Body.Bytes()))
		} else if body := w.Body.String(); strings.HasPrefix(body, tmplHead) {
			// A full mihomo config: what differs from the template.
			fmt.Fprintf(&out, "mihomo template sha256 %x\n", sha256.Sum256(mihomoBuiltin))
			out.WriteString(lineDiff(string(mihomoBuiltin), body))
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
			if _, err := a.store.Create(u); err != nil {
				t.Fatal(err)
			}
			a.store.Update(u.Name, func(s *User) error { s.SubToken = u.SubToken; return nil })
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
			call("mihomo full router", a.handleMihomo, "/m?full=router&download=1", name)
			call("mihomo full desktop", a.handleMihomo, "/m?full=desktop", name)
			for _, p := range []string{protoHy2} {
				call("mihomo proto="+p, a.handleMihomo, "/m?proto="+p, name)
				call("qr proto="+p, a.handleQR, "/q?proto="+p, name)
			}
			call("qr", a.handleQR, "/q", name)
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
