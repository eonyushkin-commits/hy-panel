package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestJobArgs(t *testing.T) {
	ok := map[string]struct {
		action string
		p      map[string]string
		want   []string
	}{
		"hysteria default": {"hysteria", map[string]string{"port": "443", "obfs": "salamander", "cert": "self"},
			[]string{"settings", "-port", "443", "-obfs", "salamander", "-cert", "self"}},
		"hysteria acme": {"hysteria", map[string]string{"port": "20000-50000", "obfs": "none", "cert": "acme", "domain": "vpn.example.com", "email": "a@b.cd"},
			[]string{"settings", "-port", "20000-50000", "-obfs", "none", "-cert", "acme", "-domain", "vpn.example.com", "-email", "a@b.cd"}},
		"vless new":   {"vless", map[string]string{"port": "443", "target": "Lurkpro.tech"}, []string{"xray", "-port", "443", "-target", "lurkpro.tech"}},
		"vless site":  {"vless", map[string]string{"target": "api.ilexa.online"}, []string{"xray", "-target", "api.ilexa.online"}},
		"update xray": {"update-xray", nil, []string{"fetch", "xray"}},
	}
	for name, c := range ok {
		if got, err := jobArgs(c.action, c.p); err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	for name, c := range map[string]struct {
		action string
		p      map[string]string
	}{
		"unknown":         {"shell", map[string]string{"cmd": "id"}},
		"port":            {"hysteria", map[string]string{"port": "443; rm -rf /"}},
		"obfs":            {"hysteria", map[string]string{"obfs": "-config=/etc/shadow"}},
		"acme no domain":  {"hysteria", map[string]string{"cert": "acme"}},
		"flag in domain":  {"hysteria", map[string]string{"cert": "acme", "domain": "-y"}},
		"bad email":       {"hysteria", map[string]string{"cert": "acme", "domain": "a.example", "email": "x y@z"}},
		"vless no target": {"vless", nil},
		"vless target":    {"vless", map[string]string{"target": "-port=1"}},
		"vless port":      {"vless", map[string]string{"port": "0", "target": "a.example"}},
	} {
		if args, err := jobArgs(c.action, c.p); err == nil {
			t.Errorf("%s accepted: %v", name, args)
		}
	}
}

func TestAgentJob(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake")
	os.WriteFile(bin, []byte("#!/bin/sh\necho \"✓ $*\"\n[ \"$1\" = fetch ] && exit 3\nexit 0\n"), 0o755)
	a := &agent{bin: bin}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /job", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.current()) })
	mux.HandleFunc("POST /jobs", a.handleStart)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	start := func(body string) int {
		resp, err := http.Post(srv.URL+"/jobs", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	wait := func() job {
		for i := 0; i < 100; i++ {
			if j := a.current(); !j.Running {
				return j
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("job never ends")
		return job{}
	}
	if code := start(`{"action":"vless","params":{"target":"lurkpro.tech"}}`); code != 200 {
		t.Fatalf("start: %d", code)
	}
	if j := wait(); !j.OK || !strings.Contains(j.Log, "✓ xray -target lurkpro.tech") {
		t.Fatalf("%+v", j)
	}
	start(`{"action":"update-hysteria"}`)
	if j := wait(); j.OK || !strings.Contains(j.Log, "exit status 3") {
		t.Fatalf("failed job reported ok: %+v", j)
	}
	if code := start(`{"action":"vless","params":{"target":"-x"}}`); code != 400 {
		t.Fatalf("bad params: %d", code)
	}
	// One job at a time.
	os.WriteFile(bin, []byte("#!/bin/sh\nsleep 1\n"), 0o755)
	start(`{"action":"update-xray"}`)
	if code := start(`{"action":"update-xray"}`); code != 409 {
		t.Fatalf("second job: %d", code)
	}
	wait()
}

func TestFetch(t *testing.T) {
	bin := []byte("#!/bin/sh\necho Xray 26.3.27\n")
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for name, b := range map[string][]byte{"xray": bin, "geoip.dat": []byte("ip"), "geosite.dat": []byte("site")} {
		w, _ := zw.Create(name)
		w.Write(b)
	}
	zw.Close()
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	files := map[string][]byte{
		"/hy/hysteria-linux-amd64":  []byte("hy-bin"),
		"/hy/hashes.txt":            []byte(sum([]byte("other")) + "  build/hysteria-linux-arm64\n" + sum([]byte("hy-bin")) + "  build/hysteria-linux-amd64\n"),
		"/x/Xray-linux-64.zip":      zb.Bytes(),
		"/x/Xray-linux-64.zip.dgst": []byte("MD5= 00\nSHA1= 00\nSHA2-256= " + sum(zb.Bytes()) + "\nSHA2-512= 00\n"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[r.URL.Path]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	d, err := dgst(files["/x/Xray-linux-64.zip.dgst"])
	if err != nil || d != sum(zb.Bytes()) {
		t.Fatalf("dgst %q %v", d, err)
	}
	b, err := download(srv.URL+"/hy/", "hysteria-linux-amd64", hashesTxt(files["/hy/hashes.txt"]))
	if err != nil || string(b) != "hy-bin" {
		t.Fatalf("%q %v", b, err)
	}
	// A tampered file is refused.
	files["/hy/hysteria-linux-amd64"] = []byte("evil")
	if _, err := download(srv.URL+"/hy/", "hysteria-linux-amd64", hashesTxt(files["/hy/hashes.txt"])); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered binary accepted: %v", err)
	}
	if _, err := download(srv.URL+"/hy/", "hysteria-linux-mips", hashesTxt(files["/hy/hashes.txt"])); err == nil {
		t.Fatal("file without a published hash accepted")
	}
	z, err := download(srv.URL+"/x/", "Xray-linux-64.zip", func(string) (string, error) { return d, nil })
	if err != nil || !bytes.Equal(z, zb.Bytes()) {
		t.Fatal(err)
	}
}

func TestSystemNeedsAgent(t *testing.T) {
	a := testApp(t, nil)
	a.agent = newAgentClient(filepath.Join(t.TempDir(), "none.sock"))
	w := httptest.NewRecorder()
	a.handleSystem(w, httptest.NewRequest("GET", "/api/system", nil))
	var st struct{ AgentError string }
	json.Unmarshal(w.Body.Bytes(), &st)
	if !strings.Contains(st.AgentError, "hy-panel-agent") {
		t.Fatalf("%s", w.Body)
	}
	w = httptest.NewRecorder()
	a.handleJobStart(w, httptest.NewRequest("POST", "/api/system/jobs", strings.NewReader(`{}`)))
	if w.Code != 503 {
		t.Fatalf("%d", w.Code)
	}
}

func TestLatestRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apernet/hysteria/releases/latest": // a moved repository: 301 first
			http.Redirect(w, r, "/new-org/hysteria/releases/latest", http.StatusMovedPermanently)
		case "/new-org/hysteria/releases/latest":
			http.Redirect(w, r, "/new-org/hysteria/releases/tag/app/v2.6.1", http.StatusFound)
		case "/new-org/hysteria/releases/tag/app/v2.6.1":
			t.Error("the tag page itself is not needed")
		case "/XTLS/Xray-core/releases/latest":
			http.Redirect(w, r, "/XTLS/Xray-core/releases/tag/v25.9.11", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	for base, want := range map[string]hyVersion{
		srv.URL + "/apernet/hysteria/releases/latest/download/": {2, 6, 1},
		srv.URL + "/XTLS/Xray-core/releases/latest/download/":   {25, 9, 11},
	} {
		if v, err := latestRelease(base); err != nil || v != want {
			t.Errorf("%s: %v %v, want %v", base, v, err, want)
		}
	}
	// A mirror without the redirect: unknown, not "up to date".
	if v, err := latestRelease(srv.URL + "/mirror/download/"); err == nil {
		t.Errorf("mirror: %v, want an error", v)
	}

	defer func(h, x string) { hysteriaURL, xrayURL = h, x }(hysteriaURL, xrayURL)
	hysteriaURL, xrayURL = srv.URL+"/apernet/hysteria/releases/latest/download/", srv.URL+"/mirror/download/"
	r := releases{latest: map[string]release{}}
	if v, e := r.get(protoHy2); v != (hyVersion{}) || e == "" {
		t.Errorf("before a check: %v %q", v, e)
	}
	if r.check() {
		t.Error("check: ok with a failing mirror")
	}
	if v, e := r.get(protoHy2); v != (hyVersion{2, 6, 1}) || e != "" {
		t.Errorf("hysteria: %v %q", v, e)
	}
	if v, e := r.get(protoVless); v != (hyVersion{}) || !strings.Contains(e, "404") {
		t.Errorf("xray: %v %q, want the reason", v, e)
	}
}
