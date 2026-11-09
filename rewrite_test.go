package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
)

type isolatedBackend struct {
	id      string
	entered chan struct{}
	release <-chan struct{}
}

func (b *isolatedBackend) proto() string                { return b.id }
func (b *isolatedBackend) errText() string              { return b.id + ": " }
func (b *isolatedBackend) push(time.Time, []User) error { return nil }
func (b *isolatedBackend) stats(now time.Time, _ []User) (map[string]trafficEntry, onlineSnapshot, error) {
	b.entered <- struct{}{}
	if b.release != nil {
		<-b.release
		return nil, onlineSnapshot{}, errors.New("unavailable")
	}
	return map[string]trafficEntry{"phone": {Tx: 1}}, onlineSnapshot{map[string]int{"phone": 1}, now}, nil
}

func TestProtocolWorkersAreIndependent(t *testing.T) {
	a := testApp(t, nil)
	mustCreate(t, a.store, User{Name: "phone"})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	slow := &isolatedBackend{protoVless, make(chan struct{}, 2), release}
	fast := &isolatedBackend{protoHy2, make(chan struct{}, 2), nil}
	a.addBackend(slow)
	a.addBackend(fast)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.syncLoop(ctx, time.Hour); close(done) }()
	wait := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("healthy protocol blocked behind failed protocol")
		}
	}
	wait(slow.entered)
	wait(fast.entered)
	a.requestSync()
	wait(fast.entered)
	cancel()
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("workers did not stop")
	}
	u, _ := a.store.Get("phone")
	if u.Up < 2 {
		t.Fatal("healthy traffic was not accounted")
	}
}

func TestAdminRejectsCrossOriginAndAmbiguousJSON(t *testing.T) {
	a := testApp(t, nil)
	h := a.routes(false)
	for _, test := range []struct {
		body, origin string
		code         int
	}{
		{`{"name":"one"}`, "https://foreign.example", 403},
		{`{"name":"one"} {"name":"two"}`, "", 400},
		{`{"name":"one","typo":true}`, "", 400},
		{`{"name":"one"}`, "https://panel.example", 200},
	} {
		r := httptest.NewRequest("POST", "https://panel.example/api/users", strings.NewReader(test.body))
		r.Header.Set("Origin", test.origin)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: a.sign(time.Now().Add(time.Hour).Unix())})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.code {
			t.Fatalf("%s: %d: %s", test.body, w.Code, w.Body.String())
		}
	}
}

func TestExportRespectsUserProtocolRestrictions(t *testing.T) {
	a := testApp(t, nil)
	xs, err := parseXray(freshXray("443", "example.org"))
	if err != nil {
		t.Fatal(err)
	}
	a.ep = Endpoint{Host: "vpn.example.org", Port: "443", Vless: &xs.Link}
	mustCreate(t, a.store, User{Name: "phone", ProtoOff: []string{protoHy2}})
	for _, handler := range []http.HandlerFunc{a.handleQR, a.handleMihomo} {
		r := httptest.NewRequest("GET", "/?proto=hysteria2", nil)
		r.SetPathValue("name", "phone")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 400 {
			t.Fatalf("disabled protocol exported: %d", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.SetPathValue("name", "phone")
	w := httptest.NewRecorder()
	a.handleQR(w, r)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatal("default VLESS QR unavailable")
	}
}

func TestAgentRemembersInterruptedJob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.json")
	a := &agent{jobPath: path}
	if err := a.saveJob(job{ID: 42, Action: "vless", Running: true}); err != nil {
		t.Fatal(err)
	}
	restored := &agent{jobPath: path}
	if err := restored.restoreJob(); err != nil {
		t.Fatal(err)
	}
	j := restored.current()
	if j.ID != 42 || j.Running || j.OK || !strings.Contains(j.Log, "перезапущен") {
		t.Fatalf("interruption hidden: %+v", j)
	}
	again := &agent{jobPath: path}
	if err := again.restoreJob(); err != nil {
		t.Fatal(err)
	}
	if again.current().Log != j.Log {
		t.Fatal("interrupted status not durable")
	}
}

func TestValidationBeforeConfigPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err := atomicfile.Replace(path, []byte("candidate"), atomicfile.Options{Validate: func(candidate string) error {
		old, _ := os.ReadFile(path)
		next, _ := os.ReadFile(candidate)
		if string(old) != "old" || string(next) != "candidate" || filepath.Ext(candidate) != ".json" {
			t.Fatal("live config changed before validation")
		}
		return errors.New("invalid candidate")
	}})
	if err == nil {
		t.Fatal("invalid config accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "old" {
		t.Fatal("validation failure destroyed working config")
	}
}

func TestLogoutRevokesCopiedCookieAfterRestart(t *testing.T) {
	a := testApp(t, nil)
	a.sessionPath = filepath.Join(t.TempDir(), "session.key")
	if err := writeAtomic(a.sessionPath, a.key, 0600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/logout", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: a.sign(time.Now().Add(time.Hour).Unix())})
	w := httptest.NewRecorder()
	a.routes(false).ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	if a.authed(r) {
		t.Fatal("copied cookie still authenticates")
	}
	restarted := testApp(t, nil)
	key, err := sessionKey(a.sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted.key = key
	if restarted.authed(r) {
		t.Fatal("logout revocation lost after restart")
	}
}

func TestXrayBatchOnlineStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/GetUsersStats") {
			t.Error("wrong RPC")
		}
		user := pbString(nil, 1, "phone")
		user = pbBytes(user, 2, pbString(nil, 1, "192.0.2.1"))
		user = pbBytes(user, 2, pbString(nil, 1, "192.0.2.2"))
		payload := pbBytes(nil, 1, user)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(payload))))
		w.Write(payload)
		w.Header().Set("Grpc-Status", "0")
	}))
	defer server.Close()
	b := &xrayBackend{api: &xrayAPI{base: server.URL, hc: server.Client()}}
	b.pollOnline([]User{{Name: "phone"}})
	if b.onlineErr != nil || b.pendingOnline.users["phone"] != 2 {
		t.Fatalf("batch stats: %+v %v", b.pendingOnline, b.onlineErr)
	}
}

func TestAuthRefusesUnconfiguredHysteria(t *testing.T) {
	a := testApp(t, nil)
	u := mustCreate(t, a.store, User{Name: "phone"})
	r := httptest.NewRequest("POST", "/auth", strings.NewReader(`{"auth":"phone:`+u.Password+`"}`))
	r.RemoteAddr = "127.0.0.1:5000"
	w := httptest.NewRecorder()
	a.handleAuth(w, r)
	if !strings.Contains(w.Body.String(), `"ok":false`) {
		t.Fatal("unmanaged Hysteria can bypass traffic enforcement")
	}
}
