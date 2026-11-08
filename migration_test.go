package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyUsersKeepHysteriaCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	legacy := `[
 {"name":"alice","password":"original-password","subToken":"original-token","uuid":"old-key","awgKey":"old-key","awgIndex":2,"enabled":true,"protoOff":["vless","awg"],"up":123,"down":456,"quotaBytes":10000,"maxDevices":2},
 {"name":"bob","password":"another-password","subToken":"another-token","enabled":true,"protoOff":["hysteria2"]}
 ]`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := s.Resolve("alice:original-password")
	if !ok || !u.Enabled || u.SubToken != "original-token" || u.Up != 123 || u.Down != 456 || u.QuotaBytes != 10000 || u.MaxDevices != 2 {
		t.Fatalf("migration changed user: %+v", u)
	}
	if u, ok := s.Get("bob"); !ok || u.Enabled {
		t.Fatal("Hysteria-disabled user gained access")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"uuid", "awgKey", "awgIndex", "protoOff"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Fatalf("obsolete field retained: %s", key)
		}
	}
	s, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Get("bob"); u.Enabled {
		t.Fatal("disabled state lost on restart")
	}
	if _, err := s.Update("bob", func(u *User) error { u.Enabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Get("bob"); !u.Enabled {
		t.Fatal("cannot enable migrated user")
	}
}

func TestOnlyHysteriaIsExposed(t *testing.T) {
	a := testApp(t, nil)
	a.ep.Port = "443"
	u := mustCreate(t, a.store, User{Name: "phone"})
	if got := a.ep.URIs(u); len(got) != 1 || !strings.HasPrefix(got[0], "hysteria2://") {
		t.Fatalf("subscription: %v", got)
	}
	w := httptest.NewRecorder()
	a.handleState(w, httptest.NewRequest("GET", "/api/state", nil))
	var state struct {
		Server struct{ Protocols []struct{ ID string } }
		Users  []struct{ Links []link }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Server.Protocols) != 1 || state.Server.Protocols[0].ID != protoHy2 || len(state.Users[0].Links) != 1 || state.Users[0].Links[0].Proto != protoHy2 {
		t.Fatalf("state: %s", w.Body)
	}
	for _, path := range []string{"/api/users/phone/awg.conf", "/api/system/check-target", "/api/system/site-scan"} {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: a.sign(1 << 62)})
		w := httptest.NewRecorder()
		a.routes(false).ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("removed endpoint %s: %d", path, w.Code)
		}
	}
	for _, id := range []string{"vless", "awg"} {
		if a.ep.Link(id, u) != "" || a.ep.MihomoProxy(id, u) != "" {
			t.Errorf("removed protocol %s generated a profile", id)
		}
	}
}
