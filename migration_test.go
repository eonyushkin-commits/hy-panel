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
	if u.UUID != "old-key" || len(u.ProtoOff) != 1 || u.ProtoOff[0] != protoVless {
		t.Fatalf("VLESS credentials or access changed: %+v", u)
	}
	a := testApp(t, nil)
	a.store = s
	if ok, _, _ := a.authorize("bob:another-password"); ok {
		t.Fatal("Hysteria-disabled user gained access")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"awgKey", "awgIndex"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Fatalf("obsolete field retained: %s", key)
		}
	}
	s, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	a.store = s
	if ok, _, _ := a.authorize("bob:another-password"); ok {
		t.Fatal("protocol access lost on restart")
	}
	if _, err := s.Update("bob", func(u *User) error { u.ProtoOff = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := a.authorize("bob:another-password"); !ok {
		t.Fatal("cannot enable migrated user")
	}
}

func TestHysteriaBeforeVlessSetup(t *testing.T) {
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
	for _, path := range []string{"/api/users/phone/awg.conf"} {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: a.sign(1 << 62)})
		w := httptest.NewRecorder()
		a.routes(false).ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("removed endpoint %s: %d", path, w.Code)
		}
	}
	for _, id := range []string{"awg"} {
		if a.ep.Link(id, u) != "" || a.ep.MihomoProxy(id, u) != "" {
			t.Errorf("removed protocol %s generated a profile", id)
		}
	}
}

func TestHysteriaOnlyDatabaseGetsStableVlessKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(`[{"name":"alice","password":"original-password","subToken":"original-token","enabled":true,"up":123}]`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get("alice")
	if u.UUID == "" || !u.Enabled || u.Up != 123 || u.Password != "original-password" || u.SubToken != "original-token" {
		t.Fatalf("migration: %+v", u)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved, _ := reopened.Get("alice"); saved.UUID != u.UUID {
		t.Fatal("VLESS key changes after restart")
	}
}
