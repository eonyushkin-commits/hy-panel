package storage

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"github.com/eonyushkin-commits/hy-panel/internal/model"
)

func database(t *testing.T) *Store {
	t.Helper()
	s := newStore(t)
	mustCreate(t, s, model.User{Name: "phone", ProtoOff: []string{model.VLESS}})
	return s
}

func TestIsolationAndFailedTransaction(t *testing.T) {
	s := database(t)
	u, _ := s.Get("phone")
	u.ProtoOff[0] = model.Hysteria
	all := s.List()
	all[0].ProtoOff[0] = model.Hysteria
	sentinel := errors.New("abort")
	if _, err := s.Update("phone", func(u *model.User) error { u.ProtoOff[0] = model.Hysteria; return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	var retained *model.User
	if _, err := s.Update("phone", func(u *model.User) error { retained = u; return nil }); err != nil {
		t.Fatal(err)
	}
	retained.ProtoOff[0] = model.Hysteria
	s.write = func(string, []byte) error { return os.ErrPermission }
	if _, err := s.Update("phone", func(u *model.User) error { u.ProtoOff[0] = model.Hysteria; return nil }); err == nil {
		t.Fatal("write failure accepted")
	}
	u, _ = s.Get("phone")
	if u.ProtoOff[0] != model.VLESS {
		t.Fatal("failed transaction or reader changed stored protocol")
	}
	if err := s.Delete("phone"); err == nil {
		t.Fatal("delete failure accepted")
	}
	if _, ok := s.Get("phone"); !ok {
		t.Fatal("failed delete removed user")
	}
}

func TestMonthBoundaryAndOverflow(t *testing.T) {
	s := database(t)
	_, err := s.Update("phone", func(u *model.User) error { u.ResetMonthly = true; u.LastReset = 202610; u.Up = 99; return nil })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 0, 0, 3, 0, time.UTC)
	s.Tick(now, map[string]model.Traffic{"phone": {Tx: 7, Rx: 11}}, nil)
	u, _ := s.Get("phone")
	if u.Up != 7 || u.Down != 11 || u.LastReset != 202611 {
		t.Fatalf("first sample lost: %+v", u)
	}
	s.Tick(now, map[string]model.Traffic{"phone": {Tx: math.MaxInt64, Rx: -500}}, nil)
	u, _ = s.Get("phone")
	if u.Up != math.MaxInt64 || u.Down != 11 {
		t.Fatalf("invalid counters: %+v", u)
	}
	u.QuotaBytes = math.MaxInt64
	if u.Blocked(now) != "quota" {
		t.Fatal("overflow bypassed quota")
	}
}

func TestFlushDoesNotBlockAuthOrLoseConcurrentSample(t *testing.T) {
	s := database(t)
	now := time.Now()
	s.Tick(now, map[string]model.Traffic{"phone": {Tx: 10}}, nil)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	s.write = func(path string, b []byte) error { close(entered); <-release; return writeUsers(path, b) }
	go func() { done <- s.Flush() }()
	<-entered
	read := make(chan bool, 1)
	go func() { _, ok := s.Resolve(s.List()[0].Password); read <- ok }()
	select {
	case ok := <-read:
		if !ok {
			t.Fatal("auth failed")
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("disk write blocked auth")
	}
	s.Tick(now, map[string]model.Traffic{"phone": {Tx: 5}}, nil)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.write = writeUsers
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(s.path)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := reloaded.Get("phone")
	if u.Up != 15 {
		t.Fatalf("concurrent sample lost: %d", u.Up)
	}
}

func TestInvalidDatabaseIsRejected(t *testing.T) {
	s := database(t)
	u, _ := s.Get("phone")
	dup := u.Clone()
	dup.Name = "other"
	for name, rows := range map[string][]*model.User{"null-user": {nil}, "duplicate-name": {&u, &u}, "duplicate-keys": {&u, &dup}} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(rows)
			path := filepath.Join(t.TempDir(), "users.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); err == nil {
				t.Fatal("invalid database accepted")
			}
		})
	}
}

func TestCommittedWritePublishesMatchingMemory(t *testing.T) {
	s := database(t)
	s.write = func(path string, b []byte) error {
		if err := writeUsers(path, b); err != nil {
			return err
		}
		return &atomicfile.CommitError{Err: os.ErrPermission}
	}
	if _, err := s.Update("phone", func(u *model.User) error { u.Note = "saved"; return nil }); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get("phone")
	if u.Note != "saved" || s.Problem() == nil {
		t.Fatal("committed file and memory diverged or warning lost")
	}
	s.write = writeUsers
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if s.Problem() != nil {
		t.Fatal("warning persisted after durable retry")
	}
}

func TestMigrationKeepsOriginalAndDoesNotPublishUnsavedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	original := []byte(`[{"name":"old","password":"original-password","subToken":"original-token","enabled":true,"up":12}]`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := open(path, func(string, []byte) error { return os.ErrPermission }); err == nil || s != nil {
		t.Fatal("unsaved migration keys published")
	}
	backup, err := os.ReadFile(path + ".pre-v2")
	if err != nil || string(backup) != string(original) {
		t.Fatal("original migration backup lost")
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get("old")
	if u.Password != "original-password" || u.SubToken != "original-token" || u.Up != 12 || u.UUID == "" {
		t.Fatal("legacy credentials or counters lost")
	}
	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := reloaded.Get("old")
	if u.UUID != u2.UUID {
		t.Fatal("new UUID changed on restart")
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, _ := newStoreWithPath(t)
	return s
}

func newStoreWithPath(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func mustCreate(t *testing.T, s *Store, u model.User) model.User {
	t.Helper()
	u.Enabled = true
	got, err := s.Create(u)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestResolve(t *testing.T) {
	s := newStore(t)
	mustCreate(t, s, model.User{Name: "Phone", Password: "secret123"})

	cases := map[string]string{
		"phone:secret123": "phone",
		"PHONE:secret123": "phone", // Hysteria userpass: names are case-insensitive
		"secret123":       "phone", // bare password
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
	s, path := newStoreWithPath(t)
	a := mustCreate(t, s, model.User{Name: "a"})
	if len(a.Password) != 20 {
		t.Fatalf("generated password %q", a.Password)
	}
	for _, pw := range []string{"short", "has:colon1", "has space1", a.Password} {
		if _, err := s.Create(model.User{Name: "b", Password: pw}); err == nil {
			t.Errorf("Create with password %q succeeded", pw)
		}
	}
	if _, err := s.Create(model.User{Name: "Bad Name"}); err == nil {
		t.Error("bad name accepted")
	}
	b := mustCreate(t, s, model.User{Name: "b"})
	// Duplicate on update is rejected and leaves the user untouched.
	if _, err := s.Update("b", func(u *model.User) error { u.Password = a.Password; u.Note = "x"; return nil }); err == nil {
		t.Fatal("duplicate password accepted on update")
	}
	if got, _ := s.Get("b"); got.Password != b.Password || got.Note != "" {
		t.Fatalf("failed update changed user: %+v", got)
	}
	// Persisted and reloadable.
	s2, err := Open(path)
	if err != nil || len(s2.List()) != 2 {
		t.Fatalf("reload: %v %d", err, len(s2.List()))
	}
}

func TestCountersFlushedLater(t *testing.T) {
	s, path := newStoreWithPath(t)
	mustCreate(t, s, model.User{Name: "u"})
	disk := func() int64 {
		s2, _ := Open(path)
		u, _ := s2.Get("u")
		return u.Down
	}
	s.Tick(time.Now(), map[string]model.Traffic{"u": {Rx: 500}}, nil)
	if disk() != 0 {
		t.Fatal("counters written on every tick")
	}
	if err := s.Flush(); err != nil || disk() != 500 {
		t.Fatalf("flush: %v %d", err, disk())
	}
	// An admin change is written at once, with the counters.
	s.Tick(time.Now(), map[string]model.Traffic{"u": {Rx: 1}}, nil)
	s.Update("u", func(u *model.User) error { u.Note = "x"; return nil })
	if disk() != 501 {
		t.Fatal("admin change not written with counters")
	}
}
