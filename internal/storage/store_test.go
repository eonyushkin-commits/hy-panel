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
	s, err := Open(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Create(model.User{Name: "phone", Enabled: true, ProtoOff: []string{model.VLESS}})
	if err != nil {
		t.Fatal(err)
	}
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
