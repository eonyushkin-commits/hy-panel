package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

type snapshotBackend struct {
	id       string
	snapshot onlineSnapshot
	err      error
}

func (b *snapshotBackend) proto() string                { return b.id }
func (b *snapshotBackend) errText() string              { return b.id + ": " }
func (b *snapshotBackend) push(time.Time, []User) error { return nil }
func (b *snapshotBackend) stats(time.Time, []User) (map[string]trafficEntry, onlineSnapshot, error) {
	return nil, b.snapshot, b.err
}

func readOnlineStatus(t *testing.T, a *App) map[string]onlineStatus {
	t.Helper()
	w := httptest.NewRecorder()
	a.handleState(w, httptest.NewRequest("GET", "/api/state", nil))
	var state struct {
		OnlineStatus map[string]onlineStatus `json:"onlineStatus"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	return state.OnlineStatus
}

func TestOnlineFreshnessPerProtocol(t *testing.T) {
	a := testApp(t, nil)
	mustCreate(t, a.store, User{Name: "phone"})
	hy := &snapshotBackend{id: protoHy2}
	x := &snapshotBackend{id: protoVless}
	a.addBackend(hy)
	a.addBackend(x)
	for p, s := range readOnlineStatus(t, a) {
		if !s.Stale || s.LastSuccess != 0 {
			t.Fatalf("%s before first poll: %+v", p, s)
		}
	}

	now := time.Now()
	old := now.Add(-onlineFreshFor - time.Second)
	hy.snapshot = onlineSnapshot{map[string]int{"phone": 1}, now}
	x.snapshot = onlineSnapshot{map[string]int{"phone": 2}, old}
	a.syncAccess(now)
	status := readOnlineStatus(t, a)
	if status[protoHy2].Stale || !status[protoVless].Stale {
		t.Fatalf("independent freshness: %+v", status)
	}

	// No new Xray snapshot: other successful polls must not refresh its timestamp
	// or erase the last known count. An unsuccessful poll has the same effect.
	x.snapshot, x.err = onlineSnapshot{}, errors.New("online unavailable")
	a.syncAccess(now)
	if s := readOnlineStatus(t, a)[protoVless]; !s.Stale || s.LastSuccess != old.Unix() || a.live[protoVless].online["phone"] != 2 {
		t.Fatalf("failed poll replaced last snapshot: %+v", s)
	}

	// Recovery with nobody online must clear the old count and stale flag.
	x.snapshot, x.err = onlineSnapshot{map[string]int{}, now}, nil
	a.syncAccess(now)
	if s := readOnlineStatus(t, a)[protoVless]; s.Stale || s.LastSuccess != now.Unix() || len(a.live[protoVless].online) != 0 {
		t.Fatalf("recovery: %+v", s)
	}
}

func TestXrayOnlineTimestampSurvivesDelayedConsumption(t *testing.T) {
	a := testApp(t, nil)
	fx, api := newFakeXray(t)
	x := &xrayBackend{api: api, tag: "in"}
	a.addBackend(x)
	mustCreate(t, a.store, User{Name: "phone"})
	fx.mu.Lock()
	fx.online["phone"] = 1
	fx.mu.Unlock()
	x.pollOnline(a.store.List())
	if x.pendingOnline.at.IsZero() {
		t.Fatal("successful online poll has no timestamp")
	}
	// Consuming a buffered snapshot later must not make it look new.
	old := time.Now().Add(-time.Minute)
	x.pendingOnline.at = old
	a.syncAccess(time.Now())
	if s := readOnlineStatus(t, a)[protoVless]; !s.Stale || s.LastSuccess != old.Unix() {
		t.Fatalf("buffered snapshot was refreshed: %+v", s)
	}
	a.syncAccess(time.Now()) // traffic and user synchronization still succeed
	if s := readOnlineStatus(t, a)[protoVless]; !s.Stale || s.LastSuccess != old.Unix() {
		t.Fatalf("traffic refreshed online: %+v", s)
	}
	fx.mu.Lock()
	fx.down = true
	fx.mu.Unlock()
	x.pollOnline(a.store.List())
	a.syncAccess(time.Now())
	if s := readOnlineStatus(t, a)[protoVless]; !s.Stale || s.LastSuccess != old.Unix() {
		t.Fatalf("failed poll refreshed online: %+v", s)
	}
	fx.mu.Lock()
	fx.down = false
	fx.mu.Unlock()
	x.pollOnline(a.store.List())
	a.syncAccess(time.Now())
	if s := readOnlineStatus(t, a)[protoVless]; s.Stale || s.LastSuccess <= old.Unix() {
		t.Fatalf("successful poll did not recover: %+v", s)
	}
}
