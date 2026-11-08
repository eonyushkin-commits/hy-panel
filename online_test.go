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

func (b *snapshotBackend) proto() string   { return b.id }
func (b *snapshotBackend) errText() string { return b.id + ": " }
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

func TestOnlineFreshness(t *testing.T) {
	a := testApp(t, nil)
	mustCreate(t, a.store, User{Name: "phone"})
	hy := &snapshotBackend{id: protoHy2}
	a.addBackend(hy)
	if s := readOnlineStatus(t, a)[protoHy2]; !s.Stale || s.LastSuccess != 0 {
		t.Fatalf("before poll: %+v", s)
	}
	now := time.Now()
	old := now.Add(-onlineFreshFor - time.Second)
	hy.snapshot = onlineSnapshot{map[string]int{"phone": 1}, old}
	a.syncAccess(now)
	if s := readOnlineStatus(t, a)[protoHy2]; !s.Stale || s.LastSuccess != old.Unix() {
		t.Fatalf("old snapshot: %+v", s)
	}
	hy.snapshot, hy.err = onlineSnapshot{}, errors.New("online unavailable")
	a.syncAccess(now)
	if s := readOnlineStatus(t, a)[protoHy2]; !s.Stale || s.LastSuccess != old.Unix() || a.live[protoHy2].online["phone"] != 1 {
		t.Fatalf("failed poll: %+v", s)
	}
	// A successful empty snapshot stays fresh even if traffic collection failed.
	hy.snapshot, hy.err = onlineSnapshot{map[string]int{}, now}, errors.New("traffic unavailable")
	a.syncAccess(now)
	if s := readOnlineStatus(t, a)[protoHy2]; s.Stale || s.LastSuccess != now.Unix() || len(a.live[protoHy2].online) != 0 {
		t.Fatalf("recovery: %+v", s)
	}
}
