package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"
)

const (
	revokeWindow  = 2 * time.Minute
	flushInterval = time.Minute // traffic counters reach the disk at least this often
)

// revocation: sessions of a user whose password changed at `at` are dropped
// until they are all gone or `until` passes.
type revocation struct{ at, until time.Time }

// ---- Hysteria HTTP auth backend ----

func (a *App) handleAuth(w http.ResponseWriter, r *http.Request) {
	// Only Hysteria on this host; refuse anything relayed by a local reverse proxy.
	if !isLoopbackReq(r) || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" || r.Header.Get("Forwarded") != "" {
		log.Printf("auth: refused request from %s (only loopback without proxy headers)", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		Addr string `json:"addr"`
		Auth string `json:"auth"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ok, id, why := a.authorize(req.Auth)
	if !ok {
		log.Printf("auth deny %s user=%q: %s", req.Addr, id, why)
		if why == "bad credentials" {
			time.Sleep(time.Second) // slow down guessing
		}
		id = ""
	}
	writeJSON(w, map[string]any{"ok": ok, "id": id})
}

// authorize uses memory only (users and the last /online snapshot), so a
// connect never waits for the disk or for Hysteria.
func (a *App) authorize(auth string) (bool, string, string) {
	u, ok := a.store.Resolve(auth)
	if !ok {
		return false, "", "bad credentials"
	}
	if why := u.Blocked(time.Now()); why != "" {
		return false, u.Name, why
	}
	if u.MaxDevices > 0 {
		a.mu.RLock()
		n := a.online[u.Name]
		a.mu.RUnlock()
		if n >= u.MaxDevices {
			return false, u.Name, fmt.Sprintf("device limit %d", u.MaxDevices)
		}
	}
	return true, u.Name, ""
}

// ---- sync & enforcement ----

func (a *App) syncLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	flushed := time.Now()
	for {
		a.syncOnce(time.Now())
		if time.Since(flushed) >= flushInterval {
			if err := a.store.Flush(); err != nil {
				log.Printf("save: %v", err)
			}
			flushed = time.Now()
		}
		select {
		case <-t.C:
		case <-a.poke:
		}
	}
}

// requestSync runs the loop now (after a user was blocked, deleted or re-keyed).
func (a *App) requestSync() {
	select {
	case a.poke <- struct{}{}:
	default:
	}
}

func (a *App) syncOnce(now time.Time) {
	// Counters are cleared on read: account them even if /online fails below.
	tr, errT := a.stats.TrafficAndClear()
	on, errO := a.stats.Online()
	a.store.Tick(now, tr, on)
	err := errors.Join(errT, errO)
	a.mu.Lock()
	if errO == nil {
		a.online, a.lastSync = on, now
	}
	a.hyErr = ""
	if err != nil {
		a.hyErr = err.Error()
	}
	a.mu.Unlock()
	if errO == nil {
		a.enforce(now, on)
	}
}

// mustDrop reports whether online sessions of name must be closed.
func (a *App) mustDrop(name string, now time.Time) bool {
	u, ok := a.store.Get(name)
	if !ok || u.Blocked(now) != "" {
		return true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	r, ok := a.revoked[name]
	return ok && now.Before(r.until)
}

// enforce closes sessions of deleted, disabled, expired, over-quota and
// re-keyed users.
//
// Hysteria's kick is a one-shot flag per ID: the next traffic of any session
// with that ID closes the session and clears the flag; there is no expiry and no
// way to clear it otherwise. A flag left behind (kicked again after the last
// session was already gone) kills the user's next legitimate session. So a kick
// is sent only for online users, and the next one only after the previous was
// consumed, i.e. the online count dropped.
func (a *App) enforce(now time.Time, on map[string]int) {
	a.mu.Lock()
	for name, r := range a.revoked {
		// on was fetched after `now`; a revocation newer than that may not be reflected yet.
		if (on[name] == 0 && r.at.Before(now)) || !now.Before(r.until) {
			delete(a.revoked, name)
		}
	}
	a.mu.Unlock()

	var kick []string
	for name, n := range on {
		if !a.mustDrop(name, now) {
			delete(a.kicked, name)
			continue
		}
		if prev, pending := a.kicked[name]; pending && n >= prev {
			continue // not consumed yet: the session is idle
		}
		a.kicked[name] = n
		kick = append(kick, name)
	}
	for name := range a.kicked {
		if on[name] == 0 {
			delete(a.kicked, name)
		}
	}
	if len(kick) == 0 {
		return
	}
	sort.Strings(kick)
	log.Printf("kick %v", kick)
	if err := a.stats.Kick(kick); err != nil {
		log.Printf("kick: %v", err)
		for _, n := range kick {
			delete(a.kicked, n)
		}
	}
}
