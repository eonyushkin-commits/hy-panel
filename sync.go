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
	revokeWindow   = 2 * time.Minute
	flushInterval  = time.Minute // traffic counters reach the disk at least this often
	onlineFreshFor = 30 * time.Second
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

// Recheck an old full snapshot before refusing a reconnect.
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
		n := a.onlineOf(protoHy2)[u.Name]
		last := a.lastSync
		a.mu.RUnlock()
		if a.hy != nil && time.Since(last) > 30*time.Second {
			last = time.Now()
			on, err := a.hy.c.Online()
			if err != nil {
				return false, u.Name, "device count unavailable"
			}
			n = on[u.Name]
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.lastSync.After(last) {
			n, last = a.onlineOf(protoHy2)[u.Name], a.lastSync
		}
		pending := a.reservations[u.Name]
		for len(pending) > 0 && !pending[0].After(last) {
			pending = pending[1:]
		}
		if n+len(pending) >= u.MaxDevices {
			return false, u.Name, fmt.Sprintf("device limit %d", u.MaxDevices)
		}
		if a.reservations == nil {
			a.reservations = make(map[string][]time.Time)
		}
		a.reservations[u.Name] = append(pending, time.Now().Add(10*time.Second))
	}
	return true, u.Name, ""
}

// ---- sync & enforcement ----

func (a *App) syncLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	flushed := time.Now()
	for {
		a.syncAccess(time.Now())
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

// A backend reads Hysteria traffic and online sessions.
type backend interface {
	proto() string
	// stats reads and clears the server's counters. A snapshot with nil users
	// means no new online data; the traffic counts anyway.
	stats(now time.Time, users []User) (map[string]trafficEntry, onlineSnapshot, error)
	// errText leads its sync errors in the panel's banner.
	errText() string
}

// live is what the syncs learned about one protocol's server.
type live struct {
	online   map[string]int // Hysteria sessions per user
	onlineAt time.Time      // time of the last successful online snapshot
	err      string         // shown once it repeats
	fails    int            // syncs failed in a row
}

type onlineSnapshot struct {
	users map[string]int // nil means no new snapshot; an empty map means nobody online
	at    time.Time
}

func (a *App) addBackend(b backend) { a.backends = append(a.backends, b) }

// onlineOf is the last known online map of protocol p; a.mu held.
func (a *App) onlineOf(p string) map[string]int {
	if l := a.live[p]; l != nil {
		return l.online
	}
	return nil
}

func (a *App) syncAccess(now time.Time) {
	// Counters are cleared on read: account them even if a server fails below.
	type result struct {
		online onlineSnapshot
		err    error
	}
	res := make([]result, len(a.backends))
	var traffic map[string]trafficEntry
	var online map[string]int
	users := a.store.List()
	for i, b := range a.backends {
		tr, on, err := b.stats(now, users)
		traffic, online = addTraffic(traffic, tr), joinOnline(online, on.users)
		res[i] = result{on, err}
	}
	a.store.Tick(now, traffic, online)
	// Hysteria's sessions drive the device limit and the kicks; without
	// Hysteria nobody is online there.
	hyOn := map[string]int{}
	if a.hy != nil {
		hyOn = nil
	}
	a.mu.Lock()
	for i, b := range a.backends {
		l := a.live[b.proto()]
		if l == nil {
			l = &live{}
			a.live[b.proto()] = l
		}
		if res[i].online.users != nil {
			l.online, l.onlineAt = res[i].online.users, res[i].online.at
			if b.proto() == protoHy2 {
				hyOn = res[i].online.users
			}
		}
	}
	if hyOn != nil {
		a.lastSync = now
		for name, deadlines := range a.reservations {
			if !deadlines[len(deadlines)-1].After(now) {
				delete(a.reservations, name)
			}
		}
	}
	a.mu.Unlock()
	if hyOn != nil {
		a.enforce(now, hyOn)
	}
	for i, b := range a.backends {
		a.mu.Lock()
		l := a.live[b.proto()]
		l.err, l.fails = failing(l.fails, res[i].err)
		a.mu.Unlock()
	}
}

// failing shows an error once it repeats: one miss right after a restart
// (the panel came up before Hysteria) is not worth a banner.
func failing(n int, err error) (string, int) {
	if err == nil {
		return "", 0
	}
	if n++; n < 2 {
		return "", n
	}
	return err.Error(), n
}

// ---- Hysteria ----

// hyBackend is Hysteria's trafficStats API: traffic, sessions and kicks.
type hyBackend struct{ c *statsClient }

func (b *hyBackend) proto() string   { return protoHy2 }
func (b *hyBackend) errText() string { return "Нет связи с trafficStats Hysteria: " }

func (b *hyBackend) stats(now time.Time, _ []User) (map[string]trafficEntry, onlineSnapshot, error) {
	tr, errT := b.c.TrafficAndClear()
	on, errO := b.c.Online()
	if errO != nil {
		on = nil
	}
	return tr, onlineSnapshot{on, now}, errors.Join(errT, errO)
}

func addTraffic(a, b map[string]trafficEntry) map[string]trafficEntry {
	if len(b) == 0 {
		return a
	}
	m := make(map[string]trafficEntry, len(a)+len(b))
	for _, src := range []map[string]trafficEntry{a, b} {
		for k, e := range src {
			t := m[k]
			t.Tx += e.Tx
			t.Rx += e.Rx
			m[k] = t
		}
	}
	return m
}

func joinOnline(a, b map[string]int) map[string]int {
	if len(b) == 0 {
		return a
	}
	m := make(map[string]int, len(a)+len(b))
	for _, src := range []map[string]int{a, b} {
		for k, n := range src {
			m[k] += n
		}
	}
	return m
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
// re-keyed users, and of users whose Hysteria was switched off.
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
	if err := a.hy.c.Kick(kick); err != nil {
		log.Printf("kick: %v", err)
		for _, n := range kick {
			delete(a.kicked, n)
		}
	}
}
