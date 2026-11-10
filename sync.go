package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
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
	if a.hy == nil {
		writeJSON(w, map[string]any{"ok": false, "id": ""})
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
	if !u.Uses(protoHy2) {
		return false, u.Name, "hysteria off for user"
	}
	if u.MaxDevices > 0 {
		a.mu.RLock()
		on, last := a.hyOnline()
		n := on[u.Name]
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
		if on, at := a.hyOnline(); at.After(last) {
			n, last = on[u.Name], at
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

// Each protocol owns its polling loop. A timeout in one server cannot delay
// traffic, access changes or fresh online status for the other.
func (a *App) syncLoop(ctx context.Context, every time.Duration) {
	var wg sync.WaitGroup
	run := wg.Go
	wake := make([]chan struct{}, len(a.backends))
	for i, b := range a.backends {
		wake[i] = make(chan struct{}, 1)
		if x, ok := b.(*xrayBackend); ok {
			x.refresh = make(chan struct{}, 1)
			run(func() { x.syncUsers(ctx, a.store) })
			run(func() { repeat(ctx, every, nil, func() { x.pollOnlineContext(ctx, a.store.List()) }) })
		}
	}
	for i, b := range a.backends {
		run(func() { repeat(ctx, every, wake[i], func() { a.syncBackend(time.Now(), b) }) })
	}
	flush := time.NewTicker(flushInterval)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-flush.C:
			if err := a.store.Flush(); err != nil {
				log.Printf("save: %v", err)
			}
		case <-a.poke:
			for _, ch := range wake {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}

func repeat(ctx context.Context, every time.Duration, wake <-chan struct{}, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		fn()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-wake:
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

// A backend is a protocol's server as the panel drives it: it reports the
// traffic since the last sync and who is online, and is told who may
// connect. Hysteria asks the panel itself (/auth) and needs no telling.
type backend interface {
	proto() string
	// stats reads and clears the server's counters. A snapshot with nil users
	// means no new online data; the traffic counts anyway.
	stats(now time.Time, users []User) (map[string]trafficEntry, onlineSnapshot, error)
	// push makes the server's users the panel's active users of this
	// protocol: new and unblocked ones in, blocked, deleted and re-keyed
	// ones out, everyone back after the server restarts.
	push(now time.Time, users []User) error
	// errText leads its sync errors in the panel's banner.
	errText() string
}

// live is what the syncs learned about one protocol's server.
type live struct {
	online   map[string]int // per user: Hysteria sessions, Xray client IPs
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

// hyOnline is Hysteria's last session snapshot and when it was taken (zero
// before the first); a.mu held.
func (a *App) hyOnline() (map[string]int, time.Time) {
	if l := a.live[protoHy2]; l != nil {
		return l.online, l.onlineAt
	}
	return nil, time.Time{}
}

func (a *App) syncBackend(now time.Time, b backend) {
	tr, on, statsErr := b.stats(now, a.store.List())
	a.store.Tick(now, tr, on.users)
	a.mu.Lock()
	l := a.live[b.proto()]
	if l == nil {
		l = &live{}
		a.live[b.proto()] = l
	}
	if on.users != nil {
		l.online, l.onlineAt = on.users, on.at
		if b.proto() == protoHy2 {
			for name, deadlines := range a.reservations {
				if len(deadlines) == 0 || !deadlines[len(deadlines)-1].After(on.at) {
					delete(a.reservations, name)
				}
			}
		}
	}
	a.mu.Unlock()
	if b.proto() == protoHy2 && a.hy != nil && on.users != nil {
		a.enforce(now, on.users)
	}
	var pushErr error
	if x, ok := b.(*xrayBackend); ok && x.refresh != nil {
		select {
		case x.refresh <- struct{}{}:
		default:
		}
		x.onlineMu.Lock()
		pushErr = x.pushErr
		x.onlineMu.Unlock()
	} else {
		pushErr = b.push(time.Now(), a.store.List())
	}
	a.mu.Lock()
	l.err, l.fails = failing(l.fails, errors.Join(statsErr, pushErr))
	a.mu.Unlock()
}

// failing shows an error once it repeats: one miss right after a restart
// (the panel came up before Hysteria or Xray) is not worth a banner.
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

// push: Hysteria asks the panel at every connect (/auth), and enforce
// closes sessions that must go.
func (b *hyBackend) push(time.Time, []User) error { return nil }

// ---- Xray (VLESS + Reality) ----

// xrayBackend is Xray's gRPC API for the VLESS inbound the panel keeps.
type xrayBackend struct {
	batchUnsupported bool // owned by the online worker
	refresh          chan struct{}
	pushErr          error
	onlineMu         sync.Mutex
	pendingOnline    onlineSnapshot
	onlineErr        error
	api              *xrayAPI
	tag              string // the inbound
	flow             string // given to every user: xtls-rprx-vision on TCP, none with XHTTP
}

func (b *xrayBackend) proto() string   { return protoVless }
func (b *xrayBackend) errText() string { return "Нет связи с API Xray: " }

// stats reads and clears Xray's per-user counters and consumes the latest
// online snapshot collected by the independent worker.
func (b *xrayBackend) stats(time.Time, []User) (map[string]trafficEntry, onlineSnapshot, error) {
	tr, err := b.api.TrafficAndClear()
	b.onlineMu.Lock()
	defer b.onlineMu.Unlock()
	on := b.pendingOnline
	b.pendingOnline = onlineSnapshot{}
	return tr, on, errors.Join(err, b.onlineErr)
}

// Only the online worker makes per-user requests.
func (b *xrayBackend) pollOnlineContext(parent context.Context, users []User) {
	// A long poll must not make its oldest results appear fresh.
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var pollErr error
	var on map[string]int
	if !b.batchUnsupported {
		on, pollErr = b.api.OnlineUsers(ctx)
		var ge *grpcError
		if errors.As(pollErr, &ge) && ge.code == 12 {
			b.batchUnsupported = true
		}
	}
	if b.batchUnsupported {
		on, pollErr = b.pollOnlineLegacy(ctx, users)
	}
	b.onlineMu.Lock()
	b.pendingOnline, b.onlineErr = onlineSnapshot{on, started}, pollErr
	b.onlineMu.Unlock()
}

func (b *xrayBackend) pollOnlineLegacy(ctx context.Context, users []User) (map[string]int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var pollErr error
	on := map[string]int{}
	jobs := make(chan User)
	var wg sync.WaitGroup
	for range min(8, len(users)) {
		wg.Go(func() {
			for u := range jobs {
				n, err := b.api.onlineContext(ctx, u.Name)
				mu.Lock()
				if err != nil {
					if pollErr == nil {
						pollErr = err
					}
					cancel()
				} else if n > 0 {
					on[u.Name] = n
				}
				mu.Unlock()
			}
		})
	}
send:
	for _, u := range users {
		select {
		case jobs <- u:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	if pollErr != nil {
		return nil, pollErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return on, nil
}

func (b *xrayBackend) syncUsers(ctx context.Context, store *Store) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-b.refresh:
			if !ok {
				return
			}
		}
		err := b.pushContext(ctx, time.Now(), store.List())
		b.onlineMu.Lock()
		b.pushErr = err
		b.onlineMu.Unlock()
	}
}

// push makes the inbound's users exactly the panel's active users. Xray
// has no auth callback like Hysteria's: whoever is in its list gets in. So
// blocked, deleted and re-keyed users are taken out (new connections are
// refused, open ones end when they close), and after an Xray restart (its
// config lists nobody) everyone is put back.
func (b *xrayBackend) push(now time.Time, users []User) error {
	return b.pushContext(context.Background(), now, users)
}
func (b *xrayBackend) pushContext(ctx context.Context, now time.Time, users []User) error {
	have, err := b.api.usersContext(ctx, b.tag)
	if err != nil {
		return err
	}
	var add []User
	for _, u := range users {
		if !u.Allowed(protoVless, now) {
			continue // stays in have: taken out below
		}
		if have[u.Name] == u.UUID {
			delete(have, u.Name)
			continue
		}
		add = append(add, u)
	}
	var errs []error
	var gone, added []string
	// Removals first: a re-keyed user's e-mail must be free to be added again.
	for name := range have {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := b.api.removeUserContext(ctx, b.tag, name); err != nil {
			errs = append(errs, err)
		} else {
			gone = append(gone, name)
		}
	}
	for _, u := range add {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := b.api.addUserContext(ctx, b.tag, u.Name, u.UUID, b.flow); err != nil {
			errs = append(errs, err)
		} else {
			added = append(added, u.Name)
		}
	}
	if len(gone)+len(added) > 0 {
		sort.Strings(gone)
		sort.Strings(added)
		log.Printf("xray users: -%v +%v", gone, added)
	}
	return errors.Join(errs...)
}

// watchTarget checks hourly that the site Reality impersonates still answers
// like a browser expects. When it is gone, probes of the server get errors
// instead of that site, and the server stands out. Two failures in a row
// (a minute apart) raise the banner.
func (a *App) watchTarget(ctx context.Context, target, sni string) {
	fails := 0
	for {
		err := checkTarget(target, sni)
		if err == nil {
			fails = 0
		} else {
			fails++
			log.Printf("reality target %s: %v", target, err)
		}
		a.mu.Lock()
		a.targetErr = ""
		if fails >= 2 {
			a.targetErr = fmt.Sprintf("Сайт для маскировки VLESS (%s) не отвечает по TLS 1.3 + HTTP/2: %v. Смени его в панели: VLESS + Reality → «Настройки»", sni, err)
		}
		a.mu.Unlock()
		delay := time.Hour
		if fails == 1 {
			delay = time.Minute
		}
		if !sleepCtx(ctx, delay) {
			return
		}
	}
}

// mustDrop reports whether online sessions of name must be closed.
func (a *App) mustDrop(name string, now time.Time) bool {
	u, ok := a.store.Get(name)
	if !ok || !u.Allowed(protoHy2, now) {
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
