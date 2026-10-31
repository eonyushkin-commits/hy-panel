package main

import (
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
		n := a.onlineOf(protoHy2)[u.Name]
		last := a.lastSync
		a.mu.RUnlock()
		if n >= u.MaxDevices && a.hy != nil && time.Since(last) > 30*time.Second {
			on, err := a.hy.c.Online()
			if err != nil {
				return false, u.Name, "device count unavailable"
			}
			n = on[u.Name]
		}
		if n >= u.MaxDevices {
			return false, u.Name, fmt.Sprintf("device limit %d", u.MaxDevices)
		}
	}
	return true, u.Name, ""
}

// ---- sync & enforcement ----

func (a *App) syncLoop(every time.Duration) {
	for _, backend := range a.backends {
		if x, ok := backend.(*xrayBackend); ok {
			go func() {
				for {
					x.pollOnline(a.store.List())
					time.Sleep(every)
				}
			}()
		}
	}
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

// A backend is a protocol's server as the panel drives it: it reports the
// traffic since the last sync and who is online, and is told who may
// connect. Hysteria asks the panel itself (/auth) and needs no telling.
type backend interface {
	proto() string
	// stats reads and clears the server's counters. A nil online map means
	// the server could not say; the traffic counts anyway.
	stats(now time.Time, users []User) (map[string]trafficEntry, map[string]int, error)
	// push makes the server's users the panel's active users of this
	// protocol: new and unblocked ones in, blocked, deleted and re-keyed
	// ones out, everyone back after the server restarts.
	push(now time.Time, users []User) error
	// errText leads its sync errors in the panel's banner.
	errText() string
}

// live is what the syncs learned about one protocol's server.
type live struct {
	online map[string]int // per user: Hysteria sessions, Xray client IPs, AmneziaWG 1
	err    string         // shown once it repeats
	fails  int            // syncs failed in a row
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
		online map[string]int
		err    error
	}
	res := make([]result, len(a.backends))
	var traffic map[string]trafficEntry
	var online map[string]int
	users := a.store.List()
	for i, b := range a.backends {
		tr, on, err := b.stats(now, users)
		traffic, online = addTraffic(traffic, tr), joinOnline(online, on)
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
		if res[i].online != nil {
			l.online = res[i].online
			if b.proto() == protoHy2 {
				hyOn = res[i].online
			}
		}
	}
	if hyOn != nil {
		a.lastSync = now
	}
	a.mu.Unlock()
	if hyOn != nil {
		a.enforce(now, hyOn)
	}
	// Publish sessions before updating a potentially large user list.
	// Tick has already applied quotas, so exhausted users are removed here.
	users = a.store.List()
	for i, b := range a.backends {
		err := errors.Join(res[i].err, b.push(now, users))
		a.mu.Lock()
		l := a.live[b.proto()]
		l.err, l.fails = failing(l.fails, err)
		a.mu.Unlock()
	}
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

func (b *hyBackend) stats(time.Time, []User) (map[string]trafficEntry, map[string]int, error) {
	tr, errT := b.c.TrafficAndClear()
	on, errO := b.c.Online()
	if errO != nil {
		on = nil
	}
	return tr, on, errors.Join(errT, errO)
}

// push: Hysteria asks the panel at every connect (/auth), and enforce
// closes sessions that must go.
func (b *hyBackend) push(time.Time, []User) error { return nil }

// ---- Xray (VLESS + Reality) ----

// xrayBackend is Xray's gRPC API for the VLESS inbound the panel keeps.
type xrayBackend struct {
	onlineMu      sync.Mutex
	pendingOnline map[string]int
	onlineErr     error
	api           *xrayAPI
	tag           string // the inbound
	flow          string // given to every user: xtls-rprx-vision on TCP, none with XHTTP
}

func (b *xrayBackend) proto() string   { return protoVless }
func (b *xrayBackend) errText() string { return "Нет связи с API Xray: " }

// stats reads and clears Xray's per-user counters and consumes the latest
// online snapshot collected by the independent worker.
func (b *xrayBackend) stats(time.Time, []User) (map[string]trafficEntry, map[string]int, error) {
	tr, err := b.api.TrafficAndClear()
	b.onlineMu.Lock()
	defer b.onlineMu.Unlock()
	on := b.pendingOnline
	b.pendingOnline = nil
	return tr, on, errors.Join(err, b.onlineErr)
}

// Only the online worker makes per-user requests.
func (b *xrayBackend) pollOnline(users []User) {
	var pollErr error
	on := map[string]int{}
	for _, u := range users {
		n, err := b.api.Online(u.Name)
		if err != nil {
			on, pollErr = nil, err
			break
		}
		if n > 0 {
			on[u.Name] = n
		}
	}
	b.onlineMu.Lock()
	b.pendingOnline, b.onlineErr = on, pollErr
	b.onlineMu.Unlock()
}

// push makes the inbound's users exactly the panel's active users. Xray
// has no auth callback like Hysteria's: whoever is in its list gets in. So
// blocked, deleted and re-keyed users are taken out (new connections are
// refused, open ones end when they close), and after an Xray restart (its
// config lists nobody) everyone is put back.
func (b *xrayBackend) push(now time.Time, users []User) error {
	have, err := b.api.Users(b.tag)
	if err != nil {
		return err
	}
	var add []User
	for _, u := range users {
		if u.Blocked(now) != "" || !u.Uses(protoVless) {
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
		if err := b.api.RemoveUser(b.tag, name); err != nil {
			errs = append(errs, err)
		} else {
			gone = append(gone, name)
		}
	}
	for _, u := range add {
		if err := b.api.AddUser(b.tag, u.Name, u.UUID, b.flow); err != nil {
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

// ---- AmneziaWG ----

// awgBackend is the AmneziaWG service's control socket.
type awgBackend struct {
	c      *awgClient
	seen   map[string]awgPeer // last counters per public key
	pubs   map[string]string  // private → public key, cached
	peered bool               // the last stats call got the peers
}

func newAWGBackend(c *awgClient) *awgBackend { return &awgBackend{c: c} }

func (b *awgBackend) proto() string   { return protoAWG }
func (b *awgBackend) errText() string { return "Нет связи с AmneziaWG: " }

func (b *awgBackend) pub(priv string) string {
	if b.pubs == nil {
		b.pubs = map[string]string{}
	}
	pub, ok := b.pubs[priv]
	if !ok {
		pub, _ = wgPublic(priv)
		b.pubs[priv] = pub
	}
	return pub
}

// stats turns the service's cumulative counters into deltas since the
// last sync (a peer that was re-added or a restarted service starts from
// zero) and counts a user online after a handshake in the last 3 minutes:
// WireGuard re-handshakes every 2 while traffic flows.
func (b *awgBackend) stats(now time.Time, users []User) (map[string]trafficEntry, map[string]int, error) {
	peers, err := b.c.Peers()
	b.peered = err == nil
	if err != nil {
		return nil, nil, err
	}
	byKey := make(map[string]awgPeer, len(peers))
	for _, p := range peers {
		byKey[p.Key] = p
	}
	tr, on := map[string]trafficEntry{}, map[string]int{}
	for _, u := range users {
		p, ok := byKey[b.pub(u.AWGKey)]
		if !ok {
			continue
		}
		last := b.seen[p.Key]
		d := trafficEntry{Tx: p.Rx - last.Rx, Rx: p.Tx - last.Tx} // Tx: from the client
		if d.Tx < 0 || d.Rx < 0 {
			d = trafficEntry{Tx: p.Rx, Rx: p.Tx}
		}
		if d.Tx > 0 || d.Rx > 0 {
			tr[u.Name] = d
		}
		if p.LastHandshake > 0 && now.Unix()-p.LastHandshake < 180 {
			on[u.Name] = 1
		}
	}
	b.seen = byKey
	return tr, on, nil
}

// push makes the service's peers exactly the active users with AmneziaWG
// on. A removed peer is cut off at once: its session dies with it. Not
// while the service does not answer: the stats error says so already.
func (b *awgBackend) push(now time.Time, users []User) error {
	if !b.peered {
		return nil
	}
	want := []awgPeer{}
	for _, u := range users {
		if u.Blocked(now) == "" && u.Uses(protoAWG) && u.AWGKey != "" {
			want = append(want, awgPeer{Key: b.pub(u.AWGKey), IP: awgIP(u.AWGIndex)})
		}
	}
	return b.c.SetPeers(want)
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

// watchTarget checks hourly that the site Reality impersonates still answers
// like a browser expects. When it is gone, probes of the server get errors
// instead of that site, and the server stands out. Two failures in a row
// (a minute apart) raise the banner.
func (a *App) watchTarget(target, sni string) {
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
		if fails == 1 {
			time.Sleep(time.Minute)
		} else {
			time.Sleep(time.Hour)
		}
	}
}

// mustDrop reports whether online sessions of name must be closed.
func (a *App) mustDrop(name string, now time.Time) bool {
	u, ok := a.store.Get(name)
	if !ok || u.Blocked(now) != "" || !u.Uses(protoHy2) {
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
