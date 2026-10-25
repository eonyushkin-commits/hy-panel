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
	if !u.Uses(protoHy2) {
		return false, u.Name, "hysteria off for user"
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
	var tr map[string]trafficEntry
	on, errT, errO := map[string]int{}, error(nil), error(nil)
	if a.stats != nil { // nil: Hysteria is not set up
		tr, errT = a.stats.TrafficAndClear()
		on, errO = a.stats.Online()
	}
	xtr, xon, errX := a.xrayStats()
	atr, aon, errA := a.awgStats(now)
	a.store.Tick(now, addTraffic(addTraffic(tr, xtr), atr), joinOnline(joinOnline(on, xon), aon))
	// After Tick: a quota used up just now closes VLESS and AmneziaWG at once.
	if a.xray != nil {
		errX = errors.Join(errX, a.pushXrayUsers(now))
	}
	if a.awg != nil && errA == nil {
		errA = a.pushAWGPeers(now)
	}
	err := errors.Join(errT, errO)
	a.mu.Lock()
	if errO == nil {
		a.online, a.lastSync = on, now
	}
	if xon != nil {
		a.xonline = xon
	}
	if aon != nil {
		a.aonline = aon
	}
	a.awgErr, a.awgFails = failing(a.awgFails, errA)
	a.hyErr, a.hyFails = failing(a.hyFails, err)
	a.xrayErr, a.xrayFails = failing(a.xrayFails, errX)
	a.mu.Unlock()
	if errO == nil {
		a.enforce(now, on)
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

// ---- Xray (VLESS + Reality) ----

// xrayStats reads and clears Xray's per-user counters and counts the users'
// online client IPs (Xray counts addresses, not sessions).
func (a *App) xrayStats() (map[string]trafficEntry, map[string]int, error) {
	if a.xray == nil {
		return nil, nil, nil
	}
	tr, errT := a.xray.TrafficAndClear()
	on := map[string]int{}
	for _, u := range a.store.List() {
		n, err := a.xray.Online(u.Name)
		if err != nil {
			return tr, nil, errors.Join(errT, err)
		}
		if n > 0 {
			on[u.Name] = n
		}
	}
	return tr, on, errT
}

// pushXrayUsers makes the inbound's users exactly the panel's active users.
// Xray has no auth callback like Hysteria's: whoever is in its list gets in.
// So blocked, deleted and re-keyed users are taken out (new connections are
// refused, open ones end when they close), and after an Xray restart (its
// config lists nobody) everyone is put back.
func (a *App) pushXrayUsers(now time.Time) error {
	have, err := a.xray.Users(a.xrayTag)
	if err != nil {
		return err
	}
	var add []User
	for _, u := range a.store.List() {
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
		if err := a.xray.RemoveUser(a.xrayTag, name); err != nil {
			errs = append(errs, err)
		} else {
			gone = append(gone, name)
		}
	}
	for _, u := range add {
		if err := a.xray.AddUser(a.xrayTag, u.Name, u.UUID, a.xrayFlow); err != nil {
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

func (a *App) awgPub(priv string) string {
	if a.awgPubs == nil {
		a.awgPubs = map[string]string{}
	}
	pub, ok := a.awgPubs[priv]
	if !ok {
		pub, _ = wgPublic(priv)
		a.awgPubs[priv] = pub
	}
	return pub
}

// awgStats turns the service's cumulative counters into deltas since the
// last sync (a peer that was re-added or a restarted service starts from
// zero) and counts a user online after a handshake in the last 3 minutes:
// WireGuard re-handshakes every 2 while traffic flows.
func (a *App) awgStats(now time.Time) (map[string]trafficEntry, map[string]int, error) {
	if a.awg == nil {
		return nil, nil, nil
	}
	peers, err := a.awg.Peers()
	if err != nil {
		return nil, nil, err
	}
	byKey := make(map[string]awgPeer, len(peers))
	for _, p := range peers {
		byKey[p.Key] = p
	}
	tr, on := map[string]trafficEntry{}, map[string]int{}
	for _, u := range a.store.List() {
		p, ok := byKey[a.awgPub(u.AWGKey)]
		if !ok {
			continue
		}
		last := a.awgSeen[p.Key]
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
	a.awgSeen = byKey
	return tr, on, nil
}

// pushAWGPeers makes the service's peers exactly the active users with
// AmneziaWG on. A removed peer is cut off at once: its session dies with it.
func (a *App) pushAWGPeers(now time.Time) error {
	want := []awgPeer{}
	for _, u := range a.store.List() {
		if u.Blocked(now) == "" && u.Uses(protoAWG) && u.AWGKey != "" {
			want = append(want, awgPeer{Key: a.awgPub(u.AWGKey), IP: awgIP(u.AWGIndex)})
		}
	}
	return a.awg.SetPeers(want)
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
	if err := a.stats.Kick(kick); err != nil {
		log.Printf("kick: %v", err)
		for _, n := range kick {
			delete(a.kicked, n)
		}
	}
}
