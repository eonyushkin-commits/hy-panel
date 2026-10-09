package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed index.html
var assets embed.FS

const revokeWindow = 2 * time.Minute

// revocation: sessions of a user whose password changed at `at` are dropped
// until they are all gone or `until` passes.
type revocation struct{ at, until time.Time }

type App struct {
	store    *Store
	stats    *statsClient
	ep       Endpoint
	password string
	subBase  string // public base URL of the subscription listener, "" = disabled
	key      []byte
	loginMu  sync.Mutex // serializes logins: ~1 guess/s total, not per connection
	poke     chan struct{}

	mu       sync.RWMutex
	online   map[string]int
	hyErr    string
	lastSync time.Time
	revoked  map[string]revocation // password changed: drop old sessions

	kicked map[string]int // syncLoop only: pending kick -> online count when sent
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			runInstall(os.Args[2:])
			return
		case "uninstall":
			runUninstall(os.Args[2:])
			return
		case "info":
			printInfo()
			return
		case "passwd":
			runPasswd()
			return
		}
	}
	var (
		listen    = flag.String("listen", "127.0.0.1:8090", "UI, API and Hysteria auth backend (keep it on loopback)")
		subListen = flag.String("sub-listen", "", "optional public listener for subscriptions only, e.g. :2096")
		uiListen  = flag.String("ui-listen", "", "optional public HTTPS listener for the UI (self-signed cert), e.g. :9443")
		subURL    = flag.String("sub-url", "", "public base URL of -sub-listen (default http://<host>:<sub port>)")
		hyCfg     = flag.String("hy-config", "/etc/hysteria/config.yaml", "Hysteria 2 server config")
		data      = flag.String("data", "/var/lib/hy-panel/users.json", "user database")
		host      = flag.String("host", "", "public server IP/domain for client links (default: domain from acme/cert)")
		port      = flag.String("port", "", "public port or hopping range, e.g. 20000-50000 (default: from listen)")
		sni       = flag.String("sni", "", "SNI for client links (default: acme domain or cert DNS SAN)")
		name      = flag.String("name", "", "profile name prefix shown in clients")
		interval  = flag.Duration("interval", 10*time.Second, "traffic sync interval")
	)
	flag.Parse()
	log.SetFlags(0) // journald adds timestamps

	password := os.Getenv("HYP_PASSWORD")
	if len(password) < 8 {
		log.Fatal("set HYP_PASSWORD (8+ chars) — the panel always requires a password")
	}
	cfg, err := loadHyConfig(*hyCfg)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.TrafficStats.Listen == "" {
		log.Fatal("trafficStats.listen is not set in hysteria config — the panel needs it for traffic, online and kicks")
	}
	ci, err := readCert(cfg.TLS.Cert)
	if err != nil {
		log.Printf("WARN: tls.cert: %v (no pin/SNI from cert)", err)
	}
	if strings.HasPrefix(cfg.Listen, "realm") {
		log.Fatal("listen is a realm:// address: Realms (NAT traversal) are not supported, links would point nowhere")
	}
	ech, err := readECH(cfg.ECH.KeyPath)
	if err != nil {
		log.Fatalf("ech.keyPath: %v", err)
	}
	store, err := OpenStore(*data)
	if err != nil {
		log.Fatal(err)
	}
	if store.Empty() {
		importUsers(store, cfg)
	}
	checkHyConfig(cfg, *listen)

	app := &App{
		store:    store,
		stats:    newStatsClient(cfg.TrafficStats.Listen, cfg.TrafficStats.Secret),
		ep:       buildEndpoint(cfg, ci, ech, *host, *port, *sni, *name),
		password: password,
		key:      make([]byte, 32),
		poke:     make(chan struct{}, 1),
		online:   map[string]int{},
		revoked:  map[string]revocation{},
		kicked:   map[string]int{},
	}
	rand.Read(app.key)
	if app.ep.Host == "" {
		log.Fatal("-host is required (public IP or domain for client links)")
	}
	log.Printf("links: %s:%s sni=%q obfs=%q pinned=%v ech=%v", app.ep.Host, app.ep.Port, app.ep.SNI, app.ep.ObfsType, app.ep.Pin != "", app.ep.ECH != "")

	if *subListen != "" {
		_, p, err := net.SplitHostPort(*subListen)
		if err != nil {
			log.Fatalf("-sub-listen: %v", err)
		}
		app.subBase = strings.TrimRight(*subURL, "/")
		if app.subBase == "" {
			app.subBase = "http://" + net.JoinHostPort(app.ep.Host, p)
		}
		sub := http.NewServeMux()
		sub.HandleFunc("GET /sub/{token}", app.handleSub)
		go func() { log.Fatal(server(*subListen, sub).ListenAndServe()) }()
		log.Printf("subscriptions on %s (%s)", *subListen, app.subBase)
	}

	if *uiListen != "" {
		cert, fp, err := panelCert(filepath.Dir(*data), app.ep.Host)
		if err != nil {
			log.Fatalf("panel certificate: %v", err)
		}
		srv := server(*uiListen, underPath(os.Getenv("HYP_UI_PATH"), app.routes(false)))
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		go func() { log.Fatal(srv.ListenAndServeTLS("", "")) }()
		log.Printf("UI on https://%s%s (cert sha256 %s)", *uiListen, os.Getenv("HYP_UI_PATH"), fp)
	}

	go app.syncLoop(*interval)
	log.Printf("hy-panel on http://%s, users: %d", *listen, len(store.List()))
	log.Fatal(server(*listen, app.routes(true)).ListenAndServe())
}

func server(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			h.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// checkHyConfig warns about Hysteria settings that make the panel ineffective or exposed.
func checkHyConfig(c *hyConfig, listen string) {
	want := "http://" + listen + "/auth"
	switch t := strings.ToLower(c.Auth.Type); {
	case t != "http":
		log.Printf("WARN: hysteria auth.type is %q — set auth: {type: http, http: {url: %s}}", t, want)
	default:
		u, err := url.Parse(c.Auth.HTTP.URL)
		if err != nil || u.Host != listen || u.Path != "/auth" {
			log.Printf("WARN: hysteria auth.http.url is %q, expected %s", c.Auth.HTTP.URL, want)
		}
	}
	if c.TLS.ClientCA != "" {
		log.Print("WARN: tls.clientCA (mTLS) is set: clients also need a client certificate, links alone will not connect")
	}
	if c.Mimic.Enabled {
		log.Print("WARN: mimic is enabled: clients must run Mimic too; links cannot carry it")
	}
	if h, _, _ := net.SplitHostPort(c.TrafficStats.Listen); h == "" || !isLoopbackHost(h) {
		log.Printf("WARN: trafficStats.listen %q is reachable from outside — use 127.0.0.1:<port>", c.TrafficStats.Listen)
	}
}

func importUsers(s *Store, c *hyConfig) {
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		if c.Auth.Password != "" {
			if _, err := s.Create(User{Name: "default", Password: c.Auth.Password, Enabled: true, Note: "imported"}, true); err == nil {
				log.Print("imported auth.password as user 'default' — existing clients keep working")
			}
		}
	case "userpass":
		for n, p := range c.Auth.UserPass {
			if _, err := s.Create(User{Name: n, Password: p, Enabled: true, Note: "imported"}, true); err != nil {
				log.Printf("import %q: %v", n, err)
			} else {
				log.Printf("imported user %q", n)
			}
		}
	}
}

// ---- sync & enforcement ----

func (a *App) syncLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		a.syncOnce(time.Now())
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
	if errT != nil {
		tr = nil
	}
	if errO != nil {
		on = nil
	}
	if err := a.store.Tick(now, tr, on); err != nil {
		log.Printf("save: %v", err)
	}
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

func (a *App) authorize(auth string) (bool, string, string) {
	u, ok := a.store.Resolve(auth)
	if !ok {
		return false, "", "bad credentials"
	}
	if why := u.Blocked(time.Now()); why != "" {
		return false, u.Name, why
	}
	if u.MaxDevices > 0 {
		on, err := a.stats.Online()
		if err != nil {
			a.mu.RLock()
			on = a.online
			a.mu.RUnlock()
		}
		if on[u.Name] >= u.MaxDevices {
			return false, u.Name, fmt.Sprintf("device limit %d", u.MaxDevices)
		}
	}
	return true, u.Name, ""
}

// ---- panel session ----

const cookieName = "hyp_session"

func (a *App) sign(exp int64) string {
	m := hmac.New(sha256.New, a.key)
	fmt.Fprint(m, exp)
	return strconv.FormatInt(exp, 10) + "." + hex.EncodeToString(m.Sum(nil))
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	exp, err := strconv.ParseInt(strings.SplitN(c.Value, ".", 2)[0], 10, 64)
	return err == nil && time.Now().Unix() < exp && hmac.Equal([]byte(c.Value), []byte(a.sign(exp)))
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	json.NewDecoder(r.Body).Decode(&req)
	a.loginMu.Lock()
	ok := ctEq(req.Password, a.password)
	if !ok {
		time.Sleep(time.Second)
	}
	a.loginMu.Unlock()
	if !ok {
		log.Printf("login failed from %s", r.RemoteAddr)
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}
	exp := time.Now().Add(7 * 24 * time.Hour).Unix()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: a.sign(exp), Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", MaxAge: 7 * 24 * 3600})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// ---- admin API ----

type userView struct {
	User
	Online  int    `json:"online"`
	Status  string `json:"status"` // "", disabled, expired, quota
	URI     string `json:"uri"`
	SubPath string `json:"subPath"`
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	on, hyErr, last := a.online, a.hyErr, a.lastSync
	a.mu.RUnlock()
	now := time.Now()
	users := a.store.List()
	views := make([]userView, len(users))
	for i, u := range users {
		views[i] = userView{User: u, Online: on[u.Name], Status: u.Blocked(now), URI: a.ep.URI(u), SubPath: "/sub/" + u.SubToken}
	}
	writeJSON(w, map[string]any{
		"users":    views,
		"server":   map[string]any{"host": a.ep.Host, "port": a.ep.Port, "obfs": a.ep.ObfsType, "sni": a.ep.SNI, "pinned": a.ep.Pin != ""},
		"hyError":  hyErr,
		"lastSync": last.Unix(),
		"subBase":  a.subBase,
	})
}

type userPatch struct {
	Name         string  `json:"name"`
	Password     *string `json:"password"` // "" = generate
	Enabled      *bool   `json:"enabled"`
	QuotaBytes   *int64  `json:"quotaBytes"`
	ResetMonthly *bool   `json:"resetMonthly"`
	ExpiresAt    *int64  `json:"expiresAt"`
	MaxDevices   *int    `json:"maxDevices"`
	Note         *string `json:"note"`
	ResetTraffic bool    `json:"resetTraffic"`
	NewKey       bool    `json:"newKey"` // new password + new subscription link
}

func (p userPatch) apply(u *User, now time.Time) {
	if p.Enabled != nil {
		u.Enabled = *p.Enabled
	}
	if p.QuotaBytes != nil {
		u.QuotaBytes = max(*p.QuotaBytes, 0)
	}
	if p.ResetMonthly != nil {
		if *p.ResetMonthly && !u.ResetMonthly {
			u.LastReset = yyyymm(now) // first reset on the next 1st, not right away
		}
		u.ResetMonthly = *p.ResetMonthly
	}
	if p.ExpiresAt != nil {
		u.ExpiresAt = max(*p.ExpiresAt, 0)
	}
	if p.MaxDevices != nil {
		u.MaxDevices = max(*p.MaxDevices, 0)
	}
	if p.Note != nil {
		u.Note = strings.TrimSpace(*p.Note)
	}
	if p.ResetTraffic {
		u.Up, u.Down = 0, 0
	}
	if p.Password != nil {
		u.Password = *p.Password
		if u.Password == "" {
			u.Password = randStr(20)
		}
	}
	if p.NewKey {
		u.Password = randStr(20)
		u.SubToken = randStr(24)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func (a *App) handleCreate(w http.ResponseWriter, r *http.Request) {
	var p userPatch
	if !decode(w, r, &p) {
		return
	}
	u := User{Name: p.Name, Enabled: true}
	p.Enabled, p.ResetTraffic, p.NewKey = nil, false, false
	p.apply(&u, time.Now())
	u, err := a.store.Create(u, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, u)
}

func (a *App) handlePatch(w http.ResponseWriter, r *http.Request) {
	var p userPatch
	if !decode(w, r, &p) {
		return
	}
	name := r.PathValue("name")
	now := time.Now()
	var oldPass string
	u, err := a.store.Update(name, func(u *User) error {
		oldPass = u.Password
		p.apply(u, now)
		return nil
	})
	switch {
	case errors.Is(err, errNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if u.Password != oldPass {
		// Hysteria checks auth only on connect: drop sessions opened with the old key.
		a.mu.Lock()
		a.revoked[name] = revocation{at: now, until: now.Add(revokeWindow)}
		a.mu.Unlock()
		a.requestSync()
	} else if u.Blocked(now) != "" {
		a.requestSync()
	}
	writeJSON(w, u)
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Delete(r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	a.requestSync()
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	u, ok := a.store.Get(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	text := a.ep.URI(u)
	if r.URL.Query().Has("sub") && a.subBase != "" {
		text = a.subBase + "/sub/" + u.SubToken
	}
	png, err := qrcode.Encode(text, qrcode.Medium, 320)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

func (a *App) handleMihomo(w http.ResponseWriter, r *http.Request) {
	u, ok := a.store.Get(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "proxies:\n"+a.ep.Mihomo(u))
}

// ---- subscription (public listener, token-protected) ----

func (a *App) handleSub(w http.ResponseWriter, r *http.Request) {
	u, ok := a.store.BySubToken(r.PathValue("token"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	title := a.ep.remark(u)
	h := w.Header()
	h.Set("Subscription-Userinfo", subscriptionUserinfo(u))
	h.Set("Profile-Update-Interval", "12")
	h.Set("Profile-Title", "base64:"+b64(title))
	h.Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(title))
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")

	format := r.URL.Query().Get("format")
	if ua := strings.ToLower(r.UserAgent()); format == "" && (strings.Contains(ua, "mihomo") || strings.Contains(ua, "clash")) {
		format = "mihomo" // mihomo's default UA is clash.meta/<version>
	}
	switch format {
	case "mihomo", "clash":
		fmt.Fprint(w, "proxies:\n"+a.ep.Mihomo(u))
	case "raw":
		fmt.Fprintln(w, a.ep.URI(u))
	default:
		fmt.Fprint(w, b64(a.ep.URI(u)+"\n"))
	}
}

// underPath serves h only below a secret path, like 3x-ui's web base path:
// everything else is a plain 404, so scanners do not find the panel.
func underPath(p string, h http.Handler) http.Handler {
	p = "/" + strings.Trim(p, "/")
	if p == "/" {
		return h
	}
	strip := http.StripPrefix(p, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == p:
			http.Redirect(w, r, p+"/", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, p+"/"):
			strip.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// routes: withAuth adds Hysteria's /auth backend (loopback listener only).
func (a *App) routes(withAuth bool) http.Handler {
	mux := http.NewServeMux()
	if withAuth {
		mux.HandleFunc("POST /auth", a.handleAuth)
	}
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/state", a.guard(a.handleState))
	mux.HandleFunc("POST /api/users", a.guard(a.handleCreate))
	mux.HandleFunc("PATCH /api/users/{name}", a.guard(a.handlePatch))
	mux.HandleFunc("DELETE /api/users/{name}", a.guard(a.handleDelete))
	mux.HandleFunc("GET /api/users/{name}/qr.png", a.guard(a.handleQR))
	mux.HandleFunc("GET /api/users/{name}/mihomo", a.guard(a.handleMihomo))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		b, _ := assets.ReadFile("index.html")
		w.Write(b)
	})
	return mux
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func ctEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackReq(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && isLoopbackHost(h)
}
