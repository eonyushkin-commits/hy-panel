package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed index.html
var assets embed.FS

type App struct {
	store    *Store
	hy       *hyBackend // nil: Hysteria not set up
	backends []backend  // the protocols' servers the panel syncs, Hysteria's first
	hyOpts   *hyOpts    // Hysteria's port, obfs, certificate; nil: not set up
	agent    *agentClient
	siteScan scanState // the search for a Reality site
	ep       Endpoint
	password string
	subBase  string   // public base URL of the subscription listener, "" = disabled
	cfgErr   string   // Hysteria or Xray config unreadable: no links are handed out
	warns    []string // shown in the panel banner (set once before serving)
	key      []byte
	loginMu  sync.Mutex // serializes logins: ~1 guess/s total, not per connection
	poke     chan struct{}

	mu        sync.RWMutex
	live      map[string]*live // per protocol: who is online, sync errors
	targetErr string
	lastSync  time.Time             // Hysteria's sessions were last read
	revoked   map[string]revocation // password changed: drop old sessions
	listenErr map[string]string     // public listener → why it does not run

	kicked map[string]int // syncLoop only: pending kick -> online count when sent
}

// newApp makes the panel; stats is Hysteria's trafficStats, nil if it is
// not set up. Xray's and AmneziaWG's backends are added after.
func newApp(store *Store, stats *statsClient, ep Endpoint, password string, key []byte) *App {
	a := &App{store: store, ep: ep, password: password, key: key,
		poke: make(chan struct{}, 1), live: map[string]*live{}, revoked: map[string]revocation{},
		listenErr: map[string]string{}, kicked: map[string]int{}}
	if stats != nil {
		a.hy = &hyBackend{c: stats}
		a.addBackend(a.hy)
	}
	return a
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

// keepServing runs a public listener; if it fails (port taken, certificate),
// the panel keeps running — /auth must not go down with it — and says why.
func (a *App) keepServing(name string, run func() error) {
	for {
		a.mu.Lock()
		delete(a.listenErr, name)
		a.mu.Unlock()
		err := run()
		log.Printf("%s: %v (retry in 30s)", name, err)
		a.mu.Lock()
		a.listenErr[name] = err.Error()
		a.mu.Unlock()
		time.Sleep(30 * time.Second)
	}
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
	Online  map[string]int `json:"online"` // per protocol: Hysteria sessions, VLESS client IPs, AmneziaWG 1
	Status  string         `json:"status"` // "", disabled, expired, quota
	Links   []link         `json:"links"`  // the user's protocols, in fallback order
	SubPath string         `json:"subPath"`
}

type link struct {
	Proto string `json:"proto"`
	URI   string `json:"uri"`
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	online := map[string]map[string]int{}
	for p, l := range a.live {
		online[p] = l.online
	}
	last := a.lastSync
	var listen []string
	for name, e := range a.listenErr {
		listen = append(listen, name+": "+e)
	}
	sort.Strings(listen)
	var problems []string
	if a.cfgErr != "" {
		problems = append(problems, a.cfgErr)
	}
	problems = append(problems, a.warns...)
	for _, b := range a.backends {
		if l := a.live[b.proto()]; l != nil && l.err != "" {
			problems = append(problems, b.errText()+l.err)
		}
	}
	if a.targetErr != "" {
		problems = append(problems, a.targetErr)
	}
	problems = append(problems, listen...)
	a.mu.RUnlock()
	now := time.Now()
	users := a.store.List()
	views := make([]userView, len(users))
	for i, u := range users {
		views[i] = userView{User: u, Online: map[string]int{}, Status: u.Blocked(now), Links: []link{}, SubPath: "/sub/" + u.SubToken}
		for p, on := range online {
			if n := on[u.Name]; n > 0 {
				views[i].Online[p] = n
			}
		}
		for _, p := range a.ep.userProtos(u) {
			views[i].Links = append(views[i].Links, link{p.ID(), p.Link(a.ep, u)})
		}
	}
	protos := []map[string]string{}
	for _, p := range a.ep.running() {
		protos = append(protos, map[string]string{"id": p.ID(), "title": p.Title()})
	}
	var vless any
	if v := a.ep.Vless; v != nil {
		vless = map[string]any{"port": v.Port, "sni": v.SNI, "network": v.Network}
	}
	writeJSON(w, map[string]any{
		"users": views,
		"server": map[string]any{"host": a.ep.Host, "port": a.ep.Port, "obfs": a.ep.ObfsType, "sni": a.ep.SNI, "pinned": a.ep.Pin != "",
			"vless": vless, "protocols": protos},
		"problems": strings.Join(problems, "; "),
		"lastSync": last.Unix(),
		"subBase":  a.subBase,
	})
}

type userPatch struct {
	Name         string    `json:"name"`
	Password     *string   `json:"password"` // "" = generate
	Enabled      *bool     `json:"enabled"`
	QuotaBytes   *int64    `json:"quotaBytes"`
	ResetMonthly *bool     `json:"resetMonthly"`
	ExpiresAt    *int64    `json:"expiresAt"`
	MaxDevices   *int      `json:"maxDevices"`
	Note         *string   `json:"note"`
	ProtoOff     *[]string `json:"protoOff"` // protocols the user may not use
	ResetTraffic bool      `json:"resetTraffic"`
	NewKey       bool      `json:"newKey"` // new password, VLESS key and subscription link
}

// check rejects a hand-set password too short for Hysteria, which also
// accepts a bare password without the user name.
func (p userPatch) check() error {
	if p.Password != nil && *p.Password != "" && len(*p.Password) < 8 {
		return errors.New("пароль: не короче 8 символов (пусто — сгенерировать)")
	}
	if p.ProtoOff != nil {
		for _, id := range *p.ProtoOff {
			if !knownProto(id) {
				return errors.New("неизвестный протокол: " + id)
			}
		}
	}
	return nil
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
	if p.ProtoOff != nil {
		off := slices.Clone(*p.ProtoOff)
		slices.Sort(off)
		u.ProtoOff = slices.Compact(off)
		if len(u.ProtoOff) == 0 {
			u.ProtoOff = nil
		}
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
		u.UUID = newUUID()
		u.AWGKey = newWGKey()
	}
}

func decode(w http.ResponseWriter, r *http.Request, p *userPatch) bool {
	err := json.NewDecoder(r.Body).Decode(p)
	if err != nil {
		err = errors.New("bad request: " + err.Error())
	} else {
		err = p.check()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	a.requestSync() // into Xray now, not in up to 10 s
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
	}
	a.requestSync() // blocks, re-keys and Xray's user list take effect now
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
	if a.noLinks(w) {
		return
	}
	u, ok := a.store.Get(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	text := a.ep.URI(u)
	if p := r.URL.Query().Get("proto"); slices.Contains(a.ep.Protocols(), p) {
		text = a.ep.Link(p, u)
	}
	if r.URL.Query().Has("sub") && a.subBase != "" {
		text = a.subBase + "/sub/" + u.SubToken
	}
	level, size := qrcode.Medium, 320
	if len(text) > 400 { // an AmneziaWG config: bigger and with less redundancy, so phones read it
		level, size = qrcode.Low, 480
	}
	png, err := qrcode.Encode(text, level, size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

func (a *App) handleMihomo(w http.ResponseWriter, r *http.Request) {
	if a.noLinks(w) {
		return
	}
	u, ok := a.store.Get(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	switch p := q.Get("proto"); {
	case slices.Contains(a.ep.Protocols(), p):
		fmt.Fprint(w, "proxies:\n"+a.ep.MihomoProxy(p, u))
	case q.Has("fallback"):
		fmt.Fprint(w, a.ep.MihomoFallback(u))
	default:
		fmt.Fprint(w, a.ep.MihomoDoc(u))
	}
}

// handleAWGConf downloads u's AmneziaWG config as a file the apps import.
func (a *App) handleAWGConf(w http.ResponseWriter, r *http.Request) {
	if a.noLinks(w) {
		return
	}
	u, ok := a.store.Get(r.PathValue("name"))
	if !ok || !slices.Contains(a.ep.UserProtocols(u), protoAWG) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Apps name the tunnel after the file: keep it short and plain.
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.Map(func(r rune) rune {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return r
		}
		return '-'
	}, a.ep.awgRemark(u))+`.conf"`)
	fmt.Fprint(w, a.ep.AWGConf(u))
}

// ---- subscription (public listener, token-protected) ----

// noLinks answers 503 while the Hysteria or Xray config is unreadable, so
// clients keep their working profile instead of fetching a broken one.
func (a *App) noLinks(w http.ResponseWriter) bool {
	if a.cfgErr != "" {
		http.Error(w, a.cfgErr, http.StatusServiceUnavailable)
		return true
	}
	return false
}

func (a *App) handleSub(w http.ResponseWriter, r *http.Request) {
	if a.noLinks(w) {
		return
	}
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
		fmt.Fprint(w, a.ep.MihomoDoc(u))
	case "raw":
		fmt.Fprint(w, strings.Join(a.ep.URIs(u), "\n")+"\n")
	default:
		fmt.Fprint(w, b64(strings.Join(a.ep.URIs(u), "\n")+"\n"))
	}
}

// ---- protocols: the agent installs and configures them ----

func (a *App) handleSystem(w http.ResponseWriter, r *http.Request) {
	st := map[string]protoStatus{}
	agentErr := ""
	if a.agent == nil {
		agentErr = errNoAgent.Error()
	} else if code, b, err := a.agent.do("GET", "/status", nil); err != nil {
		agentErr = err.Error()
	} else if code != http.StatusOK || json.Unmarshal(b, &st) != nil {
		agentErr = "агент: " + strings.TrimSpace(string(b))
	}
	settings := map[string]any{}
	if o := a.hyOpts; o != nil {
		settings[protoHy2] = map[string]any{"port": o.Port, "obfs": o.Obfs, "domain": o.Domain, "email": o.Email}
	}
	if v := a.ep.Vless; v != nil {
		settings[protoVless] = map[string]any{"port": v.Port, "sni": v.SNI, "network": v.Network}
	}
	if c := a.ep.AWG; c != nil {
		settings[protoAWG] = map[string]any{"port": c.Port, "net": awgNet.String()}
	}
	writeJSON(w, map[string]any{"status": st, "settings": settings, "agentError": agentErr, "host": a.ep.Host})
}

// handleJobStart and handleJob pass the request to the agent, which checks
// it and runs the job; its answer goes back as is.
func (a *App) handleJobStart(w http.ResponseWriter, r *http.Request) {
	a.proxyAgent(w, "POST", "/jobs", r.Body)
}

func (a *App) handleJob(w http.ResponseWriter, r *http.Request) { a.proxyAgent(w, "GET", "/job", nil) }

// handleReleases has the agent ask GitHub now, then answers as GET /api/system.
func (a *App) handleReleases(w http.ResponseWriter, r *http.Request) {
	if a.agent == nil {
		http.Error(w, errNoAgent.Error(), http.StatusServiceUnavailable)
		return
	}
	if code, b, err := a.agent.do("POST", "/releases", nil); err != nil || code != http.StatusOK {
		if err == nil {
			err = errors.New(strings.TrimSpace(string(b)))
		}
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	a.handleSystem(w, r)
}

func (a *App) proxyAgent(w http.ResponseWriter, method, path string, body io.Reader) {
	if a.agent == nil {
		http.Error(w, errNoAgent.Error(), http.StatusServiceUnavailable)
		return
	}
	code, b, err := a.agent.do(method, path, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if code != http.StatusOK {
		http.Error(w, strings.TrimSpace(string(b)), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// handleCheckTarget checks a site for Reality before it is chosen.
func (a *App) handleCheckTarget(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if !validHostname(d) || !strings.Contains(d, ".") {
		http.Error(w, "нужен домен", http.StatusBadRequest)
		return
	}
	res := map[string]any{"ok": true, "note": strings.TrimLeft(subnetNote(d, a.ep.Host), ",; ")}
	if err := checkTarget(net.JoinHostPort(d, "443"), d); err != nil {
		res["ok"], res["error"] = false, err.Error()
	}
	writeJSON(w, res)
}

// handleSiteScanStart starts the search for a Reality site in the server's
// /24 (one at a time); handleSiteScan reports its progress and finds.
func (a *App) handleSiteScanStart(w http.ResponseWriter, r *http.Request) {
	ip, err := serverIPv4(a.ep.Host)
	if err != nil {
		http.Error(w, "адрес сервера: "+err.Error(), http.StatusBadRequest)
		return
	}
	st := &a.siteScan
	st.mu.Lock()
	if !st.Running {
		st.Running, st.Done, st.Found = true, 0, nil
		go newSiteScanner().run(st, ip)
	}
	st.mu.Unlock()
	writeJSON(w, st.snapshot())
}

func (a *App) handleSiteScan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.siteScan.snapshot())
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
	mux.HandleFunc("GET /api/users/{name}/awg.conf", a.guard(a.handleAWGConf))
	mux.HandleFunc("GET /api/system", a.guard(a.handleSystem))
	mux.HandleFunc("POST /api/system/jobs", a.guard(a.handleJobStart))
	mux.HandleFunc("GET /api/system/job", a.guard(a.handleJob))
	mux.HandleFunc("POST /api/system/releases", a.guard(a.handleReleases))
	mux.HandleFunc("GET /api/system/check-target", a.guard(a.handleCheckTarget))
	mux.HandleFunc("POST /api/system/site-scan", a.guard(a.handleSiteScanStart))
	mux.HandleFunc("GET /api/system/site-scan", a.guard(a.handleSiteScan))
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
	w.Header().Set("Cache-Control", "no-store") // carries passwords and links
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

// loopbackHost guards the 127.0.0.1 listener against DNS rebinding: a page
// in the admin's browser (SSH tunnel) reaches it under a foreign host name.
func loopbackHost(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if !isLoopbackHost(strings.Trim(host, "[]")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func isLoopbackReq(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	return err == nil && isLoopbackHost(h)
}
