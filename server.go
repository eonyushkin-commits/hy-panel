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
	"log"
	"net"
	"net/http"
	"net/url"
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
	stats    *statsClient
	ep       Endpoint
	password string
	subBase  string // public base URL of the subscription listener, "" = disabled
	cfgErr   string // Hysteria config unreadable: no links are handed out
	key      []byte
	loginMu  sync.Mutex // serializes logins: ~1 guess/s total, not per connection
	poke     chan struct{}

	mu        sync.RWMutex
	online    map[string]int
	hyErr     string
	lastSync  time.Time
	revoked   map[string]revocation // password changed: drop old sessions
	listenErr map[string]string     // public listener → why it does not run

	kicked map[string]int // syncLoop only: pending kick -> online count when sent
}

func newApp(store *Store, stats *statsClient, ep Endpoint, password string, key []byte) *App {
	return &App{store: store, stats: stats, ep: ep, password: password, key: key,
		poke: make(chan struct{}, 1), online: map[string]int{}, revoked: map[string]revocation{},
		listenErr: map[string]string{}, kicked: map[string]int{}}
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
	Online  int    `json:"online"`
	Status  string `json:"status"` // "", disabled, expired, quota
	URI     string `json:"uri"`
	SubPath string `json:"subPath"`
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	on, last := a.online, a.lastSync
	var listen []string
	for name, e := range a.listenErr {
		listen = append(listen, name+": "+e)
	}
	sort.Strings(listen)
	var problems []string
	if a.cfgErr != "" {
		problems = append(problems, a.cfgErr)
	}
	if a.hyErr != "" {
		problems = append(problems, "Нет связи с trafficStats Hysteria: "+a.hyErr)
	}
	problems = append(problems, listen...)
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
		"hyError":  strings.Join(problems, "; "),
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
	if a.noLinks(w) {
		return
	}
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
	if a.noLinks(w) {
		return
	}
	u, ok := a.store.Get(r.PathValue("name"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, a.ep.MihomoDoc(u))
}

// ---- subscription (public listener, token-protected) ----

// noLinks answers 503 while the Hysteria config is unreadable, so clients
// keep their working profile instead of fetching a broken one.
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
