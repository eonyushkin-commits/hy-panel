package main

import (
	"context"
	"crypto/rand"
	"embed"
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
	"strings"
	"sync"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/adminauth"
	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"github.com/eonyushkin-commits/hy-panel/internal/hostname"
	"github.com/eonyushkin-commits/hy-panel/internal/model"
	"github.com/eonyushkin-commits/hy-panel/internal/sitescan"
	"github.com/eonyushkin-commits/hy-panel/internal/storage"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed index.html
var assets embed.FS

type App struct {
	reservations map[string][]time.Time // Hysteria admissions awaiting a fresh online snapshot, under mu
	store        *Store
	hy           *hyBackend // nil: Hysteria not set up
	backends     []backend  // the protocols' servers the panel syncs, Hysteria's first
	hyOpts       *hyOpts    // Hysteria's port, obfs, certificate; nil: not set up
	agent        *agentClient
	siteScan     sitescan.State // the search for a Reality site
	ep           Endpoint
	password     string
	subBase      string   // public base URL of the subscription listener, "" = disabled
	cfgErr       string   // Hysteria or Xray config unreadable: no links are handed out
	warns        []string // shown in the panel banner (set once before serving)
	key          []byte
	sessionMu    sync.RWMutex
	sessionPath  string
	loginLimiter adminauth.Limiter
	poke         chan struct{}

	mu        sync.RWMutex
	live      map[string]*live // per protocol: who is online, sync errors
	targetErr string
	revoked   map[string]revocation // password changed: drop old sessions
	listenErr map[string]string     // public listener → why it does not run

	kicked map[string]int // syncLoop only: pending kick -> online count when sent
}

// newApp makes the panel; stats is Hysteria's trafficStats, nil if it is
// not set up. Xray's backend is added after.
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

var readinessClient = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, IdleConnTimeout: time.Minute}}

// A 401 from the local admin API confirms that startup completed, including
// opening the database. Protocol statistics alone cannot prove that /auth runs.
func checkPanelReady(ctx context.Context) error {
	r, err := http.NewRequestWithContext(ctx, "GET", "http://"+panelAddr+"/api/state", nil)
	if err != nil {
		return err
	}
	resp, err := readinessClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("панель не готова: %s", resp.Status)
	}
	return nil
}

// Type=simple systemd units become active before the HTTP socket is ready.
// Configuration rollback must wait for actual readiness before reporting back.
func waitPanelReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var last error
	for ctx.Err() == nil {
		if last = checkPanelReady(ctx); last == nil {
			return nil
		}
		sleepCtx(ctx, 200*time.Millisecond)
	}
	return fmt.Errorf("панель не восстановилась: %w", errors.Join(ctx.Err(), last))
}

// sleepCtx waits d; false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// keepServing runs a public listener; if it fails (port taken, certificate),
// the panel keeps running — /auth must not go down with it — and says why.
func (a *App) keepServing(ctx context.Context, name string, run func() error) {
	for ctx.Err() == nil {
		a.mu.Lock()
		delete(a.listenErr, name)
		a.mu.Unlock()
		err := run()
		if ctx.Err() != nil {
			return
		}
		log.Printf("%s: %v (retry in 30s)", name, err)
		a.mu.Lock()
		if err != nil {
			a.listenErr[name] = err.Error()
		}
		a.mu.Unlock()
		if !sleepCtx(ctx, 30*time.Second) {
			return
		}
	}
}

func serveHTTP(ctx context.Context, srv *http.Server, tls bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	finished := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdown); err != nil {
				srv.Close()
			}
		case <-finished:
		}
	}()
	var err error
	if tls {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	close(finished)
	<-stopped
	return err
}

// ---- panel session ----

const cookieName = "hyp_session"

func (a *App) sign(exp int64) string {
	a.sessionMu.RLock()
	defer a.sessionMu.RUnlock()
	return adminauth.Sign(a.key, a.password, exp)
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	a.sessionMu.RLock()
	defer a.sessionMu.RUnlock()
	return adminauth.Verify(a.key, a.password, c.Value, time.Now())
}

// The panel has one administrator. Logout rotates the persistent signing key,
// revoking that administrator's cookies in every browser, including copied ones.
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		http.Error(w, "session key unavailable", 500)
		return
	}
	a.sessionMu.Lock()
	if a.sessionPath != "" {
		if err := writeAtomic(a.sessionPath, key, 0600); err != nil && !atomicfile.Committed(err) {
			a.sessionMu.Unlock()
			http.Error(w, "не удалось завершить сеансы", 500)
			return
		}
	}
	a.key = key
	a.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if !a.loginLimiter.Allow(time.Now()) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "слишком много попыток, повтори через секунду", http.StatusTooManyRequests)
		return
	}
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !model.EqualSecret(req.Password, a.password) {
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
	Online  map[string]int `json:"online"` // per protocol: Hysteria sessions, VLESS client IPs
	Status  string         `json:"status"` // "", disabled, expired, quota
	Links   []link         `json:"links"`  // the user's protocols, in fallback order
	SubPath string         `json:"subPath"`
}

type link struct {
	Proto string `json:"proto"`
	URI   string `json:"uri"`
}

type onlineStatus struct {
	LastSuccess int64 `json:"lastSuccess"` // 0 until the first successful online poll
	Stale       bool  `json:"stale"`
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	a.mu.RLock()
	online := map[string]map[string]int{}
	freshness := map[string]onlineStatus{}
	for _, b := range a.backends {
		freshness[b.proto()] = onlineStatus{Stale: true}
	}
	for p, l := range a.live {
		online[p] = l.online
		status := onlineStatus{Stale: l.onlineAt.IsZero() || now.Sub(l.onlineAt) >= onlineFreshFor}
		if !l.onlineAt.IsZero() {
			status.LastSuccess = l.onlineAt.Unix()
		}
		freshness[p] = status
	}
	_, last := a.hyOnline()
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
	if err := a.store.Problem(); err != nil {
		problems = append(problems, "Не удалось сохранить пользователей: "+err.Error())
	}
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
		"problems":       strings.Join(problems, "; "),
		"lastSync":       last.Unix(),
		"onlineStatus":   freshness,
		"serverTime":     now.Unix(),
		"onlineFreshFor": int64(onlineFreshFor / time.Second),
		"subBase":        a.subBase,
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
	}
}

func decode(w http.ResponseWriter, r *http.Request, p *userPatch) bool {
	err := decodeJSONBody(r, p)
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
	u, err := a.store.Create(u)
	if err != nil {
		http.Error(w, err.Error(), storeErrorStatus(err))
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
	if err != nil {
		http.Error(w, err.Error(), storeErrorStatus(err))
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
		http.Error(w, err.Error(), storeErrorStatus(err))
		return
	}
	a.requestSync()
	w.WriteHeader(http.StatusNoContent)
}

// exportUser is the user a QR code or mihomo export is for and the protocols
// it may get, in fallback order; ?proto= must be one of them. Otherwise it
// answers the request itself and ok is false.
func (a *App) exportUser(w http.ResponseWriter, r *http.Request) (u User, ps []protocol, ok bool) {
	if a.noLinks(w) {
		return u, nil, false
	}
	if u, ok = a.store.Get(r.PathValue("name")); !ok {
		http.NotFound(w, r)
		return u, nil, false
	}
	if ps = a.ep.userProtos(u); len(ps) == 0 {
		http.Error(w, "нет доступных протоколов для пользователя", http.StatusConflict)
		return u, nil, false
	}
	if p := r.URL.Query().Get("proto"); p != "" && !slices.ContainsFunc(ps, func(x protocol) bool { return x.ID() == p }) {
		http.Error(w, "протокол недоступен пользователю", http.StatusBadRequest)
		return u, nil, false
	}
	return u, ps, true
}

func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	u, ps, ok := a.exportUser(w, r)
	if !ok {
		return
	}
	text := ps[0].Link(a.ep, u)
	if p := r.URL.Query().Get("proto"); p != "" {
		text = a.ep.Link(p, u)
	}
	if r.URL.Query().Has("sub") && a.subBase != "" {
		text = a.subBase + "/sub/" + u.SubToken
	}
	level, size := qrcode.Medium, 320
	if len(text) > 400 { // long share link
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
	u, _, ok := a.exportUser(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	if full := q.Get("full"); full == "router" || full == "desktop" {
		b, err := a.mihomoFull(u, full == "router")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if q.Has("download") {
			w.Header().Set("Content-Disposition", `attachment; filename="`+fileName(a.ep.remark(u))+"-"+full+`.yaml"`)
		}
		w.Write(b)
		return
	}
	switch p := q.Get("proto"); {
	case p != "": // exportUser checked it
		fmt.Fprint(w, "proxies:\n"+a.ep.MihomoProxy(p, u))
	case q.Has("fallback"):
		fmt.Fprint(w, a.ep.MihomoFallback(u))
	default:
		fmt.Fprint(w, a.ep.MihomoDoc(u))
	}
}

// fileName keeps a name to what every system takes in a file name.
func fileName(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return r
		}
		return '-'
	}, s)
}

// mihomoFull is u's complete mihomo config from the current template.
func (a *App) mihomoFull(u User, router bool) ([]byte, error) {
	tmpl, err := mihomoTemplate()
	if err != nil {
		return nil, err
	}
	return a.ep.MihomoFull(tmpl, u, router)
}

// ---- subscription (public listener, token-protected) ----

// A failed protocol must not prevent exporting a healthy one. If no protocol
// remains, fail instead of replacing a client's working profile with emptiness.
func (a *App) noLinks(w http.ResponseWriter) bool {
	if a.cfgErr != "" && len(a.ep.running()) == 0 {
		http.Error(w, a.cfgErr, http.StatusServiceUnavailable)
		return true
	}
	return false
}

func (a *App) handleSub(w http.ResponseWriter, r *http.Request) {
	u, ok := a.store.BySubToken(r.PathValue("token"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if a.noLinks(w) {
		return
	}
	if len(a.ep.userProtos(u)) == 0 {
		http.Error(w, "нет доступных протоколов для пользователя", http.StatusServiceUnavailable)
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
		// The whole config, for Clash Verge and the like; a router's
		// proxy-providers take only its proxies.
		b, err := a.mihomoFull(u, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write(b)
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
	if !hostname.Domain(d) {
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
	ip, err := sitescan.ServerIPv4(a.ep.Host)
	if err != nil {
		http.Error(w, "адрес сервера: "+err.Error(), http.StatusBadRequest)
		return
	}
	a.siteScan.Start(ip)
	writeJSON(w, a.siteScan.Snapshot())
}

func (a *App) handleSiteScan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.siteScan.Snapshot())
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
	mux.HandleFunc("POST /api/logout", a.guard(a.handleLogout))
	mux.HandleFunc("GET /api/state", a.guard(a.handleState))
	mux.HandleFunc("POST /api/users", a.guard(a.handleCreate))
	mux.HandleFunc("PATCH /api/users/{name}", a.guard(a.handlePatch))
	mux.HandleFunc("DELETE /api/users/{name}", a.guard(a.handleDelete))
	mux.HandleFunc("GET /api/users/{name}/qr.png", a.guard(a.handleQR))
	mux.HandleFunc("GET /api/users/{name}/mihomo", a.guard(a.handleMihomo))
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
	return sameOrigin(mux)
}

// ---- helpers ----

func storeErrorStatus(err error) int {
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	var writeErr *storage.WriteError
	if errors.As(err, &writeErr) {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

func decodeJSONBody(r *http.Request, out any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("expected one JSON value")
		}
		return err
	}
	return nil
}

func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != "GET" && r.Method != "HEAD" {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // carries passwords and links
	json.NewEncoder(w).Encode(v)
}

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
