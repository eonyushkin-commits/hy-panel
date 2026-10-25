package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The agent is the panel's root helper. The panel runs as an unprivileged
// user and cannot touch the system; the agent does a fixed set of things
// for it: install a protocol's server and change its settings. Each action
// is this binary's own command (settings, xray, fetch) run with checked
// flags, one at a time; its output is the job log the panel shows. A
// stolen panel password gets these actions, not a root shell.

const (
	agentDir      = "/run/hy-panel"
	agentSock     = agentDir + "/agent.sock"
	agentUnitPath = "/etc/systemd/system/hy-panel-agent.service"
	panelUser     = "hy-panel"
)

const agentUnit = `[Unit]
Description=hy-panel agent (installs and configures protocols for the panel)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hy-panel agent
RuntimeDirectory=hy-panel
RuntimeDirectoryMode=0755
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`

type job struct {
	ID      int64  `json:"id"`
	Action  string `json:"action"`
	Running bool   `json:"running"`
	OK      bool   `json:"ok"`
	Log     string `json:"log"`
}

type agent struct {
	bin string
	mu  sync.Mutex
	job job
	log bytes.Buffer
}

func (a *agent) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.log.Len() > 1<<20 {
		return len(p), nil // a runaway job: keep the start
	}
	return a.log.Write(p)
}

// jobArgs turns a request from the panel into the command to run, or says
// why not. Values only ever become single arguments of fixed flags.
func jobArgs(action string, p map[string]string) ([]string, error) {
	switch action {
	case "hysteria":
		f := hyFlags{port: p["port"], obfs: p["obfs"], cert: p["cert"], domain: p["domain"], email: p["email"]}
		if err := f.check(); err != nil {
			return nil, err
		}
		args := []string{"settings", "-y"}
		for _, kv := range [][2]string{{"port", f.port}, {"obfs", f.obfs}, {"cert", f.cert}, {"domain", f.domain}, {"email", f.email}} {
			if kv[1] != "" {
				args = append(args, "-"+kv[0], kv[1])
			}
		}
		return args, nil
	case "vless":
		args := []string{"xray", "-y"}
		if port := p["port"]; port != "" {
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("порт %q: нужен 1–65535", port)
			}
			args = append(args, "-port", port)
		}
		t := strings.ToLower(strings.TrimSpace(p["target"]))
		if !validHostname(t) || !strings.Contains(t, ".") {
			return nil, fmt.Errorf("сайт для маскировки %q: нужен домен", t)
		}
		return append(args, "-target", t), nil
	case "awg":
		args := []string{"awg", "-y"}
		if port := p["port"]; port != "" {
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("порт %q: нужен 1–65535", port)
			}
			args = append(args, "-port", port)
		}
		return args, nil
	case "update-hysteria", "update-xray":
		return []string{"fetch", strings.TrimPrefix(action, "update-")}, nil
	}
	return nil, fmt.Errorf("неизвестное действие %q", action)
}

func runAgent() {
	log.SetFlags(0)
	if os.Geteuid() != 0 {
		log.Fatal("the agent runs as root (hy-panel-agent.service)")
	}
	bin, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	a := &agent{bin: bin}
	rel := &releases{}
	go rel.watch()
	os.Remove(agentSock)
	l, err := net.Listen("unix", agentSock)
	if err != nil {
		log.Fatal(err)
	}
	// Only root and the panel's group may talk to the agent.
	_, gid := userIDs(panelUser)
	if err := os.Chown(agentSock, 0, gid); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(agentSock, 0o660); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, systemStatus(rel.get)) })
	mux.HandleFunc("POST /releases", func(w http.ResponseWriter, r *http.Request) {
		rel.check()
		writeJSON(w, systemStatus(rel.get))
	})
	mux.HandleFunc("GET /job", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.current()) })
	mux.HandleFunc("POST /jobs", a.handleStart)
	log.Printf("hy-panel agent on %s", agentSock)
	log.Fatal(server("", mux).Serve(l))
}

func (a *agent) current() job {
	a.mu.Lock()
	defer a.mu.Unlock()
	j := a.job
	j.Log = a.log.String()
	return j
}

func (a *agent) handleStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string            `json:"action"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	args, err := jobArgs(req.Action, req.Params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	if a.job.Running {
		a.mu.Unlock()
		http.Error(w, "уже идёт: "+a.job.Action, http.StatusConflict)
		return
	}
	a.job = job{ID: time.Now().UnixNano(), Action: req.Action, Running: true}
	a.log.Reset()
	j := a.job
	a.mu.Unlock()
	log.Printf("job %s: %s %s", req.Action, a.bin, strings.Join(args, " "))
	go a.run(args)
	writeJSON(w, j)
}

func (a *agent) run(args []string) {
	// A job that hangs (a download that never ends) must not hold the agent forever.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.bin, args...)
	cmd.Stdin = nil // no terminal: no questions
	cmd.Stdout, cmd.Stderr = a, a
	cmd.WaitDelay = 10 * time.Second // a child left holding the output does not keep the job open
	err := cmd.Run()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.job.Running, a.job.OK = false, err == nil
	if err != nil {
		fmt.Fprintf(&a.log, "\n✗ %v\n", err)
	}
	log.Printf("job %s: ok=%v", a.job.Action, a.job.OK)
}

// protoStatus is what the panel shows on a protocol's card.
type protoStatus struct {
	Installed bool   `json:"installed"` // server binary and unit present
	Version   string `json:"version"`
	Active    bool   `json:"active"`              // service running
	Latest    string `json:"latest,omitempty"`    // the latest official release, if known
	Update    bool   `json:"update,omitempty"`    // it is newer than the installed one
	LatestErr string `json:"latestErr,omitempty"` // why the latest is not known
}

// systemStatus describes the servers; latest gives a protocol's latest
// release (zero if not known, with the reason if there is one).
func systemStatus(latest func(proto string) (hyVersion, string)) map[string]protoStatus {
	env := readEnvNoFatal()
	_, hySvc := hyPaths(env)
	_, xSvc := xrayPaths(env)
	st := func(proto, bin, svc string, v hyVersion) protoStatus {
		s := protoStatus{Installed: fileExists(bin) && unitExists(svc)}
		if s.Installed {
			s.Version = v.String()
			s.Active = systemctl("is-active", "--quiet", svc) == nil
			if l, err := latest(proto); l != (hyVersion{}) {
				s.Latest, s.Update = l.String(), !v.atLeast(l)
			} else {
				s.LatestErr = err
			}
		}
		return s
	}
	awg := protoStatus{Installed: fileExists(awgCfgPath) && fileExists(awgUnitPath), Version: awgVersion()}
	awg.Active = awg.Installed && systemctl("is-active", "--quiet", "hy-panel-awg") == nil
	return map[string]protoStatus{
		protoHy2:   st(protoHy2, hysteriaBin, hySvc, hysteriaVersion()),
		protoVless: st(protoVless, xrayBin, xSvc, xrayVersion()),
		protoAWG:   awg,
	}
}

// releases knows the latest official release of each server, so the panel
// offers an update only when there is one. It asks a few times a day.
type releases struct {
	mu     sync.Mutex
	latest map[string]hyVersion
	errs   map[string]string
}

func (r *releases) get(proto string) (hyVersion, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.latest[proto]; ok {
		return v, ""
	}
	if e, ok := r.errs[proto]; ok {
		return hyVersion{}, e
	}
	return hyVersion{}, "ещё не проверено"
}

// check asks GitHub now, for both servers at once; false if it did not
// answer for one of them.
func (r *releases) check() bool {
	ok := true
	var wg sync.WaitGroup
	for proto, base := range map[string]string{protoHy2: hysteriaURL, protoVless: xrayURL} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := latestRelease(base)
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.latest == nil {
				r.latest, r.errs = map[string]hyVersion{}, map[string]string{}
			}
			if err != nil {
				log.Printf("latest release: %v", err)
				delete(r.latest, proto)
				r.errs[proto], ok = err.Error(), false
				return
			}
			r.latest[proto] = v
			delete(r.errs, proto)
		}()
	}
	wg.Wait()
	return ok
}

func (r *releases) watch() {
	for {
		next := 6 * time.Hour
		if !r.check() {
			next = 30 * time.Minute
		}
		time.Sleep(next)
	}
}

// latestRelease reads the version off where releases/latest leads, the
// page the downloads come from (base is its download/ URL): GitHub sends it
// to .../releases/tag/app/v2.6.1 (Hysteria) or .../tag/v25.9.11 (Xray),
// through a moved repository's redirect first if there is one. No API, so
// no API rate limit.
func latestRelease(base string) (hyVersion, error) {
	page := strings.TrimSuffix(strings.TrimSuffix(base, "/"), "/download")
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if strings.Contains(r.URL.Path, "/releases/tag/") || len(via) >= 5 {
				return http.ErrUseLastResponse // the tag is in the URL: no need for the page
			}
			return nil
		}}
	resp, err := c.Head(page)
	if err != nil {
		return hyVersion{}, err
	}
	resp.Body.Close()
	loc, _ := resp.Location()
	if loc == nil {
		return hyVersion{}, fmt.Errorf("%s: %s, без перенаправления на релиз", page, resp.Status)
	}
	v := parseVersion(versionRe, []byte(loc.Path))
	if v == (hyVersion{}) {
		return v, fmt.Errorf("%s: %s, версии в перенаправлении нет (%s)", page, resp.Status, loc)
	}
	return v, nil
}

// awgVersion is the amneziawg-go built into this binary, as the card shows it.
func awgVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, m := range bi.Deps {
			if m.Path == "github.com/amnezia-vpn/amneziawg-go" {
				if m.Replace != nil {
					m = m.Replace
				}
				return moduleVersion(m.Version)
			}
		}
	}
	return "встроена"
}

// moduleVersion makes a Go module version readable: a tag stays, a
// pseudo-version (v0.2.20-0.20260724121833-457d920a1a7d) is the commit's
// date and hash, "24.07.2026 (457d920)".
func moduleVersion(v string) string {
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return strings.TrimPrefix(v, "v")
	}
	ts, hash := parts[len(parts)-2], parts[len(parts)-1]
	if i := strings.LastIndex(ts, "."); i >= 0 {
		ts = ts[i+1:]
	}
	t, err := time.Parse("20060102150405", ts)
	if err != nil || len(hash) < 7 {
		return strings.TrimPrefix(v, "v")
	}
	return t.Format("02.01.2006") + " (" + hash[:7] + ")"
}

// readEnvNoFatal is readEnv for the long-running agent: an unreadable file
// means defaults here, not an exit.
func readEnvNoFatal() map[string]string {
	env := map[string]string{}
	b, _ := os.ReadFile(envPath)
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && !strings.HasPrefix(k, "#") {
			env[k] = v
		}
	}
	return env
}

// ---- the panel's side ----

// agentClient talks to the agent over its unix socket.
type agentClient struct{ hc *http.Client }

func newAgentClient(sock string) *agentClient {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	return &agentClient{hc: &http.Client{Timeout: 30 * time.Second, Transport: tr}}
}

var errNoAgent = errors.New("служба hy-panel-agent не отвечает — обнови панель: hy-panel install")

// do passes a request through and returns the agent's answer as is.
func (c *agentClient) do(method, path string, body io.Reader) (int, []byte, error) {
	req, err := http.NewRequest(method, "http://agent"+path, body)
	if err != nil {
		return 0, nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, errNoAgent
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}
