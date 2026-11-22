package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"github.com/eonyushkin-commits/hy-panel/internal/model"
)

const trustTunnelClosedUser = "HY-PANEL-CLOSED" // outside model.NamePattern

type trustTunnelUser struct {
	Username string
	Password string
}

func trustTunnelCredentials(users []trustTunnelUser) []byte {
	var b strings.Builder
	for _, u := range users {
		fmt.Fprintf(&b, "[[client]]\nusername = %q\npassword = %q\n", u.Username, u.Password)
	}
	return []byte(b.String())
}

// Keep authentication enabled even when every panel account is blocked.
func closedTrustTunnelCredentials() []byte {
	return trustTunnelCredentials([]trustTunnelUser{{trustTunnelClosedUser, randStr(32)}})
}

type trustTunnelCounters struct {
	Username string
	Sessions int
	Inbound  int64
	Outbound int64
}

type trustTunnelSnapshot struct {
	Epoch   string
	Clients []trustTunnelCounters
}

var trustTunnelHTTP = &http.Client{
	Timeout:   3 * time.Second,
	Transport: &http.Transport{},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func readTrustTunnelStats() ([]trustTunnelCounters, error) {
	return trustTunnelStatsAt(trustTunnelMetrics)
}

func trustTunnelStatsAt(address string) ([]trustTunnelCounters, error) {
	r, err := trustTunnelHTTP.Get("http://" + address + "/clients")
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TrustTunnel /clients: HTTP %d", r.StatusCode)
	}
	var clients []trustTunnelCounters
	err = json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&clients)
	return clients, err
}

func trustTunnelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /trusttunnel/stats", handleTrustTunnelStats)
	mux.HandleFunc("POST /trusttunnel/users", handleTrustTunnelUsers)
}

func handleTrustTunnelStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	epoch := func() string {
		b, _ := exec.CommandContext(ctx, "systemctl", "show", "-p", "InvocationID", "--value", trustTunnelService).Output()
		return strings.TrimSpace(string(b))
	}
	before := epoch()
	clients, err := readTrustTunnelStats()
	if err != nil || before == "" || before != epoch() {
		http.Error(w, "не удалось прочитать статистику TrustTunnel", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, trustTunnelSnapshot{Epoch: before, Clients: clients})
}

func handleTrustTunnelUsers(w http.ResponseWriter, r *http.Request) {
	var users []trustTunnelUser
	if err := decodeJSONBody(r, &users); err != nil {
		http.Error(w, "некорректный список пользователей TrustTunnel", http.StatusBadRequest)
		return
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	for i, u := range users {
		if !model.NamePattern.MatchString(u.Username) || !trustTunnelPasswordValid(u.Password) ||
			(i > 0 && users[i-1].Username == u.Username) {
			http.Error(w, "некорректные данные пользователя TrustTunnel", http.StatusBadRequest)
			return
		}
	}
	if err := syncTrustTunnelCredentials(users); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func trustTunnelPasswordValid(s string) bool {
	return len(s) == 43 && strings.IndexFunc(s, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')
	}) == -1
}

func syncTrustTunnelCredentials(users []trustTunnelUser) error {
	lock, err := lockTrustTunnel()
	if err != nil {
		return err
	}
	defer lock.Close()
	if readEnvNoFatal()["HYP_TRUSTTUNNEL"] != "1" {
		return errors.New("TrustTunnel отключён")
	}
	old, err := os.ReadFile(trustTunnelCreds)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, systemctl("stop", trustTunnelService))
	}
	data := trustTunnelCredentials(users)
	same := bytes.Equal(old, data)
	if len(users) == 0 {
		same = bytes.HasPrefix(old, []byte("[[client]]\nusername = \""+trustTunnelClosedUser+"\"\n"))
		if !same {
			data = closedTrustTunnelCredentials()
		}
	}
	if same {
		return nil
	}
	if err := atomicfile.Replace(trustTunnelCreds, data, trustTunnelFileOptions()); err != nil {
		return errors.Join(err, systemctl("stop", trustTunnelService))
	}
	// Upstream reads credentials only at startup. Do not undo a manual stop.
	if err := systemctl("try-restart", trustTunnelService); err != nil {
		return errors.Join(err, systemctl("stop", trustTunnelService))
	}
	return nil
}

type trustTunnelBackend struct {
	agent *agentClient
	epoch string
	last  map[string]trafficEntry
}

func (*trustTunnelBackend) proto() string   { return protoTrustTunnel }
func (*trustTunnelBackend) errText() string { return "TrustTunnel: " }

func (b *trustTunnelBackend) stats(now time.Time, _ []User) (map[string]trafficEntry, onlineSnapshot, error) {
	code, out, err := b.agent.do("GET", "/trusttunnel/stats", nil)
	if err != nil {
		return nil, onlineSnapshot{}, err
	}
	if code != http.StatusOK {
		return nil, onlineSnapshot{}, errors.New(strings.TrimSpace(string(out)))
	}
	var s trustTunnelSnapshot
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, onlineSnapshot{}, err
	}
	if s.Epoch == "" {
		return nil, onlineSnapshot{}, errors.New("TrustTunnel: нет идентификатора запуска")
	}
	hadBaseline := b.epoch != ""
	if b.epoch != s.Epoch {
		b.epoch, b.last = s.Epoch, nil
	}
	traffic := make(map[string]trafficEntry, len(s.Clients))
	online := make(map[string]int)
	next := make(map[string]trafficEntry, len(s.Clients))
	for _, u := range s.Clients {
		if !model.NamePattern.MatchString(u.Username) || u.Inbound < 0 || u.Outbound < 0 {
			continue
		}
		before := b.last[u.Username]
		// On first poll after a panel-only restart, no previous baseline survives.
		if hadBaseline {
			traffic[u.Username] = trafficEntry{Tx: max(0, u.Inbound-before.Tx), Rx: max(0, u.Outbound-before.Rx)}
		}
		next[u.Username] = trafficEntry{Tx: u.Inbound, Rx: u.Outbound}
		if u.Sessions > 0 {
			online[u.Username] = u.Sessions
		}
	}
	b.last = next
	return traffic, onlineSnapshot{users: online, at: now}, nil
}

func (b *trustTunnelBackend) push(now time.Time, users []User) error {
	var creds []trustTunnelUser
	for _, u := range users {
		if u.Allowed(protoTrustTunnel, now) {
			creds = append(creds, trustTunnelUser{u.Name, trustTunnelPassword(u)})
		}
	}
	payload, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	code, out, err := b.agent.do("POST", "/trusttunnel/users", bytes.NewReader(payload))
	if err == nil && code != http.StatusNoContent {
		err = errors.New(strings.TrimSpace(string(out)))
	}
	return err
}
