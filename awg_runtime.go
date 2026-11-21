package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/model"
)

const awgTable = "hy_panel_awg"

var awgRuntimeDir = agentDir

// Fixed commands only; never accept shell snippets, wg-quick hooks, interface
// names, filesystem paths or firewall expressions from a browser request.
var awgExec = func(input string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func configuredAWG() (*awgConfig, error) {
	path := readEnvNoFatal()["HYP_AWG_CONFIG"]
	if path == "" {
		return nil, errors.New("AmneziaWG не настроен")
	}
	return readAWG(path)
}

type awgRuntime struct {
	mu       sync.Mutex
	epoch    string
	lastSync time.Time
	config   *awgConfig
	external string
	ready    bool
}

type awgRuntimeState struct{ Alias, External, Subnet string }

func validExternalInterface(s string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(s) && s != awgInterface
}

func (m *awgRuntime) revoke() error {
	if m.config == nil {
		return nil
	}
	owned, err := awgOwned(m.config)
	if err != nil || !owned {
		return err
	}
	if err = awgApplyPeers(m.config, nil); err != nil {
		return errors.Join(err, m.down())
	}
	return nil
}

func awgAlias(c *awgConfig) string {
	pub, _ := model.AWGPublicKey(c.PrivateKey)
	return "hy-panel:awg:" + pub
}

// The alias and live public key must both match before adopting or deleting
// an interface. A foreign same-named interface is never modified.
func awgOwned(c *awgConfig) (bool, error) {
	out, err := awgExec("", "ip", "-j", "link", "show", "dev", awgInterface)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "Cannot find device") {
			return false, nil
		}
		return false, err
	}
	var links []struct {
		Ifalias string `json:"ifalias"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return false, err
	}
	if len(links) != 1 || links[0].Ifalias != awgAlias(c) {
		return false, errors.New("hyp-awg занят чужим интерфейсом; изменения отменены")
	}
	pub, err := awgExec("", "awg", "show", awgInterface, "public-key")
	expected, _ := model.AWGPublicKey(c.PrivateKey)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(string(pub)) != expected {
		return false, errors.New("публичный ключ hyp-awg не совпадает; изменения отменены")
	}
	return true, nil
}

func awgTableExists() (bool, error) {
	out, err := awgExec("", "nft", "-j", "list", "table", "inet", awgTable)
	if err != nil {
		if strings.Contains(err.Error(), "No such file") {
			return false, nil
		}
		return false, err
	}
	var doc struct {
		NFTables []struct {
			Table *struct {
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return false, err
	}
	for _, item := range doc.NFTables {
		if item.Table != nil && item.Table.Comment == "hy-panel AWG" {
			return true, nil
		}
	}
	return false, errors.New("таблица nft hy_panel_awg не принадлежит панели")
}

func awgFirewall(c *awgConfig, external string, exists bool) string {
	var b strings.Builder
	if exists {
		fmt.Fprintf(&b, "delete table inet %s\n", awgTable)
	}
	fmt.Fprintf(&b, `table inet %s {
 comment "hy-panel AWG"
 chain input { type filter hook input priority -10; policy accept;
  iifname "%s" drop
 }
 chain forward { type filter hook forward priority -10; policy accept;
  iifname "%s" meta nfproto ipv6 drop
  iifname "%s" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } drop
  iifname "%s" oifname "%s" ip saddr %s accept
  iifname "%s" drop
  oifname "%s" ct state established,related accept
  oifname "%s" drop
 }
 chain nat { type nat hook postrouting priority srcnat; policy accept;
  ip saddr %s oifname "%s" masquerade
 }
}
`, awgTable, awgInterface, awgInterface, awgInterface, awgInterface, external, c.Subnet, awgInterface, awgInterface, awgInterface, c.Subnet, external)
	return b.String()
}

func awgForwardRules(c *awgConfig, external string) [][]string {
	return [][]string{
		{"-i", awgInterface, "-o", external, "-s", c.Subnet, "-m", "comment", "--comment", "hy-panel AWG", "-j", "ACCEPT"},
		{"-i", external, "-o", awgInterface, "-d", c.Subnet, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "hy-panel AWG", "-j", "ACCEPT"},
	}
}

func awgNetwork(c *awgConfig) (string, error) {
	out, err := awgExec("", "ip", "-j", "route", "get", "1.1.1.1")
	if err != nil {
		return "", err
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return "", err
	}
	if len(routes) != 1 || !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(routes[0].Dev) || routes[0].Dev == awgInterface {
		return "", errors.New("не удалось определить внешний сетевой интерфейс")
	}
	out, err = awgExec("", "ip", "-j", "route", "show", "table", "all")
	if err != nil {
		return "", err
	}
	var all []struct {
		Dst string `json:"dst"`
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(out, &all); err != nil {
		return "", err
	}
	wanted, _ := netip.ParsePrefix(c.Subnet)
	for _, route := range all {
		if route.Dev == awgInterface || route.Dst == "default" {
			continue
		}
		p, err := netip.ParsePrefix(route.Dst)
		if err != nil {
			if ip, e := netip.ParseAddr(route.Dst); e == nil {
				p = netip.PrefixFrom(ip, 32)
			} else {
				continue
			}
		}
		if p.Bits() > 0 && p.Overlaps(wanted) {
			return "", fmt.Errorf("подсеть AWG %s пересекается с маршрутом %s на %s", c.Subnet, route.Dst, route.Dev)
		}
	}
	return routes[0].Dev, nil
}

func awgServerConf(c *awgConfig, peers []awgPeer) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %s\n%s", c.PrivateKey, c.Port, c.obfuscation())
	keys, indices, names := map[string]bool{}, map[int]bool{}, map[string]bool{}
	for _, p := range peers {
		key, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil || len(key) != 32 || strings.ContainsAny(p.PublicKey, "\r\n") || !model.NamePattern.MatchString(p.Name) || p.Index < 2 || p.Index > 65534 || keys[p.PublicKey] || indices[p.Index] || names[p.Name] {
			return "", errors.New("AWG: некорректный или повторяющийся peer")
		}
		keys[p.PublicKey], indices[p.Index], names[p.Name] = true, true, true
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32, fd77:77::%x/128\n", p.PublicKey, c.address(p.Index), p.Index)
	}
	return b.String(), nil
}

func awgApplyPeers(c *awgConfig, peers []awgPeer) error {
	text, err := awgServerConf(c, peers)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(awgRuntimeDir, "awg-*.conf")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if err = f.Chmod(0600); err == nil {
		_, err = f.WriteString(text)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	_, err = awgExec("", "awg", "syncconf", awgInterface, path)
	return err
}

func (m *awgRuntime) ensure(c *awgConfig, peers []awgPeer) error {
	if _, err := awgServerConf(c, peers); err != nil {
		return err
	}
	owned, err := awgOwned(c)
	if err != nil {
		return err
	}
	if owned && m.config == nil {
		// A surviving device may contain optional settings that were cleared
		// while the agent was stopped. Recreate our device rather than leaving
		// omitted native fields with their previous values.
		previous := *c
		external, err := awgNetwork(c)
		if err != nil {
			return err
		}
		var state awgRuntimeState
		if b, e := os.ReadFile(awgRuntimeDir + "/awg-state.json"); e == nil && json.Unmarshal(b, &state) == nil && state.Alias == awgAlias(c) && validExternalInterface(state.External) {
			previous.Subnet = state.Subnet
			if previous.check() == nil {
				external = state.External
			} else {
				previous = *c
			}
		}
		m.config, m.external = &previous, external
		if err := m.down(); err != nil {
			return err
		}
		owned = false
	}
	if m.config != nil && *m.config != *c && owned {
		if err := m.down(); err != nil {
			return err
		}
		owned = false
	}
	if !owned {
		m.ready = false
	}
	if m.ready {
		exists, err := awgTableExists()
		if err != nil {
			return err
		}
		if !exists {
			m.ready = false
		}
	}
	if !m.ready {
		external, err := awgNetwork(c)
		if err != nil {
			return err
		}
		if _, err = awgExec("", "modprobe", "amneziawg"); err != nil {
			return err
		}
		if !owned {
			if _, err = awgExec("", "ip", "link", "add", "dev", awgInterface, "type", "amneziawg"); err != nil {
				return err
			}
			if _, err = awgExec("", "ip", "link", "set", "dev", awgInterface, "alias", awgAlias(c)); err != nil {
				awgExec("", "ip", "link", "del", "dev", awgInterface)
				return err
			}
			// A failed initial setconf must not leave a half-created device.
			if err = awgApplyPeers(c, nil); err != nil {
				awgExec("", "ip", "link", "del", "dev", awgInterface)
				return err
			}
		}
		m.config, m.external = c, external
		ok, err := awgTableExists()
		if err != nil {
			return err
		}
		if _, err = awgExec(awgFirewall(c, external, ok), "nft", "-f", "-"); err != nil {
			return err
		}
		if _, err = awgExec("", "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return err
		}
		if _, err = awgExec("", "ip", "-4", "address", "flush", "dev", awgInterface); err != nil {
			return err
		}
		if _, err = awgExec("", "ip", "address", "replace", c.address(1)+"/16", "dev", awgInterface); err != nil {
			return err
		}
		if _, err = awgExec("", "ip", "link", "set", "dev", awgInterface, "mtu", strconv.Itoa(c.MTU), "up"); err != nil {
			return err
		}
		for _, rule := range awgForwardRules(c, external) {
			if _, err = awgExec("", "iptables", append([]string{"-w", "5", "-C", "FORWARD"}, rule...)...); err != nil {
				if _, err = awgExec("", "iptables", append([]string{"-w", "5", "-I", "FORWARD", "1"}, rule...)...); err != nil {
					return err
				}
			}
		}
		m.epoch = randStr(16)
		state, _ := json.Marshal(awgRuntimeState{Alias: awgAlias(c), External: external, Subnet: c.Subnet})
		if err := writeAtomic(awgRuntimeDir+"/awg-state.json", state, 0600); err != nil {
			return err
		}
		m.ready = true
	}
	return awgApplyPeers(c, peers)
}

func (m *awgRuntime) down() error {
	if m.config == nil {
		return nil
	}
	owned, err := awgOwned(m.config)
	if err != nil {
		return err
	}
	if owned {
		if _, err = awgExec("", "ip", "link", "del", "dev", awgInterface); err != nil {
			return err
		}
	}
	m.ready = false
	var errs []error
	for _, rule := range awgForwardRules(m.config, m.external) {
		if _, err := awgExec("", "iptables", append([]string{"-w", "5", "-C", "FORWARD"}, rule...)...); err == nil {
			_, err = awgExec("", "iptables", append([]string{"-w", "5", "-D", "FORWARD"}, rule...)...)
			errs = append(errs, err)
		}
	}
	if exists, err := awgTableExists(); err != nil {
		errs = append(errs, err)
	} else if exists {
		_, err = awgExec("", "nft", "delete", "table", "inet", awgTable)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *awgRuntime) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /awg/reconfigure", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if readEnvNoFatal()["HYP_AWG_CONFIG"] == "" {
			if err := m.down(); err != nil {
				http.Error(w, err.Error(), 503)
				return
			}
			m.config = nil
		} else {
			c, err := configuredAWG()
			if err == nil {
				err = m.ensure(c, nil)
			}
			if err != nil {
				if m.config != nil {
					_ = m.revoke()
				}
				http.Error(w, err.Error(), 503)
				return
			}
		}
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("POST /awg/sync", func(w http.ResponseWriter, r *http.Request) {
		var peers []awgPeer
		if err := decodeJSONBody(r, &peers); err != nil {
			http.Error(w, "неверный список AWG", 400)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		c, err := configuredAWG()
		if err == nil {
			err = m.ensure(c, peers)
		}
		if err != nil {
			if m.config != nil {
				_ = m.revoke()
			}
			http.Error(w, err.Error(), 503)
			return
		}
		m.lastSync = time.Now()
		writeJSON(w, struct{}{})
	})
	mux.HandleFunc("GET /awg/state", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.config == nil || !m.ready {
			http.Error(w, "интерфейс AWG ещё не запущен", 503)
			return
		}
		owned, err := awgOwned(m.config)
		if err != nil || !owned {
			http.Error(w, "интерфейс AWG недоступен", 503)
			return
		}
		out, err := awgExec("", "awg", "show", awgInterface, "dump")
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		peers, err := parseAWGDump(string(out))
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		writeJSON(w, awgSnapshot{m.epoch, peers})
	})
}

func parseAWGDump(dump string) (map[string]awgCounter, error) {
	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(lines) == 0 || len(strings.Fields(lines[0])) < 4 {
		return nil, errors.New("AWG: некорректный dump")
	}
	peers := map[string]awgCounter{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 8 {
			return nil, errors.New("AWG: некорректная строка peer")
		}
		var c awgCounter
		for i, dst := range []*int64{&c.Handshake, &c.Rx, &c.Tx} {
			v, err := strconv.ParseInt(f[4+i], 10, 64)
			if err != nil || v < 0 {
				return nil, errors.New("AWG: некорректный счётчик")
			}
			*dst = v
		}
		peers[f[0]] = c
	}
	return peers, nil
}

// Access is leased by the panel. A stopped panel cannot leave an unmetered
// kernel tunnel running indefinitely. Agent restarts start with no peers.
func (m *awgRuntime) watch(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			_ = m.down()
			m.mu.Unlock()
			return
		case <-t.C:
			m.mu.Lock()
			if m.config == nil {
				if c, err := configuredAWG(); err == nil {
					if owned, e := awgOwned(c); e == nil && owned {
						_ = awgApplyPeers(c, nil)
					}
				}
			}
			if m.config != nil && time.Since(m.lastSync) > 35*time.Second {
				if err := m.revoke(); err != nil {
					log.Printf("AWG revoke: %v", err)
				}
			}
			m.mu.Unlock()
		}
	}
}
