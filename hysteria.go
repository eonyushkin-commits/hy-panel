package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---- reading the config ----

// Subset of the Hysteria 2 server config the panel needs. Tags are lowercase
// because keys are lowercased before decoding (Hysteria/viper keys are
// case-insensitive).
type hyConfig struct {
	Listen string `yaml:"listen"`
	TLS    struct {
		Cert     string `yaml:"cert"`
		Key      string `yaml:"key"`
		ClientCA string `yaml:"clientca"`
	} `yaml:"tls"`
	ECH struct {
		KeyPath string `yaml:"keypath"`
	} `yaml:"ech"`
	Mimic struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"mimic"`
	ACME struct {
		Domains []string `yaml:"domains"`
		Email   string   `yaml:"email"`
	} `yaml:"acme"`
	Obfs struct {
		Type       string `yaml:"type"`
		Salamander struct {
			Password string `yaml:"password"`
		} `yaml:"salamander"`
		Gecko struct {
			Password string `yaml:"password"`
		} `yaml:"gecko"`
	} `yaml:"obfs"`
	Auth struct {
		Type     string            `yaml:"type"`
		Password string            `yaml:"password"`
		UserPass map[string]string `yaml:"userpass"`
		HTTP     struct {
			URL string `yaml:"url"`
		} `yaml:"http"`
	} `yaml:"auth"`
	TrafficStats struct {
		Listen string `yaml:"listen"`
		Secret string `yaml:"secret"`
	} `yaml:"trafficstats"`
}

func loadHyConfig(path string) (*hyConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseHyConfig(b)
}

func parseHyConfig(b []byte) (*hyConfig, error) {
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	// Lowercase all keys, like viper does. This also lowercases auth.userpass
	// usernames, exactly as Hysteria's userpass authenticator treats them.
	norm, err := yaml.Marshal(lowerKeys(raw))
	if err != nil {
		return nil, err
	}
	var c hyConfig
	if err := yaml.Unmarshal(norm, &c); err != nil {
		return nil, err
	}
	c.Auth.Type = strings.ToLower(c.Auth.Type)
	c.Obfs.Type = strings.ToLower(c.Obfs.Type)
	return &c, nil
}

func lowerKeys(v any) any {
	switch m := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[strings.ToLower(k)] = lowerKeys(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[strings.ToLower(fmt.Sprint(k))] = lowerKeys(val)
		}
		return out
	case []any:
		for i := range m {
			m[i] = lowerKeys(m[i])
		}
	}
	return v
}

func (c *hyConfig) port() string {
	_, p, err := net.SplitHostPort(c.Listen)
	if err != nil || p == "" {
		return "443"
	}
	return p
}

func (c *hyConfig) obfs() (typ, pass string) {
	switch c.Obfs.Type {
	case "salamander":
		return "salamander", c.Obfs.Salamander.Password
	case "gecko":
		return "gecko", c.Obfs.Gecko.Password
	}
	return "", ""
}

// ---- what kind of config this is ----

type cfgKind int

const (
	cfgNone    cfgKind = iota // missing, empty or the get.hy2.sh template: set up from scratch
	cfgPanel                  // auth already points at this panel
	cfgOwnAuth                // a working config with its own auth: connect the panel to it
	cfgOther                  // auth http to some other backend (another panel)
	cfgRealm                  // listen: realm:// — not supported
	cfgBroken                 // not parseable
)

// classify decides by the file's content only — never by whether Hysteria
// runs — so re-running install cannot rewrite a working config.
func classify(b []byte, readErr error) cfgKind {
	if readErr != nil {
		return cfgNone
	}
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return cfgBroken
	}
	if raw == nil { // empty, comments only, or null
		return cfgNone
	}
	c, err := parseHyConfig(b)
	if err != nil {
		return cfgBroken
	}
	switch {
	case slices.Contains(c.ACME.Domains, "your.domain.net"): // get.hy2.sh writes this placeholder
		return cfgNone
	case strings.HasPrefix(c.Listen, "realm"):
		return cfgRealm
	case c.Auth.Type == "http" && c.Auth.HTTP.URL == authURL:
		return cfgPanel
	case c.Auth.Type == "http":
		return cfgOther
	}
	return cfgOwnAuth
}

// ---- editing the config as a YAML tree (comments and other keys stay) ----

// yamlDoc is a config file as a node tree; root is its top-level mapping.
type yamlDoc struct {
	doc  yaml.Node
	root *yaml.Node
}

func parseDoc(b []byte) (*yamlDoc, error) {
	d := &yamlDoc{}
	if err := yaml.Unmarshal(b, &d.doc); err != nil {
		return nil, err
	}
	if len(d.doc.Content) == 0 || d.doc.Content[0].Tag == "!!null" {
		// Empty or comments only: start a new mapping.
		d.root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		d.doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{d.root}}
		return d, nil
	}
	if d.doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config is not a YAML mapping")
	}
	d.root = d.doc.Content[0]
	return d, nil
}

func (d *yamlDoc) bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&d.doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// get finds a key case-insensitively, as Hysteria/viper does.
func (d *yamlDoc) get(key string) *yaml.Node { return mapGet(d.root, key) }

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, key) {
			return m.Content[i+1]
		}
	}
	return nil
}

// set replaces the value of key (keeping its position) or appends it; v is a
// Go value or a *yaml.Node.
func (d *yamlDoc) set(key string, v any) error { return mapSet(d.root, key, v) }

func mapSet(m *yaml.Node, key string, v any) error {
	val, ok := v.(*yaml.Node)
	if !ok {
		val = &yaml.Node{}
		if err := val.Encode(v); err != nil {
			return err
		}
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, key) {
			m.Content[i+1] = val
			return nil
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
	return nil
}

func (d *yamlDoc) del(key string) {
	m := d.root
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, key) {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// connectPanel points auth at the panel and adds trafficStats if missing.
// Returns false if nothing had to change.
func (d *yamlDoc) connectPanel() (bool, error) {
	changed := false
	if a := d.get("auth"); a == nil || !strings.EqualFold(scalar(mapGet(a, "type")), "http") || scalar(mapGet(mapGet(a, "http"), "url")) != authURL {
		if err := d.set("auth", map[string]any{"type": "http", "http": map[string]any{"url": authURL}}); err != nil {
			return false, err
		}
		changed = true
	}
	if ts := d.get("trafficStats"); ts == nil || mapGet(ts, "listen") == nil {
		if err := d.set("trafficStats", map[string]any{"listen": statsAddr, "secret": randStr(32)}); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func scalar(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	return n.Value
}

// writeKeepingOwner rewrites a file in place so owner and mode stay (Hysteria
// may run as its own user); a new file is created root:hysteria 0640.
func writeKeepingOwner(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o640)
		if err == nil {
			chownHysteria(path)
		}
	}
	if err != nil {
		return err
	}
	return writeSync(f, b)
}

// chownHysteria makes a file root-owned and readable by Hysteria's group.
func chownHysteria(path string) {
	if _, gid := hysteriaIDs(); gid != 0 {
		os.Chown(path, 0, gid)
	}
}

// ---- certificates ----

type certInfo struct {
	SelfSigned bool
	Pin        string // hex SHA-256 of the leaf DER, as Hysteria's pinSHA256 expects
	DNSName    string // first DNS SAN
}

// readCert inspects tls.cert. Only a genuinely self-signed leaf gets pinned:
// a CA-issued cert (e.g. Let's Encrypt) rotates, and a pin would break clients.
func readCert(path string) (certInfo, error) {
	var ci certInfo
	if path == "" {
		return ci, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ci, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ci, fmt.Errorf("%s: no PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ci, err
	}
	if len(cert.DNSNames) > 0 {
		ci.DNSName = cert.DNSNames[0]
	}
	ci.SelfSigned = bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	if ci.SelfSigned {
		ci.Pin = certFP(cert.Raw)
	}
	return ci, nil
}

func keyPairOK(crt, key string) bool {
	_, err := tls.LoadX509KeyPair(crt, key)
	return err == nil
}

// certFP is the hex sha256 of a DER certificate: the pin clients check.
func certFP(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// panelCert loads the panel's own self-signed certificate from dir, creating it
// on first use. It is independent of Hysteria's cert. Returns the cert and its
// SHA-256 fingerprint.
func panelCert(dir, host string) (tls.Certificate, string, error) {
	crt, key := filepath.Join(dir, "panel.crt"), filepath.Join(dir, "panel.key")
	if _, err := os.Stat(crt); errors.Is(err, os.ErrNotExist) {
		if err := newSelfSigned(crt, key, host); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	c, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return c, "", err
	}
	return c, certFP(c.Certificate[0]), nil
}

func newSelfSigned(crtPath, keyPath, host string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hy-panel"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if host != "" {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// readECH returns the base64 ECHConfigList clients need (URI `ech=`, mihomo
// ech-opts.config) from the server's ech.keyPath file written by `hysteria ech`:
// the "ECH CONFIGS" block, or else the configs inside "ECH KEYS"
// (u16-prefixed private key + u16-prefixed config, repeated), as Hysteria does.
func readECH(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var keys []byte
	for rest := b; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		switch blk.Type {
		case "ECH CONFIGS":
			return base64.StdEncoding.EncodeToString(blk.Bytes), nil
		case "ECH KEYS":
			keys = blk.Bytes
		}
	}
	if keys == nil {
		return "", fmt.Errorf("%s: no ECH KEYS/ECH CONFIGS PEM block", path)
	}
	u16 := func(p []byte) ([]byte, []byte, bool) {
		if len(p) < 2 || len(p) < 2+int(binary.BigEndian.Uint16(p)) {
			return nil, nil, false
		}
		n := 2 + int(binary.BigEndian.Uint16(p))
		return p[2:n], p[n:], true
	}
	var configs []byte
	for len(keys) > 0 {
		_, rest, ok := u16(keys)
		if !ok {
			return "", fmt.Errorf("%s: malformed ECH KEYS", path)
		}
		cfg, rest, ok := u16(rest)
		if !ok {
			return "", fmt.Errorf("%s: malformed ECH KEYS", path)
		}
		configs, keys = append(configs, cfg...), rest
	}
	list := binary.BigEndian.AppendUint16(nil, uint16(len(configs)))
	return base64.StdEncoding.EncodeToString(append(list, configs...)), nil
}

// ---- trafficStats API client ----

type trafficEntry struct {
	Tx int64 `json:"tx"`
	Rx int64 `json:"rx"`
}

type statsClient struct {
	base, secret string
	hc           *http.Client
}

func newStatsClient(listen, secret string) *statsClient {
	host, port, _ := net.SplitHostPort(listen)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return &statsClient{
		base:   "http://" + net.JoinHostPort(host, port),
		secret: secret,
		hc:     &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
}

func (c *statsClient) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	if c.secret != "" {
		req.Header.Set("Authorization", c.secret)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trafficStats %s: %s", path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// TrafficAndClear and Online return nil on error, never a partial map.
func (c *statsClient) TrafficAndClear() (map[string]trafficEntry, error) {
	return get[trafficEntry](c, "/traffic?clear=1")
}

func (c *statsClient) Online() (map[string]int, error) {
	return get[int](c, "/online")
}

func get[V any](c *statsClient, path string) (map[string]V, error) {
	m := map[string]V{}
	if err := c.do("GET", path, nil, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *statsClient) Kick(ids []string) error {
	return c.do("POST", "/kick", ids, nil)
}

// ---- installed Hysteria ----

const hysteriaBin = "/usr/local/bin/hysteria"

// hyVersion is major.minor.patch of the installed Hysteria; zero if unknown.
type hyVersion [3]int

var versionRe = regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`)

func hysteriaVersion() hyVersion {
	out, _ := exec.Command(hysteriaBin, "version").Output()
	var v hyVersion
	if m := versionRe.FindStringSubmatch(string(out)); m != nil {
		for i := range v {
			v[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return v
}

func (v hyVersion) atLeast(min hyVersion) bool { return slices.Compare(v[:], min[:]) >= 0 }

func (v hyVersion) String() string {
	if v == (hyVersion{}) {
		return "неизвестна"
	}
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}
