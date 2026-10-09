package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Subset of the Hysteria 2 server config the panel needs. Tags are lowercase
// because keys are lowercased before decoding (Hysteria/viper keys are
// case-insensitive).
type hyConfig struct {
	Listen string `yaml:"listen"`
	TLS    struct {
		Cert     string `yaml:"cert"`
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
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Lowercase all keys, like viper does. This also lowercases auth.userpass
	// usernames, exactly as Hysteria's userpass authenticator treats them.
	norm, err := yaml.Marshal(lowerKeys(raw))
	if err != nil {
		return nil, err
	}
	var c hyConfig
	if err := yaml.Unmarshal(norm, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
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
	switch strings.ToLower(c.Obfs.Type) {
	case "salamander":
		return "salamander", c.Obfs.Salamander.Password
	case "gecko":
		return "gecko", c.Obfs.Gecko.Password
	}
	return "", ""
}

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
		sum := sha256.Sum256(cert.Raw)
		ci.Pin = hex.EncodeToString(sum[:])
	}
	return ci, nil
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
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
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

func (c *statsClient) TrafficAndClear() (map[string]trafficEntry, error) {
	m := map[string]trafficEntry{}
	return m, c.do("GET", "/traffic?clear=1", nil, &m)
}

func (c *statsClient) Online() (map[string]int, error) {
	m := map[string]int{}
	return m, c.do("GET", "/online", nil, &m)
}

func (c *statsClient) Kick(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return c.do("POST", "/kick", ids, nil)
}
