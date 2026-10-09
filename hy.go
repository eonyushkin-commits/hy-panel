package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
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
		Cert string `yaml:"cert"`
	} `yaml:"tls"`
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
