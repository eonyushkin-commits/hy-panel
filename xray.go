package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultXrayCfg = "/usr/local/etc/xray/config.json"
	defaultXraySvc = "xray"
	xrayBin        = "/usr/local/bin/xray"
	xrayAPIAddr    = "127.0.0.1:10085"
	xrayTag        = "vless-reality"
	visionFlow     = "xtls-rprx-vision"
)

// ---- reading the config ----

// xrayConfig is the subset of an Xray config the panel needs. Xray decodes
// it with encoding/json, so keys match case-insensitively here too.
type xrayConfig struct {
	API struct {
		Tag      string   `json:"tag"`
		Listen   string   `json:"listen"`
		Services []string `json:"services"`
	} `json:"api"`
	Stats  *struct{} `json:"stats"`
	Policy struct {
		Levels map[string]struct {
			StatsUserUplink   bool `json:"statsUserUplink"`
			StatsUserDownlink bool `json:"statsUserDownlink"`
			StatsUserOnline   bool `json:"statsUserOnline"`
		} `json:"levels"`
	} `json:"policy"`
	Inbounds []xrayInbound `json:"inbounds"`
}

type xrayInbound struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen"`
	Port     jsonPort `json:"port"`
	Protocol string   `json:"protocol"`
	Settings struct {
		Clients    []xrayUser `json:"clients"`
		Decryption string     `json:"decryption"`
		Flow       string     `json:"flow"` // default for clients without one
	} `json:"settings"`
	StreamSettings struct {
		Network   string    `json:"network"`
		Security  string    `json:"security"`
		XHTTP     xhttpOpts `json:"xhttpSettings"`
		SplitHTTP xhttpOpts `json:"splithttpSettings"` // XHTTP's former name
		Reality   struct {
			Target      json.RawMessage `json:"target"`
			Dest        json.RawMessage `json:"dest"` // target's former name
			ServerNames []string        `json:"serverNames"`
			PrivateKey  string          `json:"privateKey"`
			ShortIds    []string        `json:"shortIds"`
		} `json:"realitySettings"`
	} `json:"streamSettings"`
}

type xhttpOpts struct{ Path, Mode, Host string }

type xrayUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Flow  string `json:"flow"`
}

// jsonPort is a port written as a number or a string, as Xray accepts.
type jsonPort string

func (p *jsonPort) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil {
		var n json.Number
		if err := json.Unmarshal(b, &n); err != nil {
			return err
		}
		s = n.String()
	}
	*p = jsonPort(s)
	return nil
}

func (in *xrayInbound) isVless() bool {
	return strings.EqualFold(in.Protocol, "vless") && strings.EqualFold(in.StreamSettings.Security, "reality")
}

// vlessInbound returns the VLESS + Reality inbound the panel manages: the first one.
func (c *xrayConfig) vlessInbound() *xrayInbound {
	for i := range c.Inbounds {
		if c.Inbounds[i].isVless() {
			return &c.Inbounds[i]
		}
	}
	return nil
}

// Vless describes how clients reach Xray's VLESS + Reality inbound.
type Vless struct {
	Port      string
	SNI       string // the site Reality impersonates, as clients name it
	Target    string // where Xray forwards strangers: host:port
	PublicKey string // Reality "password", derived from the private key
	ShortID   string
	Network   string // xhttp or tcp
	Path      string // XHTTP
	Mode      string
	Host      string
	Flow      string // xtls-rprx-vision on tcp, none with XHTTP
}

// xraySetup is what the panel takes from the Xray config: the inbound it
// manages, the API to manage it with, and the link parameters.
type xraySetup struct {
	Tag  string
	API  string
	Link Vless
	Warn string // works, but something is off
}

func readXray(path string) (*xraySetup, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseXray(b)
}

func parseXray(b []byte) (*xraySetup, error) {
	var c xrayConfig
	if err := json.Unmarshal(stripComments(b), &c); err != nil {
		return nil, err
	}
	in := c.vlessInbound()
	if in == nil {
		return nil, errors.New("нет inbound VLESS + Reality — запусти hy-panel xray")
	}
	link, err := vlessLink(in)
	if err != nil {
		return nil, err
	}
	s := &xraySetup{Tag: in.Tag, Link: link}
	if s.Tag == "" {
		return nil, errors.New("у inbound VLESS нет tag — запусти hy-panel xray")
	}
	if s.API, err = c.apiAddr(); err != nil {
		return nil, err
	}
	var warns []string
	if h, _, _ := net.SplitHostPort(s.API); !isLoopbackHost(h) {
		warns = append(warns, "API Xray ("+s.API+") доступен снаружи — нужен 127.0.0.1")
	}
	if lv := c.Policy.Levels["0"]; c.Stats == nil || !lv.StatsUserUplink || !lv.StatsUserDownlink || !lv.StatsUserOnline {
		warns = append(warns, "в конфиге Xray выключена статистика пользователей: трафик и онлайн VLESS не видны — запусти hy-panel xray")
	}
	s.Warn = strings.Join(warns, "; ")
	return s, nil
}

// vlessLink checks that the panel can hand out links to the inbound and
// returns their parameters.
func vlessLink(in *xrayInbound) (Vless, error) {
	ss := &in.StreamSettings
	r := &ss.Reality
	v := Vless{Port: string(in.Port)}
	if n, err := strconv.Atoi(v.Port); err != nil || n < 1 || n > 65535 {
		return v, fmt.Errorf("port %q: нужен один порт", in.Port)
	}
	if d := in.Settings.Decryption; d != "none" {
		return v, fmt.Errorf("decryption %q: VLESS Encryption не поддерживается, нужен \"none\"", d)
	}
	switch strings.ToLower(ss.Network) {
	case "", "tcp", "raw":
		v.Network, v.Flow = "tcp", visionFlow
		if f := in.Settings.Flow; f != "" {
			v.Flow = f
		}
	case "xhttp", "splithttp":
		x := ss.XHTTP
		if x == (xhttpOpts{}) {
			x = ss.SplitHTTP
		}
		v.Network, v.Path, v.Mode, v.Host = "xhttp", x.Path, x.Mode, x.Host
		if v.Path == "" {
			v.Path = "/"
		}
		if v.Mode == "" {
			v.Mode = "auto"
		}
	default:
		return v, fmt.Errorf("network %q не поддерживается: нужен xhttp или tcp", ss.Network)
	}
	pub, err := realityPublicKey(r.PrivateKey)
	if err != nil {
		return v, err
	}
	v.PublicKey = pub
	if len(r.ServerNames) == 0 || r.ServerNames[0] == "" {
		return v, errors.New("realitySettings.serverNames пуст")
	}
	v.SNI = r.ServerNames[0]
	if len(r.ShortIds) > 0 {
		v.ShortID = r.ShortIds[0]
	}
	t := r.Target
	if len(t) == 0 {
		t = r.Dest
	}
	var target string
	if json.Unmarshal(t, &target) != nil {
		target = strings.TrimSpace(string(t)) // a bare port: a local site
	}
	if _, _, err := net.SplitHostPort(target); err != nil && target != "" {
		target = net.JoinHostPort("127.0.0.1", target)
	}
	v.Target = target
	for _, c := range in.Settings.Clients {
		f := c.Flow
		if f == "" {
			f = in.Settings.Flow
		}
		if f != v.Flow {
			return v, fmt.Errorf("клиент %q: flow %q, а панель выдаёт всем %q", c.Email, f, v.Flow)
		}
	}
	return v, nil
}

// apiAddr is where Xray's gRPC API listens: api.listen, or the older
// dokodemo-door inbound tagged like the api.
func (c *xrayConfig) apiAddr() (string, error) {
	for _, s := range []string{"HandlerService", "StatsService"} {
		if !slices.Contains(c.API.Services, s) {
			return "", fmt.Errorf("в api.services нет %s — запусти hy-panel xray", s)
		}
	}
	if c.API.Listen != "" {
		return c.API.Listen, nil
	}
	for _, in := range c.Inbounds {
		if c.API.Tag != "" && in.Tag == c.API.Tag {
			host := in.Listen
			if host == "" {
				host = "127.0.0.1"
			}
			return net.JoinHostPort(host, string(in.Port)), nil
		}
	}
	return "", errors.New("в конфиге Xray нет api — запусти hy-panel xray")
}

// stripComments removes the //, /* */ and # comments Xray allows in its JSON.
func stripComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c == '"':
			j := i + 1
			for ; j < len(b) && b[j] != '"'; j++ {
				if b[j] == '\\' {
					j++
				}
			}
			out = append(out, b[i:min(j+1, len(b))]...)
			i = j
		case c == '#' || c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := bytes.Index(b[i+2:], []byte("*/"))
			if end < 0 {
				return out
			}
			i += end + 3
			out = append(out, ' ')
		default:
			out = append(out, c)
		}
	}
	return out
}

// ---- keys and IDs ----

// newRealityKey returns an x25519 private key the way `xray x25519` prints it.
func newRealityKey() string {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes())
}

// realityPublicKey is what clients get as pbk / public-key (`xray x25519 -i`).
func realityPublicKey(priv string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(priv)
	if err == nil && len(b) != 32 {
		err = errors.New("not 32 bytes")
	}
	if err != nil {
		return "", fmt.Errorf("realitySettings.privateKey: %v", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// newUUID is a random (v4) UUID: a user's VLESS key.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmtUUID(b)
}

func fmtUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// xrayUUID is the UUID Xray makes of a client id: a UUID as is, or a short
// string (1-30 characters) hashed like Xray's uuid.ParseString does.
func xrayUUID(id string) (string, error) {
	if l := len(id); l < 32 || l > 36 {
		if l == 0 || l > 30 {
			return "", fmt.Errorf("id %q: не UUID", id)
		}
		h := sha1.Sum(append(make([]byte, 16), id...))
		u := h[:16]
		u[6] = u[6]&0x0f | 0x50
		u[8] = u[8]&0x3f | 0x80
		return fmtUUID(u), nil
	}
	b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(b) != 16 {
		return "", fmt.Errorf("id %q: не UUID", id)
	}
	return fmtUUID(b), nil
}

// ---- the site Reality impersonates ----

// checkTarget connects to the site the way a browser would. Reality needs
// TLS 1.3 with X25519 and HTTP/2 from it, and a certificate that is valid
// for the name, or active probes see something no real site shows.
func checkTarget(target, sni string) error {
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", target, &tls.Config{
		ServerName:       sni,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		NextProtos:       []string{"h2"},
	})
	if err != nil {
		return err
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		return errors.New("сайт не отвечает по HTTP/2")
	}
	return nil
}

// ---- installed Xray ----

var xrayVersionRe = regexp.MustCompile(`Xray (\d+)\.(\d+)\.(\d+)`)

func xrayVersion() hyVersion {
	out, _ := exec.Command(xrayBin, "version").Output()
	return parseVersion(xrayVersionRe, out)
}

// ---- Xray's gRPC API ----

// xrayAPI talks to Xray's gRPC API (HandlerService, StatsService) over
// cleartext HTTP/2. The few messages it needs are encoded by hand: no gRPC
// dependency for five calls.
type xrayAPI struct {
	base string
	hc   *http.Client
}

func newXrayAPI(addr string) *xrayAPI {
	tr := &http.Transport{Proxy: nil, Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	return &xrayAPI{base: "http://" + addr, hc: &http.Client{Timeout: 5 * time.Second, Transport: tr}}
}

// grpcError is a call answered with a non-OK grpc-status.
type grpcError struct {
	code int
	msg  string
}

func (e *grpcError) Error() string { return fmt.Sprintf("xray api: %s (code %d)", e.msg, e.code) }

const grpcNotFound = 5

// call makes one unary call; method is "Service/Method" under xray.app.
func (c *xrayAPI) call(method string, req []byte) ([]byte, error) {
	frame := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(req)))
	r, err := http.NewRequest("POST", c.base+"/xray.app."+method, bytes.NewReader(append(frame, req...)))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/grpc")
	r.Header.Set("TE", "trailers")
	resp, err := c.hc.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xray api %s: %s", method, resp.Status)
	}
	st, msg := resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message")
	if st == "" { // trailers-only response
		st, msg = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if st != "0" {
		code, err := strconv.Atoi(st)
		if err != nil {
			return nil, fmt.Errorf("xray api %s: no grpc-status", method)
		}
		m, _ := url.PathUnescape(msg)
		return nil, &grpcError{code, m}
	}
	if len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:])) != len(body)-5 {
		return nil, fmt.Errorf("xray api %s: bad response", method)
	}
	return body[5:], nil
}

func typedMessage(typ string, msg []byte) []byte {
	return pbBytes(pbString(nil, 1, typ), 2, msg)
}

func alterInbound(tag, op string, msg []byte) []byte {
	return pbBytes(pbString(nil, 1, tag), 2, typedMessage("xray.app.proxyman.command."+op, msg))
}

// AddUser adds a VLESS user (level 0) to the inbound.
func (c *xrayAPI) AddUser(tag, email, id, flow string) error {
	account := pbString(pbString(nil, 1, id), 2, flow)
	user := pbBytes(pbString(nil, 2, email), 3, typedMessage("xray.proxy.vless.Account", account))
	_, err := c.call("proxyman.command.HandlerService/AlterInbound", alterInbound(tag, "AddUserOperation", pbBytes(nil, 1, user)))
	return err
}

func (c *xrayAPI) RemoveUser(tag, email string) error {
	_, err := c.call("proxyman.command.HandlerService/AlterInbound", alterInbound(tag, "RemoveUserOperation", pbString(nil, 1, email)))
	return err
}

// Users returns the inbound's users: e-mail → UUID.
func (c *xrayAPI) Users(tag string) (map[string]string, error) {
	b, err := c.call("proxyman.command.HandlerService/GetInboundUsers", pbString(nil, 1, tag))
	if err != nil {
		return nil, err
	}
	users := map[string]string{}
	err = pbFields(b, func(f int, _ uint64, user []byte) error {
		// User{email = 2, account = 3: TypedMessage{value = 2: vless.Account{id = 1}}}
		if email := string(pbGet(user, 2)); f == 1 && email != "" {
			users[email] = string(pbGet(pbGet(pbGet(user, 3), 2), 1))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

// TrafficAndClear returns and zeroes the per-user counters (Tx = uplink,
// from the client, as with Hysteria).
func (c *xrayAPI) TrafficAndClear() (map[string]trafficEntry, error) {
	b, err := c.call("stats.command.StatsService/QueryStats", pbBool(pbString(nil, 1, "user>>>"), 2, true))
	if err != nil {
		return nil, err
	}
	m := map[string]trafficEntry{}
	err = pbFields(b, func(f int, _ uint64, stat []byte) error {
		if f != 1 { // QueryStatsResponse{repeated stat = 1}
			return nil
		}
		name, val, err := pbStat(stat)
		if err != nil {
			return err
		}
		// user>>>NAME>>>traffic>>>uplink
		p := strings.Split(name, ">>>")
		if len(p) != 4 || p[0] != "user" || p[2] != "traffic" || val == 0 {
			return nil
		}
		e := m[p[1]]
		switch p[3] {
		case "uplink":
			e.Tx += val
		case "downlink":
			e.Rx += val
		}
		m[p[1]] = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Online is how many client IPs of the user have connections open.
func (c *xrayAPI) Online(email string) (int, error) {
	name := "user>>>" + email + ">>>online"
	b, err := c.call("stats.command.StatsService/GetStatsOnline", pbString(nil, 1, name))
	var ge *grpcError
	if errors.As(err, &ge) && (ge.code == grpcNotFound || strings.HasSuffix(ge.msg, name+" not found.")) {
		return 0, nil // no connection since Xray started (older Xray says so without NotFound)
	}
	if err != nil {
		return 0, err
	}
	_, n, err := pbStat(pbGet(b, 1)) // GetStatsResponse{stat = 1}
	return int(n), err
}

// pbStat decodes Stat{name = 1, value = 2}.
func pbStat(b []byte) (name string, val int64, err error) {
	err = pbFields(b, func(f int, v uint64, d []byte) error {
		switch f {
		case 1:
			name = string(d)
		case 2:
			val = int64(v)
		}
		return nil
	})
	return name, val, err
}

// ---- protobuf: just enough for the messages above ----

func pbBytes(b []byte, field int, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(field)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func pbString(b []byte, field int, s string) []byte {
	if s == "" {
		return b
	}
	return pbBytes(b, field, []byte(s))
}

func pbBool(b []byte, field int, v bool) []byte {
	if !v {
		return b
	}
	return append(binary.AppendUvarint(b, uint64(field)<<3), 1)
}

var errProto = errors.New("xray api: malformed protobuf")

// pbGet returns the last length-delimited value of field (nil if absent or malformed).
func pbGet(b []byte, field int) (d []byte) {
	pbFields(b, func(f int, _ uint64, v []byte) error {
		if f == field {
			d = v
		}
		return nil
	})
	return d
}

// pbFields calls fn for each field of a message: v for varints, d for
// length-delimited fields; fixed-size fields are skipped.
func pbFields(b []byte, fn func(field int, v uint64, d []byte) error) error {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return errProto
		}
		b = b[n:]
		var v uint64
		var d []byte
		switch tag & 7 {
		case 0:
			if v, n = binary.Uvarint(b); n <= 0 {
				return errProto
			}
			b = b[n:]
		case 1, 5:
			size := map[uint64]int{1: 8, 5: 4}[tag&7]
			if len(b) < size {
				return errProto
			}
			b = b[size:]
			continue
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return errProto
			}
			d, b = b[n:n+int(l)], b[n+int(l):]
		default:
			return errProto
		}
		if err := fn(int(tag>>3), v, d); err != nil {
			return err
		}
	}
	return nil
}
