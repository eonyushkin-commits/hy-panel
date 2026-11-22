package model

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"
)

const Hysteria = "hysteria2"
const VLESS = "vless"
const VLESSTCP = "vless-tcp"
const AmneziaWG = "awg"
const TrustTunnel = "trusttunnel"

type User struct {
	Name            string   `json:"name"`
	Password        string   `json:"password"`
	SubToken        string   `json:"subToken"`
	UUID            string   `json:"uuid"`
	AWGKey          string   `json:"awgKey,omitempty"`
	AWGIndex        int      `json:"awgIndex,omitempty"`
	ProtocolVersion int      `json:"protocolVersion,omitempty"`
	ProtoOff        []string `json:"protoOff,omitempty"`
	Enabled         bool     `json:"enabled"`
	QuotaBytes      int64    `json:"quotaBytes"`
	ResetMonthly    bool     `json:"resetMonthly"`
	LastReset       int      `json:"lastReset"`
	ExpiresAt       int64    `json:"expiresAt"`
	MaxDevices      int      `json:"maxDevices"`
	Up              int64    `json:"up"`
	Down            int64    `json:"down"`
	CreatedAt       int64    `json:"createdAt"`
	LastSeen        int64    `json:"lastSeen"`
	Note            string   `json:"note"`
}

type Traffic struct {
	Tx int64 `json:"tx"`
	Rx int64 `json:"rx"`
}

func (u *User) Uses(protocol string) bool {
	return KnownProtocol(protocol) && !slices.Contains(u.ProtoOff, protocol)
}
func KnownProtocol(protocol string) bool {
	return protocol == Hysteria || protocol == VLESS || protocol == VLESSTCP || protocol == AmneziaWG || protocol == TrustTunnel
}

func NewAWGKey() string {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

func AWGPublicKey(key string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != 32 || strings.ContainsAny(key, "\r\n") {
		return "", errors.New("AWG: invalid private key")
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Allowed reports whether u may connect over protocol at now: not blocked and
// the protocol not switched off. Who a server lets in follows this rule.
func (u *User) Allowed(protocol string, now time.Time) bool {
	return u.Blocked(now) == "" && u.Uses(protocol)
}
func Month(t time.Time) int { return t.Year()*100 + int(t.Month()) }
func (u User) Clone() User  { u.ProtoOff = slices.Clone(u.ProtoOff); return u }
func (u *User) Blocked(now time.Time) string {
	if !u.Enabled {
		return "disabled"
	}
	if u.ExpiresAt > 0 && now.Unix() >= u.ExpiresAt {
		return "expired"
	}
	if u.QuotaBytes > 0 && (u.Up >= u.QuotaBytes || u.Down >= u.QuotaBytes-u.Up) {
		return "quota"
	}
	return ""
}

var NamePattern = regexp.MustCompile(`^[a-z0-9_.-]{1,32}$`)

func Validate(u User) error {
	if u.AWGKey != "" {
		if _, err := AWGPublicKey(u.AWGKey); err != nil {
			return err
		}
	}
	if u.AWGIndex < 0 || u.AWGIndex == 1 || u.AWGIndex > 65534 {
		return errors.New("AWG: address index outside 2..65534")
	}
	if !NamePattern.MatchString(u.Name) {
		return errors.New("name: 1-32 chars of a-z 0-9 _ . -")
	}
	if len(u.Password) < 8 || len(u.Password) > 128 || strings.ContainsAny(u.Password, ": \t\r\n") {
		return errors.New("password: 8-128 chars, no ':' or spaces")
	}
	if u.QuotaBytes < 0 || u.ExpiresAt < 0 || u.MaxDevices < 0 || u.Up < 0 || u.Down < 0 {
		return errors.New("negative quota, traffic, expiry or session limit")
	}
	for _, p := range u.ProtoOff {
		if !KnownProtocol(p) {
			return errors.New("unknown protocol: " + p)
		}
	}
	return nil
}
func EqualSecret(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

const Alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func Token(n int) string {
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(Alphabet))))
		if err != nil {
			panic(err)
		}
		b[i] = Alphabet[x.Int64()]
	}
	return string(b)
}
func UUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
