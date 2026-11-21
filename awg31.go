package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// AWG 3.1 device options. JSON is also the checked agent/CLI request shape;
// the same shape feeds native .conf and Mihomo's v3 implementation.
type awgObfuscation struct {
	Jc                     int       `json:"jc"`
	Jmin                   int       `json:"jmin"`
	Jmax                   int       `json:"jmax"`
	S1                     int       `json:"s1"`
	S2                     int       `json:"s2"`
	S3                     int       `json:"s3"`
	S4                     int       `json:"s4"`
	H                      [4]string `json:"h"`
	I1                     string    `json:"i1"`
	I2                     string    `json:"i2"`
	I3                     string    `json:"i3"`
	I4                     string    `json:"i4"`
	I5                     string    `json:"i5"`
	HeaderProtectionKey    string    `json:"headerProtectionKey"`
	ContentPaddingAddition string    `json:"contentPaddingAddition"`
	RekeyAfterTime         string    `json:"rekeyAfterTime"`
	RekeyTimeout           string    `json:"rekeyTimeout"`
	RejectAfterTime        string    `json:"rejectAfterTime"`
	KeepaliveTimeout       string    `json:"keepaliveTimeout"`
	MaxHandshakeAttempts   string    `json:"maxHandshakeAttempts"`
	RandomTrailers         bool      `json:"randomTrailers"`
	DisableCookies         bool      `json:"disableCookies"`
	PersistentKeepalive    string    `json:"persistentKeepalive"` // client-side peer option
}

func awgBool(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
func parseAWGObfuscation(text string, out *awgObfuscation) error {
	if len(text) > 16384 {
		return errors.New("AWG: параметры слишком длинные")
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("AWG: нужен один объект настроек")
	}
	return nil
}

func awgRange(s string, min, max uint64) (uint64, uint64, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, errors.New("нужно число или диапазон a-b")
	}
	a, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || a < min || a > max {
		return 0, 0, errors.New("значение вне диапазона")
	}
	b := a
	if len(parts) == 2 {
		b, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil || b < a || b > max {
			return 0, 0, errors.New("некорректный диапазон")
		}
	}
	return a, b, nil
}

func (o awgObfuscation) check(mtu int) error {
	if o.PersistentKeepalive != "" {
		if _, _, err := awgRange(o.PersistentKeepalive, 0, 65535); err != nil {
			return fmt.Errorf("AWG: PersistentKeepalive: %w", err)
		}
	}
	if o.Jc < 0 || o.Jc > 128 || o.Jmin < 0 || o.Jmax < o.Jmin || o.Jmax > 1280 {
		return errors.New("AWG: Jc 0–128, 0 ≤ Jmin ≤ Jmax ≤ 1280")
	}
	if o.S1 < 0 || o.S1 > 1552 || o.S2 < 0 || o.S2 > 1608 || o.S3 < 0 || o.S3 > 1636 || o.S4 < 0 || o.S4 > 32 || o.S1+56 == o.S2 {
		return errors.New("AWG: неверные S1–S4 или S1 + 56 = S2")
	}
	if o.RandomTrailers && (o.S1 != o.S2 || o.S1 != o.S3 || o.S1 != o.S4) {
		return errors.New("AWG 3.1: RandomTrailers требует одинаковые S1–S4 для корректного распознавания пакетов")
	}
	if o.HeaderProtectionKey != "" {
		key, err := base64.StdEncoding.DecodeString(o.HeaderProtectionKey)
		if err != nil || len(key) != 32 || strings.ContainsAny(o.HeaderProtectionKey, "\r\n") {
			return errors.New("AWG: HeaderProtectionKey — base64 ключ из 32 байт")
		}
		if o.S1 < 12 || o.S2 < 12 || o.S3 < 12 || o.S4 < 12 {
			return errors.New("AWG: защита заголовков требует S1–S4 ≥ 12")
		}
	}
	var ranges [4][2]uint64
	for i, h := range o.H {
		lo, hi, err := awgRange(h, 5, 4294967295)
		if err != nil {
			return fmt.Errorf("AWG: H%d: %w", i+1, err)
		}
		for j := 0; j < i; j++ {
			if lo <= ranges[j][1] && hi >= ranges[j][0] {
				return errors.New("AWG: диапазоны H1–H4 пересекаются")
			}
		}
		ranges[i] = [2]uint64{lo, hi}
	}
	paddingHi := uint64(0)
	if o.ContentPaddingAddition != "" {
		_, hi, err := awgRange(o.ContentPaddingAddition, 0, 64)
		if err != nil {
			return fmt.Errorf("AWG: ContentPaddingAddition: %w", err)
		}
		paddingHi = hi
	}
	if uint64(mtu+o.S4+80)+paddingHi > 1500 {
		return errors.New("AWG: MTU + S4 + максимальный ContentPaddingAddition + 80 превышает 1500; уменьши MTU или padding")
	}
	for i, s := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
		if err := awgSignature(s); err != nil {
			return fmt.Errorf("AWG: I%d: %w", i+1, err)
		}
	}
	for _, p := range [][2]string{{"RekeyAfterTime", o.RekeyAfterTime}, {"RekeyTimeout", o.RekeyTimeout}, {"RejectAfterTime", o.RejectAfterTime}, {"KeepaliveTimeout", o.KeepaliveTimeout}, {"MaxHandshakeAttempts", o.MaxHandshakeAttempts}} {
		if p[1] != "" {
			if _, _, err := awgRange(p[1], 1, 4294967295); err != nil {
				return fmt.Errorf("AWG: %s: %w", p[0], err)
			}
		}
	}
	rekeyHi, rejectLo := uint64(120), uint64(180)
	if o.RekeyAfterTime != "" {
		_, rekeyHi, _ = awgRange(o.RekeyAfterTime, 1, 4294967295)
	}
	if o.RejectAfterTime != "" {
		rejectLo, _, _ = awgRange(o.RejectAfterTime, 1, 4294967295)
	}
	if rekeyHi >= rejectLo {
		return errors.New("AWG: максимальный RekeyAfterTime должен быть меньше минимального RejectAfterTime")
	}
	return nil
}

// Validate the official chain grammar and bound each generated signature
// datagram. The native parser remains the final configuration validator.
func awgSignature(spec string) error {
	if strings.ContainsAny(spec, "\r\n\x00") || len(spec) > 4096 {
		return errors.New("недопустимый символ или слишком длинная сигнатура")
	}
	total := 0
	for rest := strings.TrimSpace(spec); rest != ""; {
		if !strings.HasPrefix(rest, "<") {
			return errors.New("нужна цепочка <тег значение>")
		}
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return errors.New("нет закрывающего >")
		}
		fields := strings.Fields(rest[1:end])
		if len(fields) < 1 || len(fields) > 2 {
			return errors.New("неверная сигнатура")
		}
		arg := ""
		if len(fields) == 2 {
			arg = fields[1]
		}
		switch fields[0] {
		case "r", "rc", "rd", "dz":
			n, err := strconv.Atoi(arg)
			if err != nil || n < 0 || n > 1280 {
				return errors.New("длина тега должна быть 0–1280")
			}
			total += n
		case "b":
			b, err := hex.DecodeString(strings.TrimPrefix(arg, "0x"))
			if err != nil || len(b) == 0 {
				return errors.New("тег b требует hex-байты")
			}
			total += len(b)
		case "t":
			if arg != "" {
				return errors.New("тег t не требует значения")
			}
			total += 4
		case "d", "ds":
			if arg != "" {
				return errors.New("тег данных не требует значения")
			}
		default:
			return errors.New("неизвестный тег сигнатуры")
		}
		if total > 1280 {
			return errors.New("пакет сигнатуры больше 1280 байт")
		}
		rest = strings.TrimSpace(rest[end+1:])
	}
	return nil
}

func (o awgObfuscation) strings() [][2]string {
	return [][2]string{
		{"I1", o.I1}, {"I2", o.I2}, {"I3", o.I3}, {"I4", o.I4}, {"I5", o.I5}, {"HeaderProtectionKey", o.HeaderProtectionKey}, {"ContentPaddingAddition", o.ContentPaddingAddition}, {"RekeyAfterTime", o.RekeyAfterTime}, {"RekeyTimeout", o.RekeyTimeout}, {"RejectAfterTime", o.RejectAfterTime}, {"KeepaliveTimeout", o.KeepaliveTimeout}, {"MaxHandshakeAttempts", o.MaxHandshakeAttempts},
	}
}

func (o awgObfuscation) mihomo() map[string]any {
	m := map[string]any{"version": 3, "jc": o.Jc, "jmin": o.Jmin, "jmax": o.Jmax, "s1": o.S1, "s2": o.S2, "s3": o.S3, "s4": o.S4, "h1": o.H[0], "h2": o.H[1], "h3": o.H[2], "h4": o.H[3], "random-trailers": o.RandomTrailers, "disable-cookies": o.DisableCookies}
	keys := []string{"i1", "i2", "i3", "i4", "i5", "header-protection-key", "content-padding-addition", "rekey-after-time", "rekey-timeout", "reject-after-time", "keepalive-timeout", "max-handshake-attempts"}
	for i, p := range o.strings() {
		if p[1] != "" {
			m[keys[i]] = p[1]
		}
	}
	return m
}

func (c *awgConfig) publicSettings() map[string]any {
	b, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	delete(m, "privateKey")
	return m
}

func (o awgObfuscation) keepalive() string {
	if o.PersistentKeepalive != "" {
		return o.PersistentKeepalive
	}
	return "25"
}
func (o awgObfuscation) mihomoKeepalive() uint64 {
	lo, _, _ := awgRange(o.keepalive(), 0, 65535)
	return lo
}
