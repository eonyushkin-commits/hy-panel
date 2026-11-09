// Package adminauth signs administrator sessions and bounds password attempts.
package adminauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sign binds sessions to both the persistent server key and current password.
// Restarting preserves sessions; changing the password invalidates them.
func Sign(key []byte, password string, expiry int64) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("hy-panel/admin-session/v2\x00"))
	digest := sha256.Sum256([]byte(password))
	m.Write(digest[:])
	exp := strconv.FormatInt(expiry, 10)
	m.Write([]byte(exp))
	return exp + "." + hex.EncodeToString(m.Sum(nil))
}

func Verify(key []byte, password, token string, now time.Time) bool {
	if len(token) > 96 {
		return false
	}
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(head, 10, 64)
	return err == nil && exp > now.Unix() && hmac.Equal([]byte(token), []byte(Sign(key, password, exp)))
}

// Limiter permits a small burst, then one attempt per second. It never sleeps
// while holding a lock or queues HTTP handlers behind a failed login.
type Limiter struct {
	mu      sync.Mutex
	next    time.Time
	tokens  float64
	started bool
}

func (l *Limiter) Allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.started {
		l.tokens = 5
		l.next = now
		l.started = true
	}
	l.tokens = min(5, l.tokens+max(0, now.Sub(l.next).Seconds()))
	l.next = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
