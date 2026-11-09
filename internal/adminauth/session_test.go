package adminauth

import (
	"testing"
	"time"
)

func TestPasswordChangeInvalidatesSession(t *testing.T) {
	key := []byte("persistent-key")
	now := time.Now()
	token := Sign(key, "old", now.Add(time.Hour).Unix())
	if !Verify(key, "old", token, now) {
		t.Fatal("valid session rejected")
	}
	for _, test := range []struct {
		password, token string
		now             time.Time
	}{{"new", token, now}, {"old", token, now.Add(2 * time.Hour)}, {"old", token + "0", now}, {"old", "bad", now}} {
		if Verify(key, test.password, test.token, test.now) {
			t.Fatal("invalid session accepted")
		}
	}
}
func TestLimiterRecoversWithoutQueue(t *testing.T) {
	l := new(Limiter)
	now := time.Now()
	for range 5 {
		if !l.Allow(now) {
			t.Fatal("initial burst rejected")
		}
	}
	if l.Allow(now) {
		t.Fatal("unbounded guesses")
	}
	if !l.Allow(now.Add(time.Second)) {
		t.Fatal("limiter did not refill")
	}
	if l.Allow(now.Add(time.Second)) {
		t.Fatal("extra attempt allowed")
	}
}
