package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type User struct {
	Name         string `json:"name"`
	Password     string `json:"password"`
	SubToken     string `json:"subToken"`
	Enabled      bool   `json:"enabled"`
	QuotaBytes   int64  `json:"quotaBytes"`   // 0 = unlimited, counts up+down
	ResetMonthly bool   `json:"resetMonthly"` // zero traffic on the 1st of each month (server time)
	LastReset    int    `json:"lastReset"`    // yyyymm of the last monthly reset
	ExpiresAt    int64  `json:"expiresAt"`    // unix seconds, 0 = never
	MaxDevices   int    `json:"maxDevices"`   // 0 = unlimited
	Up           int64  `json:"up"`           // client → server
	Down         int64  `json:"down"`         // server → client
	CreatedAt    int64  `json:"createdAt"`
	LastSeen     int64  `json:"lastSeen"`
	Note         string `json:"note"`
}

// Blocked returns why the user may not connect right now, "" if allowed.
func (u *User) Blocked(now time.Time) string {
	switch {
	case !u.Enabled:
		return "disabled"
	case u.ExpiresAt > 0 && now.Unix() >= u.ExpiresAt:
		return "expired"
	case u.QuotaBytes > 0 && u.Up+u.Down >= u.QuotaBytes:
		return "quota"
	}
	return ""
}

func yyyymm(t time.Time) int { return t.Year()*100 + int(t.Month()) }

// Store keeps users in memory and in one JSON file. Admin changes are written
// at once; traffic counters only by Flush (every minute and on shutdown), so
// the per-connection /auth path never waits for the disk.
type Store struct {
	saveMu sync.Mutex // orders file writes; taken before mu
	mu     sync.RWMutex
	path   string
	users  map[string]*User
	dirty  bool // counters changed since the last write (under mu)
}

// Names are lowercase: Hysteria's own userpass auth is case-insensitive, and the
// name is the ID in Hysteria's traffic stats.
var nameRe = regexp.MustCompile(`^[a-z0-9_.-]{1,32}$`)

var errNotFound = errors.New("not found")

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, users: map[string]*User{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, os.MkdirAll(filepath.Dir(path), 0o700)
	}
	if err != nil {
		return nil, err
	}
	var list []*User
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, u := range list {
		s.users[u.Name] = u
	}
	return s, nil
}

func (s *Store) listLocked() []User {
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// writeLocked writes the users (mu held at least for reading, saveMu held).
func (s *Store) writeLocked() error {
	b, err := json.MarshalIndent(s.listLocked(), "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path, b, 0o600)
}

// change applies fn under the write lock and saves; on any error nothing changes.
func (s *Store) change(fn func() (undo func(), err error)) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	undo, err := fn()
	if err != nil {
		return err
	}
	if err := s.writeLocked(); err != nil {
		undo()
		return err
	}
	s.dirty = false
	return nil
}

// Flush writes changed traffic counters. The file is written outside the
// write lock, so authorization goes on meanwhile.
func (s *Store) Flush() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	s.dirty = false
	b, err := json.MarshalIndent(s.listLocked(), "", "  ")
	s.mu.Unlock()
	if err == nil {
		err = writeAtomic(s.path, b, 0o600)
	}
	if err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
	}
	return err
}

func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listLocked()
}

func (s *Store) Get(name string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	if !ok {
		return User{}, false
	}
	return *u, true
}

func (s *Store) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users) == 0
}

// Resolve maps a Hysteria auth string to a user: "name:password" (as with
// Hysteria's userpass, name case-insensitive) or a bare password (clients of a
// former `auth.type: password` setup, and apps that send only the password).
func (s *Store) Resolve(auth string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name, pass, ok := strings.Cut(auth, ":"); ok {
		if u, ok := s.users[strings.ToLower(name)]; ok && ctEq(u.Password, pass) {
			return *u, true
		}
	}
	for _, u := range s.users {
		if ctEq(u.Password, auth) {
			return *u, true
		}
	}
	return User{}, false
}

// checkPassword must be called with mu held.
func (s *Store) checkPassword(pw, self string) error {
	if len(pw) < 8 || len(pw) > 128 || strings.ContainsAny(pw, ": \t\r\n") {
		return errors.New("password: 8-128 chars, no ':' or spaces")
	}
	for _, o := range s.users {
		if o.Name != self && o.Password == pw {
			return errors.New("password already used by " + o.Name)
		}
	}
	return nil
}

// Create adds a user. Imported passwords (legacy=true) skip the format check,
// since they must stay exactly as old clients send them.
func (s *Store) Create(u User, legacy bool) (User, error) {
	u.Name = strings.ToLower(u.Name)
	if !nameRe.MatchString(u.Name) {
		return User{}, errors.New("name: 1-32 chars of a-z 0-9 _ . -")
	}
	if u.Password == "" {
		u.Password = randStr(20)
	}
	now := time.Now()
	u.SubToken = randStr(24)
	u.CreatedAt = now.Unix()
	u.LastReset = yyyymm(now)
	err := s.change(func() (func(), error) {
		if _, ok := s.users[u.Name]; ok {
			return nil, errors.New("user exists")
		}
		if !legacy {
			if err := s.checkPassword(u.Password, u.Name); err != nil {
				return nil, err
			}
		}
		s.users[u.Name] = &u
		return func() { delete(s.users, u.Name) }, nil
	})
	return u, err
}

// Update applies fn atomically; on error (from fn or disk) nothing changes.
func (s *Store) Update(name string, fn func(*User) error) (User, error) {
	var out User
	err := s.change(func() (func(), error) {
		u, ok := s.users[name]
		if !ok {
			return nil, errNotFound
		}
		old := *u
		undo := func() { *u = old }
		if err := fn(u); err != nil {
			undo()
			return nil, err
		}
		if u.Password != old.Password {
			if err := s.checkPassword(u.Password, name); err != nil {
				undo()
				return nil, err
			}
		}
		out = *u
		return undo, nil
	})
	return out, err
}

func (s *Store) Delete(name string) error {
	return s.change(func() (func(), error) {
		u, ok := s.users[name]
		if !ok {
			return nil, errNotFound
		}
		delete(s.users, name)
		return func() { s.users[name] = u }, nil
	})
}

func (s *Store) BySubToken(tok string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if ctEq(u.SubToken, tok) {
			return *u, true
		}
	}
	return User{}, false
}

// Tick applies traffic deltas from Hysteria's /traffic?clear=1, marks online
// users as seen and performs monthly resets, in memory; Flush writes them.
func (s *Store) Tick(now time.Time, traffic map[string]trafficEntry, online map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, e := range traffic {
		if u, ok := s.users[name]; ok && (e.Tx > 0 || e.Rx > 0) {
			u.Up += e.Tx // Hysteria counts tx = from client, rx = to client
			u.Down += e.Rx
			u.LastSeen = now.Unix()
			s.dirty = true
		}
	}
	for name := range online {
		if u, ok := s.users[name]; ok {
			u.LastSeen = now.Unix()
			s.dirty = true
		}
	}
	month := yyyymm(now)
	for _, u := range s.users {
		if u.ResetMonthly && u.LastReset != month {
			u.Up, u.Down, u.LastReset = 0, 0, month
			s.dirty = true
		}
	}
}

const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randStr(n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[x.Int64()]
	}
	return string(b)
}

// writeAtomic replaces path with b: temp file, fsync, rename, fsync dir.
func writeAtomic(path string, b []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if err := writeSync(f, b); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// writeSync writes b, fsyncs and closes f, returning the first error.
func writeSync(f *os.File, b []byte) error {
	_, err := f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
