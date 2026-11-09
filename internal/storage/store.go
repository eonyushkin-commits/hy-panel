// Package storage owns validation, migration and publication of user state.
package storage

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"github.com/eonyushkin-commits/hy-panel/internal/model"
)

var ErrNotFound = errors.New("not found")

type WriteError struct{ Err error }

func (e *WriteError) Error() string { return "save users: " + e.Err.Error() }
func (e *WriteError) Unwrap() error { return e.Err }

type Store struct {
	saveMu        sync.Mutex // serialize disk writes; periodic flush leaves readers free
	mu            sync.RWMutex
	path          string
	users         map[string]model.User
	passwords     map[[32]byte]string
	subscriptions map[[32]byte]string
	uuids         map[string]string
	dirty         bool
	problem       error
	write         func(string, []byte) error
}

func Open(path string) (*Store, error) {
	return open(path, writeUsers)
}
func open(path string, write func(string, []byte) error) (*Store, error) {
	s := &Store{path: path, users: make(map[string]model.User), write: write}
	s.reindex()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, os.MkdirAll(filepath.Dir(path), 0700)
	}
	if err != nil {
		return nil, err
	}
	var rows []*model.User
	if err = json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("users database: %w", err)
	}
	if rows == nil {
		return nil, errors.New("users database: expected an array, got null")
	}
	changed := false
	for i, ptr := range rows {
		if ptr == nil {
			return nil, fmt.Errorf("users database: null user at index %d", i)
		}
		u := ptr.Clone()
		if _, exists := s.users[u.Name]; exists {
			return nil, fmt.Errorf("users database: duplicate user %q", u.Name)
		}
		before := len(u.ProtoOff)
		u.ProtoOff = slices.DeleteFunc(u.ProtoOff, func(p string) bool { return !model.KnownProtocol(p) })
		changed = changed || before != len(u.ProtoOff)
		if u.UUID == "" {
			u.UUID = model.UUID()
			changed = true
		}
		if u.SubToken == "" {
			u.SubToken = model.Token(24)
			changed = true
		}
		if err = model.Validate(u); err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		if err = s.unique(u, u.Name); err != nil {
			return nil, err
		}
		s.users[u.Name] = u
		s.index(u)
	}
	// Never hand out new migration keys unless they have been saved.
	if changed {
		if err := migrationBackup(path, b); err != nil {
			return nil, fmt.Errorf("backup before user migration: %w", err)
		}
		if err = s.persist(s.users); err != nil {
			return nil, fmt.Errorf("save user migration: %w", err)
		}
	}
	return s, nil
}

// The first automatic migration keeps the original database, including its
// original client credentials. An existing backup is never overwritten.
func migrationBackup(path string, b []byte) error {
	f, err := os.OpenFile(path+".pre-v2", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	err = atomicfile.WriteAndClose(f, b)
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

func writeUsers(path string, b []byte) error {
	return atomicfile.Replace(path, b, atomicfile.Options{Mode: 0600})
}
func cloneUsers(in map[string]model.User) map[string]model.User {
	out := make(map[string]model.User, len(in))
	for k, u := range in {
		out[k] = u.Clone()
	}
	return out
}
func sorted(in map[string]model.User) []model.User {
	out := make([]model.User, 0, len(in))
	for _, u := range in {
		out = append(out, u.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].Name < out[j].Name
	})
	return out
}
func (s *Store) persist(users map[string]model.User) error {
	b, err := json.MarshalIndent(sorted(users), "", "  ")
	if err != nil {
		return err
	}
	err = s.write(s.path, b)
	if atomicfile.Committed(err) {
		s.problem = err
		s.dirty = true
		return nil
	}
	if err != nil {
		s.problem = err
		s.dirty = true
		return &WriteError{err}
	}
	s.problem = nil
	s.dirty = false
	return nil
}
func (s *Store) unique(u model.User, self string) error {
	if name, ok := s.passwords[sha256.Sum256([]byte(u.Password))]; ok && name != self {
		return errors.New("password already used by " + name)
	}
	if name, ok := s.uuids[u.UUID]; ok && name != self {
		return errors.New("uuid already used by " + name)
	}
	if name, ok := s.subscriptions[sha256.Sum256([]byte(u.SubToken))]; ok && name != self {
		return errors.New("subscription token already used by " + name)
	}
	return nil
}

func (s *Store) index(u model.User) {
	s.passwords[sha256.Sum256([]byte(u.Password))] = u.Name
	s.subscriptions[sha256.Sum256([]byte(u.SubToken))] = u.Name
	s.uuids[u.UUID] = u.Name
}
func (s *Store) reindex() {
	s.passwords = make(map[[32]byte]string, len(s.users))
	s.subscriptions = make(map[[32]byte]string, len(s.users))
	s.uuids = make(map[string]string, len(s.users))
	for _, u := range s.users {
		s.index(u)
	}
}
func (s *Store) List() []model.User { s.mu.RLock(); defer s.mu.RUnlock(); return sorted(s.users) }
func (s *Store) Get(name string) (model.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[name]
	return u.Clone(), ok
}
func (s *Store) Problem() error { s.mu.RLock(); defer s.mu.RUnlock(); return s.problem }
func (s *Store) Resolve(auth string) (model.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name, pass, ok := strings.Cut(auth, ":"); ok {
		if u, ok := s.users[strings.ToLower(name)]; ok && model.EqualSecret(u.Password, pass) {
			return u.Clone(), true
		}
	}
	if name, ok := s.passwords[sha256.Sum256([]byte(auth))]; ok {
		return s.users[name].Clone(), true
	}
	return model.User{}, false
}
func (s *Store) BySubToken(token string) (model.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if token == "" {
		return model.User{}, false
	}
	if name, ok := s.subscriptions[sha256.Sum256([]byte(token))]; ok {
		return s.users[name].Clone(), true
	}
	return model.User{}, false
}
func (s *Store) Create(u model.User) (model.User, error) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	u = u.Clone()
	u.Name = strings.ToLower(u.Name)
	if _, exists := s.users[u.Name]; exists {
		return model.User{}, errors.New("user exists")
	}
	if u.Password == "" {
		u.Password = model.Token(20)
	}
	if u.UUID == "" {
		u.UUID = model.UUID()
	}
	u.SubToken = model.Token(24)
	u.CreatedAt = time.Now().Unix()
	u.LastReset = model.Month(time.Now())
	if err := model.Validate(u); err != nil {
		return model.User{}, err
	}
	if err := s.unique(u, u.Name); err != nil {
		return model.User{}, err
	}
	next := cloneUsers(s.users)
	next[u.Name] = u
	if err := s.persist(next); err != nil {
		return model.User{}, err
	}
	s.users = next
	s.reindex()
	return u.Clone(), nil
}
func (s *Store) Update(name string, edit func(*model.User) error) (model.User, error) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[name]
	if !ok {
		return model.User{}, ErrNotFound
	}
	u = u.Clone()
	if err := edit(&u); err != nil {
		return model.User{}, err
	}
	if u.Name != name {
		return model.User{}, errors.New("name cannot be changed by this operation")
	}
	if err := model.Validate(u); err != nil {
		return model.User{}, err
	}
	if err := s.unique(u, name); err != nil {
		return model.User{}, err
	}
	next := cloneUsers(s.users)
	next[name] = u.Clone()
	if err := s.persist(next); err != nil {
		return model.User{}, err
	}
	s.users = next
	s.reindex()
	return u.Clone(), nil
}
func (s *Store) Delete(name string) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[name]; !ok {
		return ErrNotFound
	}
	next := cloneUsers(s.users)
	delete(next, name)
	if err := s.persist(next); err != nil {
		return err
	}
	s.users = next
	s.reindex()
	return nil
}
func (s *Store) Flush() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.MarshalIndent(sorted(s.users), "", "  ")
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.dirty = false
	s.mu.Unlock()
	err = s.write(s.path, b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.problem = err
	if err != nil {
		s.dirty = true
		return err
	}
	return nil
}
func add(a, b int64) int64 {
	if b <= 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}
func (s *Store) Tick(now time.Time, traffic map[string]model.Traffic, online map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, u := range s.users {
		changed := false
		if u.ResetMonthly && u.LastReset < model.Month(now) {
			u.Up = 0
			u.Down = 0
			u.LastReset = model.Month(now)
			changed = true
		}
		if d := traffic[name]; d.Tx > 0 || d.Rx > 0 {
			u.Up = add(u.Up, d.Tx)
			u.Down = add(u.Down, d.Rx)
			u.LastSeen = max(u.LastSeen, now.Unix())
			changed = true
		}
		if online[name] > 0 {
			u.LastSeen = max(u.LastSeen, now.Unix())
			changed = true
		}
		if changed {
			s.users[name] = u
			s.dirty = true
		}
	}
}
