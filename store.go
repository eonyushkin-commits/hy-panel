package main

import (
	"os"
	"time"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"github.com/eonyushkin-commits/hy-panel/internal/model"
	"github.com/eonyushkin-commits/hy-panel/internal/storage"
)

// Shared types keep protocol adapters independent from storage implementation.
type User = model.User
type Store = storage.Store

var errNotFound = storage.ErrNotFound

func OpenStore(path string) (*Store, error) {
	return storage.Open(path)
}
func yyyymm(now time.Time) int { return model.Month(now) }
func randStr(n int) string     { return model.Token(n) }
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	return atomicfile.Replace(path, data, atomicfile.Options{Mode: mode})
}
