package transaction

import (
	"errors"
	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
	"os"
	"path/filepath"
	"testing"
)

func TestFailedActivationRestoresAllFilesBeforeRecovery(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "config")
	second := filepath.Join(dir, "env")
	if err := os.WriteFile(first, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	recovered := false
	sentinel := errors.New("service rejected candidate")
	err := Run([]File{{first, []byte("new"), atomicfile.Options{}}, {second, []byte("new env"), atomicfile.Options{}}}, func() error { return sentinel }, func() error {
		b, _ := os.ReadFile(first)
		if string(b) != "old" {
			t.Fatal("recovery saw candidate config")
		}
		if _, err := os.Stat(second); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("new env was not removed")
		}
		recovered = true
		return nil
	})
	if !errors.Is(err, sentinel) || !recovered {
		t.Fatalf("rollback: %v, recovered=%v", err, recovered)
	}
}
func TestFailedValidationRollsBackEarlierReplacement(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "one")
	second := filepath.Join(dir, "two")
	if err := os.WriteFile(first, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err := Run([]File{{first, []byte("new"), atomicfile.Options{}}, {second, []byte("bad"), atomicfile.Options{Validate: func(string) error { return errors.New("invalid") }}}}, func() error { t.Fatal("activation after invalid file"); return nil }, nil)
	b, _ := os.ReadFile(first)
	if err == nil || string(b) != "old" {
		t.Fatal("earlier file not restored")
	}
}
