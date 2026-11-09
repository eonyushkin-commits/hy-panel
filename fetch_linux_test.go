package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExistingServiceAccountHomeCanBeRecreated(t *testing.T) {
	home := filepath.Join(t.TempDir(), "removed-home")
	if err := ensureSystemHome(home, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() {
		t.Fatal("home directory not recreated")
	}
	marker := filepath.Join(home, "keep")
	if err = os.WriteFile(marker, []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = ensureSystemHome(home, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "state" {
		t.Fatal("existing home contents changed")
	}
	if err = ensureSystemHome(marker, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("regular file accepted as home directory")
	}
}
