package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReplacePreservesOriginalUntilCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if runtime.GOOS == "windows" {
		old.Close()
	}
	if err = Replace(path, []byte("new"), Options{Mode: 0600, PreserveOwner: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "new" {
		t.Fatalf("replacement %q: %v", b, err)
	}
	if runtime.GOOS != "windows" {
		buf := make([]byte, 3)
		if _, err = old.Read(buf); err != nil || string(buf) != "old" {
			t.Fatal("old inode truncated")
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0640 {
			t.Fatal("permissions lost")
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".hy-panel-*"))
	if len(matches) != 0 {
		t.Fatal("temporary files leaked")
	}
}

func TestRejectDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := Replace(dir, []byte("bad"), Options{}); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestSymlinkPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if err := Replace(link, []byte("bad"), Options{}); err == nil {
		t.Fatal("symlink accepted without opt-in")
	}
	if err := Replace(link, []byte("new"), Options{FollowSymlink: true}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(link)
	b, _ := os.ReadFile(target)
	if info.Mode()&os.ModeSymlink == 0 || string(b) != "new" {
		t.Fatal("symlink or target lost")
	}
}
