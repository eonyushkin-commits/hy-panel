// Package atomicfile provides durable, same-directory file replacement.
package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// CommitError means the replacement is visible but its directory could not be
// synced. Callers must not roll memory back to the previous file contents.
type CommitError struct{ Err error }

func (e *CommitError) Error() string {
	return "replacement committed; durability uncertain: " + e.Err.Error()
}
func (e *CommitError) Unwrap() error { return e.Err }
func Committed(err error) bool       { var e *CommitError; return errors.As(err, &e) }

// Owner is a file's owner and group, by numeric ID.
type Owner struct{ UID, GID int }

type Options struct {
	Mode          os.FileMode
	Owner         *Owner // set this owner, with Mode as given; overrides PreserveOwner
	PreserveOwner bool
	FollowSymlink bool
	Metadata      os.FileInfo // restore an earlier owner/mode instead of the current one
	// Validate runs against the complete staged file before replacing the target.
	// The temporary file keeps the target extension for format-sensitive tools.
	Validate func(string) error
}

func Replace(path string, data []byte, opts Options) error {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if info != nil && info.Mode()&os.ModeSymlink != 0 {
		if !opts.FollowSymlink {
			return fmt.Errorf("%s: refusing to replace a symlink", path)
		}
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		info, err = os.Stat(path)
		if err != nil {
			return err
		}
	}
	if info != nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected a regular file", path)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".hy-panel-*"+filepath.Ext(path))
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	mode := opts.Mode
	if mode == 0 {
		mode = 0600
	}
	if opts.Metadata != nil {
		info = opts.Metadata
	}
	switch {
	case opts.Metadata == nil && opts.Owner != nil:
		if err = f.Chown(opts.Owner.UID, opts.Owner.GID); err != nil && runtime.GOOS != "windows" {
			f.Close()
			return err
		}
	case (opts.PreserveOwner || opts.Metadata != nil) && info != nil:
		mode = info.Mode().Perm()
		if err = preserveOwner(f, info); err != nil {
			f.Close()
			return err
		}
	}
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err = WriteAndClose(f, data); err != nil {
		return err
	}
	if opts.Validate != nil {
		if err = opts.Validate(f.Name()); err != nil {
			return fmt.Errorf("validate replacement: %w", err)
		}
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		return &CommitError{err}
	}
	return nil
}

// CreateOnce writes a new file and syncs it; an existing file is left as it
// is (nil error). For originals and backups that must never be overwritten.
func CreateOnce(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = WriteAndClose(f, data); err != nil {
		os.Remove(path)
	}
	return err
}

func WriteAndClose(f *os.File, data []byte) error {
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
