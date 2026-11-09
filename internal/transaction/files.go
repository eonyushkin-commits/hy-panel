// Package transaction applies a set of files and restores their previous
// contents when a write or service activation fails. It handles process errors;
// it does not claim filesystem-wide atomicity across power loss.
package transaction

import (
	"errors"
	"fmt"
	"os"

	"github.com/eonyushkin-commits/hy-panel/internal/atomicfile"
)

type File struct {
	Path    string
	Data    []byte
	Options atomicfile.Options
}
type previous struct {
	data   []byte
	info   os.FileInfo
	exists bool
}

// Run validates snapshots before changing any file. recoverServices runs only
// after a failed activation and successful file restoration.
func Run(files []File, activate, recoverServices func() error) error {
	old := make([]previous, len(files))
	seen := map[string]bool{}
	for i, f := range files {
		if seen[f.Path] {
			return fmt.Errorf("duplicate transaction path: %s", f.Path)
		}
		seen[f.Path] = true
		info, err := os.Stat(f.Path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: expected a regular file", f.Path)
		}
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return err
		}
		old[i] = previous{data, info, true}
	}
	rollback := func(last int, cause error, activated bool) error {
		var failures []error
		for i := last; i >= 0; i-- {
			f, p := files[i], old[i]
			var err error
			if p.exists {
				err = atomicfile.Replace(f.Path, p.data, atomicfile.Options{Metadata: p.info, FollowSymlink: f.Options.FollowSymlink})
			} else {
				err = os.Remove(f.Path)
				if errors.Is(err, os.ErrNotExist) {
					err = nil
				}
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("restore %s: %w", f.Path, err))
			}
		}
		if len(failures) == 0 && activated && recoverServices != nil {
			if err := recoverServices(); err != nil {
				failures = append(failures, fmt.Errorf("restore services: %w", err))
			}
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}
	for i, f := range files {
		if err := atomicfile.Replace(f.Path, f.Data, f.Options); err != nil {
			last := i - 1
			if atomicfile.Committed(err) {
				last = i
			}
			return rollback(last, err, false)
		}
	}
	if activate != nil {
		if err := activate(); err != nil {
			return rollback(len(files)-1, err, true)
		}
	}
	return nil
}
