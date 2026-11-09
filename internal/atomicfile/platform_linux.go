package atomicfile

import (
	"os"
	"syscall"
)

func preserveOwner(f *os.File, info os.FileInfo) error {
	st := info.Sys().(*syscall.Stat_t)
	return f.Chown(int(st.Uid), int(st.Gid))
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
