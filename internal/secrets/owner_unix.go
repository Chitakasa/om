//go:build !windows

package secrets

import (
	"os"
	"syscall"
)

func ownedByMe(st os.FileInfo) bool {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid) == os.Getuid()
	}
	return true
}
