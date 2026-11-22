//go:build !windows

package state

import (
	"os"
	"path/filepath"
	"syscall"
)

// FileLock takes an exclusive inter-process lock on path and returns the function that releases it.
func FileLock(path string) (unlock func(), err error) {
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
