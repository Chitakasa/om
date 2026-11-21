//go:build windows

package state

import (
	"os"
	"path/filepath"
	"time"
)

// FileLock takes an exclusive lock by creating path+".lck" exclusively (stdlib has no LockFileEx), polling
// until it is free, and returns the function that releases it.
func FileLock(path string) (unlock func(), err error) {
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	lck := path + ".lck"
	for {
		f, e := os.OpenFile(lck, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if e == nil {
			f.Close()
			return func() { os.Remove(lck) }, nil
		}
		if !os.IsExist(e) {
			return nil, e
		}
		time.Sleep(100 * time.Millisecond)
	}
}
