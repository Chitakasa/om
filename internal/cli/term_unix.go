//go:build unix

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// ttyCols is the width of the terminal on stdout (then stderr, stdin), or 0.
func ttyCols() int {
	for _, f := range []*os.File{os.Stdout, os.Stderr, os.Stdin} {
		var ws struct{ Row, Col, X, Y uint16 }
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws))); e == 0 && ws.Col > 0 {
			return int(ws.Col)
		}
	}
	return 0
}
