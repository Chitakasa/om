//go:build windows

package cli

import (
	"os"
	"syscall"
)

func ttyCols() int { return 0 }

// isatty reports a console handle (a pipe, a file or NUL is not one).
func isatty(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}
