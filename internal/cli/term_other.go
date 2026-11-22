//go:build !unix && !windows

package cli

import "os"

func ttyCols() int { return 0 }

func isatty(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
