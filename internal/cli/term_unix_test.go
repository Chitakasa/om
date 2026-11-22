//go:build unix

package cli

import (
	"os"
	"testing"
)

// /dev/null is a character device but not a terminal: a job with stdin or stdout on it (cron, a systemd unit) is not
// interactive, and `om shell` must not ask for a tty there.
func TestDevNullIsNotATerminal(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("/dev/null counted as a terminal")
	}
	if p, err := os.Open("/dev/tty"); err == nil {
		defer p.Close()
		if !isTerminal(p) {
			t.Error("/dev/tty is a terminal")
		}
	}
}
