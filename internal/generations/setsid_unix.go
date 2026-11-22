//go:build !windows

package generations

import (
	"os/exec"
	"syscall"
)

// detach gives the command a session of its own, so it has no terminal to prompt on.
func detach(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
