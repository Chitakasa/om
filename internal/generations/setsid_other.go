//go:build windows

package generations

import "os/exec"

func detach(c *exec.Cmd) {}
