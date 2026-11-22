package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DashboardBinName is the file in <state>/bin that the dashboard container runs.
const DashboardBinName = "om-dashboard"

// installDashboardBinary copies the Linux om binary to <state>/bin/om-dashboard (atomically; unchanged copies are
// left alone). The container mounts that directory, so a replaced file is picked up when it is recreated.
func (c *Core) installDashboardBinary() error {
	if c.DashboardBinary == nil {
		return nil
	}
	src, err := c.DashboardBinary()
	if err != nil {
		return err
	}
	dir := filepath.Join(c.D.State, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dir, DashboardBinName)
	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if di, err := os.Stat(dst); err == nil && di.Size() == si.Size() && !di.ModTime().Before(si.ModTime()) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(dir, ".om-dashboard-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return fmt.Errorf("copy om binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
