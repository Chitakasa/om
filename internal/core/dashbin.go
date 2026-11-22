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
	_, err := c.installDashboardBinaryChanged()
	return err
}

// installDashboardBinaryChanged is installDashboardBinary, reporting whether it replaced the copy.
func (c *Core) installDashboardBinaryChanged() (bool, error) {
	if c.DashboardBinary == nil {
		return false, nil
	}
	src, err := c.DashboardBinary()
	if err != nil {
		return false, err
	}
	dir := filepath.Join(c.D.State, "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	dst := filepath.Join(dir, DashboardBinName)
	si, err := os.Stat(src)
	if err != nil {
		return false, err
	}
	if di, err := os.Stat(dst); err == nil && di.Size() == si.Size() && !di.ModTime().Before(si.ModTime()) {
		return false, nil
	}
	in, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(dir, ".om-dashboard-")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return false, fmt.Errorf("copy om binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), dst)
}

// RefreshDashboard puts the om that is installed now into the dashboard's folder, when the core has been started on
// this machine before, and restarts the dashboard container if it is running and the copy changed: the container
// keeps the file it started with. It reports whether it restarted the dashboard. Nothing else is touched.
func (c *Core) RefreshDashboard(runtime string) bool {
	if runtime == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(c.D.State, "bin", DashboardBinName)); err != nil {
		return false // the core was never started here: there is no dashboard to refresh
	}
	if changed, err := c.installDashboardBinaryChanged(); err != nil || !changed {
		return false
	}
	if !c.Eng.ContainerRunning(runtime, "om_dashboard") {
		return false
	}
	return c.Run(c.Eng.Lifecycle(runtime, "restart", "om_dashboard")).Code == 0
}
