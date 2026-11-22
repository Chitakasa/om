package firewall

import (
	"fmt"
	"path/filepath"

	"github.com/Chitakasa/om/internal/py"
)

func (f *Firewall) sudoAll(steps [][]string) bool {
	for _, s := range steps {
		if !f.Sudo(s) {
			return false
		}
	}
	return true
}

// Apply writes and installs the firewall: sudo steps on Linux and macOS, a script to run from an elevated
// PowerShell on Windows.
func (f *Firewall) Apply() (bool, error) {
	path, err := f.Generate()
	if err != nil {
		return false, err
	}
	switch {
	case f.linux():
		if _, err := f.LookPath("nft"); err != nil {
			fmt.Fprintln(f.Out, "\033[31m✗ nftables (nft) is not installed.\033[0m")
			return false, nil
		}
		return f.sudoAll([][]string{
			{"install", "-m644", path, "/etc/om-firewall.nft"},
			{"install", "-m644", filepath.Join(f.D.Firewall, "om-firewall.service"), "/etc/systemd/system/om-firewall.service"},
			{"systemctl", "daemon-reload"},
			{"systemctl", "enable", "om-firewall"},
			{"systemctl", "restart", "om-firewall"},
		}), nil
	case f.macos():
		ok := f.sudoAll([][]string{
			{"install", "-m644", path, "/etc/pf.anchors/om"},
			{"pfctl", "-a", "om", "-f", "/etc/pf.anchors/om"},
			{"pfctl", "-E"},
		})
		fmt.Fprintln(f.Out, "  To keep it across reboots, add to /etc/pf.conf:\n"+
			"    rdr-anchor \"om\"    (after the other rdr-anchor lines)\n"+
			"    anchor \"om\"\n    load anchor \"om\" from \"/etc/pf.anchors/om\"")
		return ok, nil
	}
	fmt.Fprintf(f.Out, "Run this from an elevated PowerShell:\n  powershell -ExecutionPolicy Bypass -File \"%s\"\n", path)
	return true, nil
}

// Remove takes the firewall off.
func (f *Firewall) Remove() bool {
	switch {
	case f.linux():
		f.Sudo([]string{"systemctl", "disable", "--now", "om-firewall"}) // the unit may not exist: not an error
		f.Sudo([]string{"nft", "delete", "table", "inet", "om_guard"})   // nor may the table (the unit's stop removed it)
		return f.Status() != "active"
	case f.macos():
		return f.Sudo([]string{"pfctl", "-a", "om", "-F", "all"})
	}
	fmt.Fprintln(f.Out, "Run from an elevated PowerShell:\n  Get-NetFirewallRule -Group \"om\" | Remove-NetFirewallRule")
	return true
}

// Installed reports that om's firewall has been applied on this host before (so re-applying it changes nothing else).
func (f *Firewall) Installed() bool {
	if f.macos() {
		_, err := f.ReadFile(f.PfInstalled)
		return err == nil
	}
	return f.Status() == "active"
}

// Status is "active", "inactive" or "unknown" (checking may need privileges).
func (f *Firewall) Status() string {
	switch {
	case f.linux():
		if py.Strip(f.Run([]string{"systemctl", "is-active", "om-firewall"}).Stdout) == "active" {
			return "active"
		}
		return "inactive"
	case f.macos():
		return "unknown"
	}
	r := f.Run([]string{"powershell", "-NoProfile", "-Command", "(Get-NetFirewallRule -Group om -ErrorAction SilentlyContinue | Measure-Object).Count"})
	if s := py.Strip(r.Stdout); s != "" && s != "0" {
		return "active"
	}
	return "inactive"
}
