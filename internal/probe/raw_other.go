//go:build !linux

package probe

// rawForge: probes run in Linux containers; elsewhere there is nothing to forge from.
func rawForge() string { return "blocked" }
