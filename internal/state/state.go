// Package state holds paths, constants and small utilities shared by every om package: where state and
// settings live, the core's container names and port bases, file locking, atomic and private writes, and the
// one subprocess wrapper. Port of lib/gitops/omstate.py.
//
// OM_HOME holds only the program. Everything per-machine lives outside it (CONFIG_DIR, STATE_DIR), so om can
// be reinstalled or updated without touching state.
package state

import (
	"os"
	"path/filepath"
	"runtime"
)

const Version = "1.0.0"

var (
	IsWindows = runtime.GOOS == "windows"
	IsMacOS   = runtime.GOOS == "darwin"
	IsLinux   = runtime.GOOS == "linux"
)

// Port layout. Each web service gets its own port, so its own browser origin: PrivatePortBase+slot (loopback and
// VPN) and, if public, PublicPortBase+slot (LAN and VPN).
const (
	PrivatePortBase = 20000
	PublicPortBase  = 21000
	PortSlots       = 200
	StreamPortBase  = 22000
	StreamPortSlots = 200
	// Edge (container) ports the VPN addresses' host 80/443 land on, apart from loopback's 80/443.
	VPNHTTPPort  = 81
	VPNHTTPSPort = 444
)

// Core container names.
const (
	Router       = "om_router"
	Egress       = "om_egress"
	Edge         = "om_caddy"
	StreamEdge   = "om_stream_edge"
	StreamRouter = "om_stream_router"
)

var CoreContainers = []string{Edge, Router, Egress, "om_sockguard", "om_dashboard", StreamEdge, StreamRouter}

// RetiredContainers are parts removed by ADR 0003; `om core start` deletes them if they still exist.
var RetiredContainers = []string{"om_wg", "om_gate", "portainer"}

// Disabled returns a reserved never-resolving name (RFC 2606 .invalid) for a disabled address slot.
func Disabled(slot string) string { return slot + ".disabled.invalid" }

// Dirs is every location om reads or writes, resolved from the environment.
type Dirs struct {
	Home, Core, CoreRoutes, Config, State string

	UserEnv, RuntimeEnv, PortsFile, MountsFile string
	Data, TokenFile, StopMarker                string
	Routes, Auth, Firewall, Logs               string
	Registry, ServicePorts, StreamPorts        string
	NetPolicy, NoLog, EgressNets               string
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultDirs() (cfg, state string) {
	if IsWindows {
		base := filepath.Join(envOr("LOCALAPPDATA", filepath.Join(homeDir(), "AppData", "Local")), "om")
		return base, base
	}
	cfg = filepath.Join(envOr("XDG_CONFIG_HOME", filepath.Join(homeDir(), ".config")), "om")
	state = filepath.Join(envOr("XDG_STATE_HOME", filepath.Join(homeDir(), ".local", "state")), "om")
	return
}

// NewDirs resolves OM_HOME, OM_CONFIG_DIR and OM_STATE_DIR (with the platform defaults).
func NewDirs() Dirs {
	dc, ds := defaultDirs()
	d := Dirs{
		Home:   envOr("OM_HOME", filepath.Join(homeDir(), ".om")),
		Config: envOr("OM_CONFIG_DIR", dc),
		State:  envOr("OM_STATE_DIR", ds),
	}
	d.Core = filepath.Join(d.Home, "core")
	d.CoreRoutes = filepath.Join(d.Core, "caddy", "conf.d")
	d.UserEnv = filepath.Join(d.Config, "om.env")
	d.RuntimeEnv = filepath.Join(d.State, "runtime.env")
	d.PortsFile = filepath.Join(d.State, "ports.yml")
	d.MountsFile = filepath.Join(d.State, "dashboard-mounts.yml")
	d.Data = filepath.Join(d.State, "data")
	d.TokenFile = filepath.Join(d.Data, "edge_token")
	d.StopMarker = filepath.Join(d.Data, "stopped")
	d.Routes = filepath.Join(d.State, "routes")
	d.Auth = filepath.Join(d.State, "auth")
	d.Firewall = filepath.Join(d.State, "firewall")
	d.Logs = filepath.Join(d.State, "logs")
	d.Registry = filepath.Join(d.State, "registry", "workspaces.json")
	d.ServicePorts = filepath.Join(d.State, "registry", "service_ports.json")
	d.StreamPorts = filepath.Join(d.State, "registry", "stream_ports.json")
	d.NetPolicy = filepath.Join(d.State, "registry", "net_policy.json")
	d.NoLog = filepath.Join(d.State, "registry", "no_log.json")
	d.EgressNets = filepath.Join(d.State, "networks", "egress.json")
	return d
}
