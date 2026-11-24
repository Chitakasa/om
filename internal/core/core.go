// Package core is the Global Core's lifecycle: its prerequisites, `up` / `down`, self-heal at boot and every two
// minutes, the instant watcher, and drift between the running edge and what detection says now. It also holds the
// two pieces that need the whole picture: writing the runtime files compose reads (runtime.env, ports.yml,
// dashboard-mounts.yml) and hot-reloading the edge's routes. Port of lib/gitops/core.py, corewatch.py and the
// remaining functions of omsettings.py and network.py.
package core

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/firewall"
	"github.com/Chitakasa/om/internal/links"
	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/stream"
)

// Core runs the core's lifecycle. Everything it touches comes in through its fields.
type Core struct {
	D      state.Dirs
	Reg    registry.Registry
	Eng    *engine.Engine
	Egress *egress.Egress
	Stream *stream.Stream
	Det    *netdetect.Detector
	FW     *firewall.Firewall
	Out    io.Writer

	// Settings loads om.env (with the template defaults).
	Settings func() settings.Settings
	// Run runs a command; RunDir runs one in a directory; RunTTY runs one with the terminal attached and returns its
	// exit code.
	Run    func([]string) state.Result
	RunDir func(cmd []string, dir string) state.Result
	RunTTY func(cmd []string, dir string) int

	Now      func() time.Time
	Sleep    func(time.Duration)
	Hostname func() string
	// ProcRoot and CgroupRoot are /proc and /sys/fs/cgroup (replaced in tests).
	ProcRoot, CgroupRoot string
	// PortFree replaces the real check that a port can be bound (tests).
	PortFree func(port int) bool
	// Watcher builds the event source of `om core watch` (Linux only; nil elsewhere).
	NewWatcher func(runtime string) (Watcher, error)
	// DashboardBinary, when set, is the Linux om binary the dashboard container runs; WriteRuntimeFiles copies it into
	// <state>/bin/om-dashboard (mounted read-only at /om).
	DashboardBinary func() (string, error)
	GOOS            string
}

func (c *Core) p(format string, a ...any) { fmt.Fprintf(c.Out, format+"\n", a...) }

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// EnsureCorePrerequisites makes the files and folders the core compose file bind-mounts exist, or the engine fails
// or creates folders.
func (c *Core) EnsureCorePrerequisites() error {
	d := c.D
	for _, dir := range []string{filepath.Join(d.Data, "caddy"), filepath.Join(d.Data, "caddy_config"), filepath.Join(d.Data, "router"),
		filepath.Join(d.Data, "dashboard"), d.Routes, d.Auth, d.CoreRoutes, d.Config} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := c.Egress.EnsureBase(); err != nil {
		return err
	}
	if err := c.Stream.EnsureConfigs(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.Registry), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(d.Registry); err != nil {
		if err := os.WriteFile(d.Registry, []byte("{}\n"), 0o644); err != nil {
			return err
		}
	}
	if _, err := os.Stat(d.UserEnv); err != nil {
		return state.WritePrivate(d.UserEnv, settings.UserEnvTemplate) // holds OM_NOTIFY_URL, a bearer-like secret
	}
	return nil
}

// CoreCompose is the compose command line for the core: its env file and the three compose files.
func (c *Core) CoreCompose(runtime string, args ...string) ([]string, error) {
	if _, err := os.Stat(c.D.MountsFile); err != nil { // state written before this file existed
		if err := state.WriteAtomic(c.D.MountsFile, settings.RenderDashboardMounts(nil)); err != nil {
			return nil, err
		}
	}
	file := filepath.Join(c.D.Core, "compose.yml")
	if _, err := os.Stat(file); err != nil {
		file = filepath.Join(c.D.Core, "docker-compose.yml")
	}
	return append([]string{runtime, "compose", "--env-file", c.D.RuntimeEnv, "-f", file, "-f", c.D.PortsFile, "-f", c.D.MountsFile}, args...), nil
}

// RootfulProblem is why om stops on an engine that runs as root: the core's containers drop every capability, so
// container-root cannot write the user-owned state folders (the edge restarts in a loop and nothing answers). Under a
// rootless engine container-root is the user, which is what om relies on.
const RootfulProblem = "The container engine runs as root (rootful). om's core containers drop every capability, so they cannot write your state folders and the edge would restart in a loop. Use rootless Podman, as a normal user (not with sudo)."

// portFree reports whether this machine can bind the port on every address (a port a rootless engine may not bind, or
// one another program holds, is not free).
func (c *Core) portFree(port int) bool {
	if c.PortFree != nil {
		return c.PortFree(port)
	}
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// Preflight returns the problems that would make `compose up` fail, with fixes. Empty means good to go.
func (c *Core) Preflight(runtime string) []string {
	eng := c.Eng.Info(runtime)
	if !eng.OK {
		return []string{fmt.Sprintf("Container engine '%s' is not responding. Check that `podman info` works (macOS and Windows: `podman machine start`). om runs on Podman only.", runtime)}
	}
	var problems []string
	if !c.Eng.ComposeAvailable(runtime) {
		problems = append(problems, fmt.Sprintf("`%s compose` is unavailable. Install a compose provider for Podman: docker-compose v2 or podman-compose.", runtime))
	}
	if c.GOOS == "linux" && !eng.Rootless && !eng.RemoteVM {
		problems = append(problems, RootfulProblem)
	}
	if c.GOOS == "linux" && eng.Rootless && !eng.RemoteVM {
		h, s := c.Settings().EdgePorts()
		low := h
		if s < low {
			low = s
		}
		if start, ok := c.Eng.UnprivilegedPortStart(); ok && start > low {
			problems = append(problems, fmt.Sprintf("Rootless engines cannot bind ports %d/%d yet. Fix (once):\n"+
				"      echo 'net.ipv4.ip_unprivileged_port_start=%d' | sudo tee /etc/sysctl.d/99-om.conf && sudo sysctl --system", h, s, low))
		}
	}
	return problems
}

// announceIngress says where the core answers, and which VPNs were found but are not trusted.
func (c *Core) announceIngress(r settings.Resolved) {
	tiers := []string{"localhost"}
	if len(r.VPNIPs) > 0 {
		tiers = append(tiers, "VPN "+strings.Join(r.VPNIPs, ", "))
	}
	if r.LANIP != "" {
		tiers = append(tiers, "LAN "+r.LANIP+" (public tier)")
	}
	c.p("  Ingress: %s", strings.Join(tiers, ", "))
	trusted := netdetect.VPNItems(c.Settings().Get("OM_VPN", ""))
	has := func(s string) bool {
		for _, t := range trusted {
			if t == s {
				return true
			}
		}
		return false
	}
	for _, a := range c.Det.VPNCandidates() {
		if !has(a.Name) && !has(a.IP) {
			ip := a.IP
			if ip == "" {
				ip = "no address"
			}
			c.p("  VPN %s (%s) is not trusted — if only your devices are on it: om vpn trust %s", a.Name, ip, a.Name)
		}
	}
}

// removeRetiredParts removes the parts ADR 0003 retired: their containers, state and gated route sections go on
// the first start after it.
func (c *Core) removeRetiredParts(runtime string) {
	var retired []string
	for _, name := range state.RetiredContainers {
		if c.Run([]string{runtime, "container", "inspect", name}).Code == 0 {
			retired = append(retired, name)
		}
	}
	for _, r := range retired {
		if r == "om_wg" {
			c.Run([]string{runtime, "rm", "-f", state.Edge}) // it ran in om_wg's network namespace; recreated below
		}
	}
	for _, r := range retired {
		c.Run([]string{runtime, "rm", "-f", r})
	}
	for _, d := range []string{"access", "gate", "door", "mirror", "hostquiet"} {
		os.RemoveAll(filepath.Join(c.D.State, d))
	}
	files, _ := filepath.Glob(filepath.Join(c.D.Routes, "*.caddy")) // gated sites in routes generated before ADR 0003
	for _, f := range files {
		text, err := py.ReadText(f)
		if err != nil {
			continue
		}
		if cut := strings.Index(text, "\n# Through the door, behind the gate"); cut >= 0 {
			os.WriteFile(f, []byte(strings.TrimRight(text[:cut], "\n")+"\n"), 0o644)
		}
	}
}

func (c *Core) composeUp(runtime string, recreate bool) bool {
	args := []string{"up", "-d", "--remove-orphans"}
	if recreate {
		args = append(args, "--force-recreate")
	}
	cmd, err := c.CoreCompose(runtime, args...)
	if err != nil {
		c.p("\033[31m✗ Global Core failed to start:\033[0m\n%s", err)
		return false
	}
	r := c.RunDir(cmd, c.D.Core)
	if r.Code == 0 {
		return true
	}
	errText := r.Stderr
	if errText == "" {
		errText = r.Stdout
	}
	errText = py.Strip(errText)
	c.p("\033[31m✗ Global Core failed to start:\033[0m\n%s", lastRunes(errText, 1500))
	low := strings.ToLower(errText)
	if strings.Contains(low, "address") && (strings.Contains(low, "assign") || strings.Contains(low, "in use")) {
		c.p("  Hint: an ingress address changed or a port is taken. Check `om doctor`, or set OM_LAN_IP / OM_VPN in %s.", c.D.UserEnv)
	}
	return false
}

// coreStaysUp: `up -d` succeeds even if a container crash-loops right after; wait up to 20 s for all of them, and
// say why not.
func (c *Core) coreStaysUp(runtime string) bool {
	deadline := c.Now().Add(20 * time.Second)
	var down []string
	for {
		down = nil
		for _, name := range state.CoreContainers {
			if !c.Eng.ContainerRunning(runtime, name) {
				down = append(down, name)
			}
		}
		if len(down) == 0 || c.Now().After(deadline) {
			break
		}
		c.Sleep(time.Second)
	}
	for _, name := range down {
		logs := c.Run([]string{runtime, "logs", "--tail", "15", name})
		c.p("\033[31m✗ %s is not running.\033[0m Last log lines:\n%s", name, lastRunes(py.Strip(logs.Stdout+logs.Stderr), 1200))
	}
	return len(down) == 0
}

// Up starts the core (recreating its containers with recreate).
func (c *Core) Up(runtime string, recreate, quiet bool) (bool, error) {
	if err := c.EnsureCorePrerequisites(); err != nil {
		return false, err
	}
	os.Remove(c.D.StopMarker)
	notes, err := settings.ResolveEdgePorts(c.D, c.portFree, func() bool { return c.Eng.ContainerRunning(runtime, state.Edge) })
	if err != nil {
		c.p("\033[31m✗ %s\033[0m", err)
		return false, nil
	}
	for _, n := range notes {
		c.p("  %s", n)
	}
	if problems := c.Preflight(runtime); len(problems) > 0 {
		for _, p := range problems {
			c.p("\033[31m✗ %s\033[0m", p)
		}
		return false, nil
	}
	if ok, msg := c.Egress.EnsureImage(runtime); !ok {
		c.p("\033[31m✗ could not build the egress proxy image: %s\033[0m", msg)
		return false, nil
	}
	resolved, err := c.WriteRuntimeFiles(runtime)
	if err != nil {
		return false, err
	}
	os.Remove(filepath.Join(c.D.Data, "heal-drift-seen")) // the core now runs on the current addresses
	if !quiet {
		c.announceIngress(resolved)
	}
	c.removeRetiredParts(runtime)
	c.Eng.ReviveZombies(runtime) // compose would treat a container with a dead process as already running
	if !c.composeUp(runtime, recreate) || !c.coreStaysUp(runtime) {
		return false, nil
	}
	var ids []string
	for id := range c.Reg.Read() {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	failed := c.Eng.ConnectRouter(runtime, ids)
	for _, net := range failed {
		c.p("\033[33m⚠ Could not attach the router to %s\033[0m", net)
	}
	return len(failed) == 0, nil
}

// Down stops the core; the self-heal timer leaves it stopped until `om core start`.
func (c *Core) Down(runtime string) (bool, error) {
	for _, f := range []string{c.D.RuntimeEnv, c.D.PortsFile, c.D.MountsFile} {
		if _, err := os.Stat(f); err != nil {
			if _, err := c.WriteRuntimeFiles(runtime); err != nil {
				return false, err
			}
			break
		}
	}
	if err := os.MkdirAll(filepath.Dir(c.D.StopMarker), 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(c.D.StopMarker, []byte("stopped by `om core stop` / `om down`; `om core start` clears this\n"), 0o644); err != nil {
		return false, err
	}
	cmd, err := c.CoreCompose(runtime, "down")
	if err != nil {
		return false, err
	}
	return c.RunTTY(cmd, c.D.Core) == 0, nil
}

// Running reports that every core container runs.
func (c *Core) Running(runtime string) bool {
	for _, name := range state.CoreContainers {
		if !c.Eng.ContainerRunning(runtime, name) {
			return false
		}
	}
	return true
}

func (c *Core) vpnPrivateOpen() bool {
	s := c.Settings()
	if len(s.VPNAllow()) == 0 {
		return true
	}
	return c.FW.VPNAllowEnforced()
}

func (c *Core) hooks() settings.Hooks {
	return settings.Hooks{
		IsLocal: c.Det.IsLocal,
		StreamPorts: func() map[string]settings.StreamPort {
			out := map[string]settings.StreamPort{}
			for k, v := range c.Reg.StreamPorts() {
				out[k] = settings.StreamPort{HostPort: v.HostPort, Scope: v.Scope}
			}
			return out
		},
		NetPolicies:       c.Reg.NetPolicies,
		NetPolicyEnforced: func(key string, pol map[string]any) bool { return c.FW.NetPolicyEnforced(key, pol) },
	}
}

// RuntimeDrift lists the differences between what the running edge was started with and what detection says now.
func (c *Core) RuntimeDrift() []string {
	b, err := py.ReadText(c.D.PortsFile)
	if err != nil {
		return nil
	}
	var drift []string
	r := c.Settings().Resolve(c.D, c.Det)
	r.VPNPrivate = c.vpnPrivateOpen()
	if b != settings.RenderPorts(c.D, r, c.hooks()) {
		drift = append(drift, "Ingress addresses changed since the core was started (e.g. new LAN IP, or a VPN came up/down). Run: om core restart")
	}
	mounts, _ := py.ReadText(c.D.MountsFile)
	if mounts != settings.RenderDashboardMounts(settings.WorkspaceDashboardDirs(c.Reg)) {
		drift = append(drift, "Workspaces were added or removed since the core started, so the dashboard doesn't see their data folders. Run: om core restart")
	}
	return drift
}

// WriteRuntimeFiles resolves the settings and writes runtime.env, ports.yml and dashboard-mounts.yml.
func (c *Core) WriteRuntimeFiles(runtime string) (settings.Resolved, error) {
	s := c.Settings()
	resolved := s.Resolve(c.D, c.Det)
	eng := c.Eng.Info(runtime)
	if err := os.MkdirAll(resolved.WallpapersDir, 0o755); err != nil {
		return resolved, err
	}
	token, err := settings.EdgeToken(c.D)
	if err != nil {
		return resolved, err
	}
	pairs := settings.RuntimeEnvPairs(c.D, resolved, settings.RuntimeInputs{
		EngineSocket: eng.Socket, EgressImage: c.Egress.Image(), EdgeToken: token, Hostname: c.Hostname(),
	})
	if err := state.WritePrivate(c.D.RuntimeEnv, settings.RenderRuntimeEnv(c.D, pairs)); err != nil {
		return resolved, err
	}
	resolved.VPNPrivate = c.vpnPrivateOpen()
	if err := c.Stream.EnsureConfigs(); err != nil {
		return resolved, err
	}
	if err := os.MkdirAll(filepath.Dir(c.D.PortsFile), 0o755); err != nil {
		return resolved, err
	}
	if err := os.WriteFile(c.D.PortsFile, []byte(settings.RenderPorts(c.D, resolved, c.hooks())), 0o644); err != nil {
		return resolved, err
	}
	dirs := settings.WorkspaceDashboardDirs(c.Reg)
	if err := settings.MigrateDashboardData(c.D, dirs); err != nil {
		return resolved, err
	}
	if err := os.WriteFile(c.D.MountsFile, []byte(settings.RenderDashboardMounts(dirs)), 0o644); err != nil {
		return resolved, err
	}
	if err := c.installDashboardBinary(); err != nil {
		fmt.Fprintf(c.Out, "\033[33m⚠ dashboard binary not installed: %s\033[0m\n", err)
	}
	return resolved, nil
}

// ReloadCaddy validates, then hot-reloads the edge route table (recreating the edge if its Caddyfile mount is
// stale). ws is only for the caller's records.
func (c *Core) ReloadCaddy(runtime, ws string, quiet bool) bool {
	st := c.Run([]string{runtime, "container", "inspect", "--format", "{{.State.Running}}", state.Edge})
	if st.Code != 0 || py.Strip(st.Stdout) != "true" {
		if !quiet {
			c.p("\033[33mℹ Edge proxy is not running; routes apply on next `om core start`.\033[0m")
		}
		return false
	}
	if c.caddyfileStale(runtime) {
		if _, err := c.WriteRuntimeFiles(runtime); err != nil {
			c.p("\033[31mEdge recreate failed:\033[0m %s", err)
			return false
		}
		cmd, err := c.CoreCompose(runtime, "up", "-d", "--force-recreate", "caddy")
		if err != nil {
			return false
		}
		r := c.RunDir(cmd, c.D.Core)
		ok := r.Code == 0
		if !quiet {
			if ok {
				c.p("\033[32m✓ Edge proxy recreated with the updated Caddyfile.\033[0m")
			} else {
				out := r.Stderr
				if out == "" {
					out = r.Stdout
				}
				c.p("\033[31mEdge recreate failed:\033[0m %s", lastRunes(py.Strip(out), 800))
			}
		}
		return ok
	}
	val := c.Run([]string{runtime, "exec", state.Edge, "caddy", "validate", "--config", "/etc/caddy/Caddyfile"})
	if val.Code != 0 {
		text := val.Stderr
		if text == "" {
			text = val.Stdout
		}
		var lines []string
		for _, ln := range py.SplitLines(text) {
			if strings.Contains(strings.ToLower(ln), "error") {
				lines = append(lines, ln)
			}
		}
		if len(lines) == 0 {
			lines = []string{py.Strip(text)}
		}
		c.p("\033[31m✗ Caddy config invalid — live routes left unchanged:\033[0m %s", lastRunes(lines[len(lines)-1], 600))
		return false
	}
	res := c.Run([]string{runtime, "exec", state.Edge, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"})
	if res.Code == 0 {
		if !quiet {
			c.p("\033[32m✓ Caddy route table hot-reloaded (zero downtime).\033[0m")
		}
		return true
	}
	c.p("\033[31mCaddy reload error: %s\033[0m", lastRunes(py.Strip(res.Stderr), 600))
	return false
}

// caddyfileStale: a single-file bind mount pins the inode: editors that replace the file leave the container
// reading the old one, so a plain reload would silently apply stale config.
func (c *Core) caddyfileStale(runtime string) bool {
	host, err := py.ReadText(filepath.Join(c.D.Core, "caddy", "Caddyfile"))
	if err != nil {
		return false
	}
	inside := c.Run([]string{runtime, "exec", state.Edge, "cat", "/etc/caddy/Caddyfile"})
	return inside.Code == 0 && inside.Stdout != host
}

// LinksRunner adapts Run for the links package.
func (c *Core) LinksRunner() links.Runner { return links.Runner(c.Run) }

// DefaultRunners fills the command runners with real ones.
func DefaultRunners(c *Core) {
	c.Run = func(cmd []string) state.Result { return state.Run(cmd) }
	c.RunDir = func(cmd []string, dir string) state.Result { return state.Run(cmd, state.WithDir(dir)) }
	c.RunTTY = func(cmd []string, dir string) int {
		x := exec.Command(cmd[0], cmd[1:]...)
		x.Dir = dir
		x.Stdin, x.Stdout, x.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := x.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			return 127
		}
		return 0
	}
}
