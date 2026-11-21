// Package engine is the container engine: detection (Podman or Docker, rootless or in a VM), networks, and
// keeping containers alive (starting through the engine with the right oom_score_adj, reviving containers whose
// process died unseen). Port of lib/gitops/enginectl.py.
package engine

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

// Engine runs the engine CLI. Use New() outside tests; the fields exist so tests can supply canned output.
type Engine struct {
	Run      func(cmd []string) state.Result
	OS       string
	Getenv   func(string) string
	Sleep    func(time.Duration)
	ProcRoot string // "/proc"
	Reg      registry.Registry
	LookPath func(string) (string, error)

	mu     sync.Mutex
	infos  map[string]Info
	oomSet bool
	oomVal *int
}

// New returns an Engine for this machine.
func New(reg registry.Registry) *Engine {
	return &Engine{
		Run:      func(c []string) state.Result { return state.Run(c) },
		OS:       runtime.GOOS,
		Getenv:   os.Getenv,
		Sleep:    time.Sleep,
		ProcRoot: "/proc",
		Reg:      reg,
		LookPath: exec.LookPath,
	}
}

// Info is the facts about the engine that change how om must behave.
type Info struct {
	Runtime  string
	OK       bool
	Rootless bool
	RemoteVM bool
	Socket   string
}

// DetectRuntime prefers podman, then docker; OM_RUNTIME forces one.
func (e *Engine) DetectRuntime() string {
	if forced := e.Getenv("OM_RUNTIME"); forced != "" {
		return forced
	}
	for _, c := range []string{"podman", "docker"} {
		if e.Run([]string{c, "--version"}).Code == 0 {
			return c
		}
	}
	return "podman"
}

// EngineInfo asks the engine about itself.
func (e *Engine) EngineInfo(rt string) Info {
	info := Info{Runtime: rt}
	if rt == "podman" {
		r := e.Run([]string{"podman", "info", "--format", "{{.Host.Security.Rootless}}|{{.Host.RemoteSocket.Path}}|{{.Host.ServiceIsRemote}}"})
		if r.Code == 0 && strings.Contains(r.Stdout, "|") {
			parts := strings.Split(py.Strip(r.Stdout), "|")
			if len(parts) >= 3 { // Python raises on fewer; here the engine is simply not understood
				info.OK = true
				info.Rootless = parts[0] == "true"
				info.RemoteVM = parts[2] == "true"
				info.Socket = py.Strip(strings.ReplaceAll(parts[1], "unix://", ""))
				if info.RemoteVM {
					// podman machine (macOS/Windows): RemoteSocket.Path is the *client-side* socket, which doesn't
					// exist inside the VM where containers run. Mount the VM's own one.
					conns := e.Run([]string{"podman", "system", "connection", "list", "--format", "json"})
					info.Socket = VMSocketFromConnections(conns.Stdout)
					if info.Socket == "" {
						info.Socket = "/run/podman/podman.sock"
					}
				}
			}
		}
		if info.Socket == "" && os.Getuid() >= 0 {
			info.Socket = "/run/user/" + strconv.Itoa(os.Getuid()) + "/podman/podman.sock"
		}
		return info
	}
	r := e.Run([]string{"docker", "info", "--format", "{{.OperatingSystem}}|{{json .SecurityOptions}}"})
	if r.Code == 0 && strings.Contains(r.Stdout, "|") {
		osName, secopts, _ := strings.Cut(py.Strip(r.Stdout), "|")
		desktop := strings.Contains(osName, "Docker Desktop")
		info.OK = true
		info.Rootless = strings.Contains(secopts, "rootless")
		info.RemoteVM = desktop || e.OS == "darwin" || e.OS == "windows"
		sock := "/var/run/docker.sock"
		if info.Rootless && !desktop {
			ctx := e.Run([]string{"docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"})
			if h := py.Strip(ctx.Stdout); ctx.Code == 0 && strings.HasPrefix(h, "unix://") {
				sock = h[len("unix://"):]
			}
		}
		info.Socket = sock
	}
	return info
}

// VMSocketFromConnections returns the engine socket path *inside* the podman machine VM, from
// `podman system connection list --format json` (default connection URI, e.g.
// ssh://core@127.0.0.1:53210/run/user/501/podman/podman.sock).
func VMSocketFromConnections(jsonText string) string {
	if jsonText == "" {
		jsonText = "[]"
	}
	v, err := py.LoadJSON([]byte(jsonText))
	if err != nil {
		return ""
	}
	var conns []map[string]any
	toList := func(a any) {
		list, _ := a.([]any)
		for _, x := range list {
			if o, ok := x.(*py.Object); ok {
				conns = append(conns, objMap(o))
			} else if m, ok := x.(map[string]any); ok {
				conns = append(conns, m)
			}
		}
	}
	switch x := v.(type) {
	case []any:
		toList(x)
	case map[string]any: // older podman: {"Connections": [...]}
		toList(x["Connections"])
	}
	var def []map[string]any
	for _, c := range conns {
		if truthy(c["Default"]) {
			def = append(def, c)
		}
	}
	if len(def) == 0 {
		def = conns
	}
	for _, c := range def {
		uri, _ := c["URI"].(string)
		if !strings.HasPrefix(uri, "ssh://") {
			continue
		}
		rest := strings.SplitN(uri, "://", 2)[1]
		if !strings.Contains(rest, "/") {
			continue
		}
		parts := strings.SplitN(rest, "/", 2)
		if path := "/" + parts[len(parts)-1]; strings.HasSuffix(path, ".sock") {
			return path
		}
	}
	return ""
}

func objMap(o *py.Object) map[string]any {
	m := map[string]any{}
	for _, k := range o.Keys() {
		m[k], _ = o.Get(k)
	}
	return m
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, _ := strconv.ParseFloat(x.String(), 64)
		return f != 0
	}
	return true
}

// ComposeAvailable reports whether `<runtime> compose` works.
func (e *Engine) ComposeAvailable(rt string) bool {
	return e.Run([]string{rt, "compose", "version"}).Code == 0
}

// UnprivilegedPortStart is the lowest port an unprivileged process may bind (Linux; rootless engines need <= 80).
func (e *Engine) UnprivilegedPortStart() (int, bool) {
	b, err := os.ReadFile(e.ProcRoot + "/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(py.Strip(string(b)))
	return n, err == nil
}

// EnsureNetwork creates the network if missing. internal: no route out and no external DNS (workspace networks).
func (e *Engine) EnsureNetwork(rt, name string, internal bool) bool {
	if e.Run([]string{rt, "network", "inspect", name}).Code == 0 {
		return true
	}
	cmd := []string{rt, "network", "create"}
	if internal {
		cmd = append(cmd, "--internal")
	}
	return e.Run(append(cmd, name)).Code == 0
}

// NetworkIsInternal reports whether the network has no route out.
func (e *Engine) NetworkIsInternal(rt, name string) bool {
	r := e.Run([]string{rt, "network", "inspect", "--format", "{{.Internal}}", name})
	return r.Code == 0 && strings.ToLower(py.Strip(r.Stdout)) == "true"
}

// NetworkSubnet returns the IPv4 subnet CIDR (e.g. "10.89.12.0/24") of the network, or "".
func (e *Engine) NetworkSubnet(rt, name string) string {
	r := e.Run([]string{rt, "network", "inspect", name})
	if r.Code != 0 {
		return ""
	}
	return subnetFrom(r.Stdout)
}

func subnetFrom(text string) string {
	var list []struct {
		Subnets []struct {
			Subnet string `json:"subnet"`
		} `json:"subnets"`
		IPAM struct {
			Config []struct {
				Subnet string `json:"Subnet"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if json.Unmarshal([]byte(text), &list) != nil || len(list) == 0 {
		return ""
	}
	for _, s := range list[0].Subnets {
		if s.Subnet != "" && !strings.Contains(s.Subnet, ":") {
			return s.Subnet
		}
	}
	for _, c := range list[0].IPAM.Config {
		if c.Subnet != "" && !strings.Contains(c.Subnet, ":") {
			return c.Subnet
		}
	}
	return ""
}

// ProjectNetworks returns the workspace's per-project networks: every service folder has its own.
func (e *Engine) ProjectNetworks(rt, ws string) []string {
	r := e.Run([]string{rt, "network", "ls", "--filter", "label=om.workspace=" + ws, "--format", "{{.Name}}"})
	if r.Code != 0 {
		return []string{}
	}
	set := map[string]bool{}
	for _, n := range strings.Fields(r.Stdout) {
		set[n] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ConnectRouter attaches the internal router to each workspace network and every project network of it, and the
// egress proxy only to those whose services may go out (om.egress). It returns the failures.
func (e *Engine) ConnectRouter(rt string, workspaceIDs []string) []string {
	failed := []string{}
	set := map[string]bool{}
	for _, w := range workspaceIDs {
		set[w] = true
	}
	ids := make([]string, 0, len(set))
	for w := range set {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	for _, wid := range ids {
		net := wid + "_net"
		if !e.EnsureNetwork(rt, net, true) {
			failed = append(failed, net)
			continue
		}
		nets := append([]string{net}, e.ProjectNetworks(rt, wid)...)
		egressOn, known := e.Reg.EgressNetworks(wid) // unknown before the workspace's first start: all
		for _, n := range nets {
			for _, c := range []string{state.Router, state.Egress, state.StreamRouter} {
				if c == state.Egress && known && !contains(egressOn, n) {
					// No service here may go out: the proxy is not even reachable from this network.
					e.Run([]string{rt, "network", "disconnect", n, c})
					continue
				}
				r := e.Run([]string{rt, "network", "connect", n, c})
				msg := strings.ToLower(r.Stderr + r.Stdout)
				if r.Code != 0 && !strings.Contains(msg, "already") && !strings.Contains(msg, "exists") {
					failed = append(failed, n+" ("+c+")")
				}
			}
		}
	}
	return failed
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (e *Engine) info(rt string) Info {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.infos == nil {
		e.infos = map[string]Info{}
	}
	if i, ok := e.infos[rt]; ok {
		return i
	}
	i := e.EngineInfo(rt)
	e.infos[rt] = i
	return i
}

func knownRuntime(rt string) bool { return rt == "podman" || rt == "docker" }

// localEngine: Podman or Docker running on this Linux host, so a container's pid can be looked up in /proc.
func (e *Engine) localEngine(rt string) bool {
	return knownRuntime(rt) && e.OS == "linux" && !e.info(rt).RemoteVM
}

// vmEngine: Podman machine / Docker Desktop: pids live in a VM, so ask the engine instead of /proc.
func (e *Engine) vmEngine(rt string) bool {
	return knownRuntime(rt) && !e.localEngine(rt) && e.info(rt).RemoteVM
}

var oomRE = regexp.MustCompile(`^-?\d{1,4}$`)

// unitOOMScoreAdj is the oom_score_adj systemd user units get (podman's healthcheck timers are such units), read
// from a throwaway unit; nil without a systemd user manager.
func (e *Engine) unitOOMScoreAdj() *int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.oomSet {
		return e.oomVal
	}
	e.oomSet = true
	if e.OS != "linux" {
		return nil
	}
	if _, err := e.LookPath("systemd-run"); err != nil {
		return nil
	}
	r := e.Run([]string{"systemd-run", "--user", "--wait", "--pipe", "--quiet", "--collect", "cat", "/proc/self/oom_score_adj"})
	if v := py.Strip(r.Stdout); r.Code == 0 && oomRE.MatchString(v) {
		n, _ := strconv.Atoi(v)
		e.oomVal = &n
	}
	return e.oomVal
}

// matchUnitOOM raises this process's oom_score_adj (inherited by the engine commands it runs) to the units'
// value. Raising needs no privilege; it is never lowered.
func (e *Engine) matchUnitOOM(procFile string) {
	target := e.unitOOMScoreAdj()
	if target == nil {
		return
	}
	b, err := os.ReadFile(procFile)
	if err != nil {
		return
	}
	cur, err := strconv.Atoi(py.Strip(string(b)))
	if err != nil || cur >= *target {
		return
	}
	_ = os.WriteFile(procFile, []byte(strconv.Itoa(*target)), 0o644)
}

// Lifecycle returns the command that starts or restarts containers (`start`, `restart`) with the engine CLI.
// Rootless Podman on Linux gives a container the oom_score_adj of whoever starts it, and runs its healthchecks
// from systemd user timers (oom_score_adj 200 by default). Started from a shell (0), the container then refuses
// those healthcheck execs and turns unhealthy. So for local Podman, om first raises its own oom_score_adj to
// the units' value. (Not by running podman inside a systemd unit: podman then keeps conmon in that unit, and
// systemd kills conmon when the unit ends.) Docker's daemon and Podman machine's VM start containers
// themselves, whoever asks, so there nothing changes.
func (e *Engine) Lifecycle(rt string, args ...string) []string {
	if rt == "podman" && e.localEngine(rt) {
		e.matchUnitOOM(e.ProcRoot + "/self/oom_score_adj")
	}
	return append([]string{rt}, args...)
}

// topFailed: `top` reads the container's processes through the engine; it fails for a container whose process
// is gone. Two failures 1.5 s apart, so a transient engine hiccup never restarts a healthy container.
func (e *Engine) topFailed(rt, name string) bool {
	for attempt := 0; attempt < 2; attempt++ {
		if e.Run([]string{rt, "top", name, "pid"}).Code == 0 {
			return false
		}
		if attempt == 0 {
			e.Sleep(1500 * time.Millisecond)
		}
	}
	return true
}

// processGone: the engine lists the container as running but its main process no longer exists. Podman learns
// of an exit only through the container's conmon; if conmon is killed the container shows 'Up' forever. A local
// engine is checked through /proc, a VM-based one through the engine (`top`).
func (e *Engine) processGone(rt, pid, name string) bool {
	if name != "" && e.vmEngine(rt) {
		return e.topFailed(rt, name)
	}
	n, err := strconv.Atoi(py.Strip(pid))
	if err != nil || n <= 0 || !e.localEngine(rt) {
		return false
	}
	_, err = os.Stat(e.ProcRoot + "/" + strconv.Itoa(n))
	return err != nil
}

// ContainerRunning reports a container that is running with a live process.
func (e *Engine) ContainerRunning(rt, name string) bool {
	r := e.Run([]string{rt, "container", "inspect", "-f", "{{.State.Running}} {{.State.Pid}}", name})
	if r.Code != 0 || !strings.Contains(strings.ToLower(r.Stdout), "true") {
		return false
	}
	f := strings.Fields(r.Stdout)
	if len(f) == 0 {
		return false
	}
	return !e.processGone(rt, f[len(f)-1], name)
}

type omContainer struct{ name, pid, coreLabel, wsLabel string }

func (c omContainer) isOM() bool {
	return notEmptyLabel(c.coreLabel) || notEmptyLabel(c.wsLabel)
}

func notEmptyLabel(s string) bool { s = py.Strip(s); return s != "" && s != "<no value>" }

const inspectFmt = `{{.Name}}|{{.State.Pid}}|{{index .Config.Labels "om.core"}}|{{index .Config.Labels "workspace.id"}}`

func (e *Engine) omContainers(rt string, names []string) []omContainer {
	info := e.Run(append([]string{rt, "container", "inspect", "-f", inspectFmt}, names...))
	var out []omContainer
	if info.Code != 0 {
		return out
	}
	for _, line := range strings.Split(strings.TrimSuffix(strings.ReplaceAll(info.Stdout, "\r\n", "\n"), "\n"), "\n") {
		if line == "" {
			continue
		}
		p := append(strings.Split(line, "|"), "", "", "", "")[:4]
		out = append(out, omContainer{strings.TrimLeft(p[0], "/"), p[1], p[2], p[3]})
	}
	return out
}

func (e *Engine) psNames(rt string) []string {
	r := e.Run([]string{rt, "ps", "--format", "{{.Names}}"})
	if r.Code != 0 {
		return nil
	}
	return strings.Fields(r.Stdout)
}

// ZombieContainers lists om's containers (core or workspace) listed as running whose process is gone.
func (e *Engine) ZombieContainers(rt string) []string {
	if !(e.localEngine(rt) || e.vmEngine(rt)) {
		return []string{}
	}
	names := e.psNames(rt)
	if len(names) == 0 {
		return []string{}
	}
	found := []string{}
	for _, c := range e.omContainers(rt, names) {
		if c.isOM() && e.processGone(rt, c.pid, c.name) {
			found = append(found, c.name)
		}
	}
	return found
}

// ReviveZombies restarts containers whose process died unseen. `stop` clears the stale 'running' record and
// `start` reuses the container exactly as created (same config, mounts, networks). A failed core container is
// removed so core up recreates it.
func (e *Engine) ReviveZombies(rt string) (revived, failed []string) {
	revived, failed = []string{}, []string{}
	for _, name := range e.ZombieContainers(rt) {
		e.Run([]string{rt, "stop", "-t", "0", name})
		if e.Run(e.Lifecycle(rt, "start", name)).Code == 0 {
			revived = append(revived, name)
			continue
		}
		failed = append(failed, name)
		if contains(state.CoreContainers, name) {
			e.Run([]string{rt, "rm", "-f", name})
		}
	}
	return revived, failed
}

// OMPids returns {pid: container name} of om's running containers (core or workspace). Containers sharing a pid
// overwrite each other, as in Python's dict.
func (e *Engine) OMPids(rt string) map[int]string {
	found := map[int]string{}
	names := e.psNames(rt)
	if len(names) == 0 {
		return found
	}
	for _, c := range e.omContainers(rt, names) {
		if n, err := strconv.Atoi(c.pid); err == nil && isASCIIDigits(c.pid) && n > 0 && c.isOM() {
			found[n] = c.name
		}
	}
	return found
}

func isASCIIDigits(s string) bool { return state.IsNumber(s) }

// Info is EngineInfo with the answer remembered per runtime (the engine's facts do not change during a run).
func (e *Engine) Info(rt string) Info { return e.info(rt) }
