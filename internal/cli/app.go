package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/core"
	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/firewall"
	"github.com/Chitakasa/om/internal/generations"
	"github.com/Chitakasa/om/internal/lock"
	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/network"
	"github.com/Chitakasa/om/internal/notify"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/routesync"
	"github.com/Chitakasa/om/internal/sched"
	"github.com/Chitakasa/om/internal/secrets"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/stream"
)

// ExitError ends the program: Msg (if any) goes to stderr, then the process exits with Code. It is Python's die().
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// Die is an error that prints msg and exits 1.
func Die(format string, a ...any) error { return &ExitError{Code: 1, Msg: fmt.Sprintf(format, a...)} }

// Exit is an error that exits with code and says nothing.
func Exit(code int) error { return &ExitError{Code: code} }

var ansiRE = regexp.MustCompile("\033\\[[0-9;]*m")

// ansiStripper drops colour codes when output is not a terminal or NO_COLOR is set.
type ansiStripper struct{ w io.Writer }

func (a ansiStripper) Write(p []byte) (int, error) {
	if _, err := a.w.Write(ansiRE.ReplaceAll(p, nil)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// App is the whole program with its dependencies. NewApp wires the real ones; tests build their own.
type App struct {
	D   state.Dirs
	Out io.Writer
	Err io.Writer
	In  *bufio.Reader

	Interactive bool // stdin is a terminal
	// OtherLoginUsers lists the other human accounts on this machine (replaced in tests; the default reads /etc/passwd).
	OtherLoginUsers func() []string
	StderrTTY       bool
	Getenv          func(string) string
	Now             func() time.Time
	Sleep           func(time.Duration)
	GOOS            string
	Version         string
	Parser          *Parser

	Reg    registry.Registry
	Eng    *engine.Engine
	Core   *core.Core
	Egress *egress.Egress
	Stream *stream.Stream
	Det    *netdetect.Detector
	FW     *firewall.Firewall
	Sched  *sched.Sched
	Notify *notify.Notifier
	Gen    *generations.Gen
	Lock   *lock.Lock
	Net    network.Net
	Syncer *routesync.Syncer
	Age    *secrets.Age
	Legacy *secrets.Legacy

	// Run runs a command and captures its output; RunIn does so in a directory with an environment; Passthrough runs
	// one with the terminal attached and returns its exit code.
	Run         func([]string) state.Result
	RunIn       func(cmd []string, dir string, env []string) state.Result
	Passthrough func(cmd []string, dir string, env []string) int
	// LookPath finds a program.
	LookPath func(string) (string, error)
}

// Printf writes a line (the newline is added).
func (a *App) p(format string, args ...any) { fmt.Fprintf(a.Out, format+"\n", args...) }

// Print writes text as is.
func (a *App) print(s string) { fmt.Fprint(a.Out, s) }

// Settings loads om.env with the template defaults.
func (a *App) Settings() settings.Settings {
	s, _ := settings.Load(a.D)
	return s
}

// Runtime is the container engine to use: podman (OM_RUNTIME names another program for the tests).
func (a *App) Runtime() string { return a.Eng.DetectRuntime() }

// BaseURL is the http URL of a host on the private tier.
func (a *App) BaseURL(host string) string { return a.Settings().BaseURL(host) }

// Confirm asks a yes/no question; without a terminal the answer is no.
func (a *App) Confirm(question string) bool {
	if !a.Interactive {
		return false
	}
	fmt.Fprintf(a.Out, "%s [y/N] ", question)
	line, _ := a.In.ReadString('\n')
	switch strings.ToLower(py.Strip(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// EmitJSON prints machine-readable output: json.dumps(obj, indent=2, sort_keys=True).
func (a *App) EmitJSON(obj any) { fmt.Fprintln(a.Out, py.Dumps(obj)) }

func (a *App) workspaceRoot() (string, bool) { return findRoot() }

// NewApp wires the real program.
func NewApp(version string, in io.Reader, out, errOut io.Writer) *App {
	d := state.NewDirs()
	a := &App{D: d, Err: errOut, In: bufio.NewReader(in), Getenv: os.Getenv, Now: time.Now, Sleep: time.Sleep, GOOS: runtime.GOOS, Version: version}
	a.Interactive = isTerminal(os.Stdin)
	a.StderrTTY = isTerminal(os.Stderr)
	if os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stdout) {
		a.Out = ansiStripper{out}
	} else {
		a.Out = out
	}
	a.LookPath = exec.LookPath
	a.Run = func(c []string) state.Result { return state.Run(c) }
	a.RunIn = func(c []string, dir string, env []string) state.Result {
		var opts []func(*exec.Cmd)
		if dir != "" {
			opts = append(opts, state.WithDir(dir))
		}
		if env != nil {
			opts = append(opts, state.WithEnv(env))
		}
		return state.Run(c, opts...)
	}
	a.Passthrough = func(c []string, dir string, env []string) int {
		x := exec.Command(c[0], c[1:]...)
		x.Dir, x.Env = dir, env
		x.Stdin, x.Stdout, x.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := x.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			return 127
		}
		return 0
	}
	a.wire()
	return a
}

// wire builds the services from the run functions and the directories.
func (a *App) wire() {
	d := a.D
	a.Reg = registry.New(d)
	a.Eng = engine.New(a.Reg)
	a.Eng.Run = a.Run
	a.Det = netdetect.Real()
	a.Det.Run = a.Run
	a.Egress = egress.New(d)
	a.Egress.Run = a.Run
	a.Stream = stream.New(d, a.Eng)
	a.Stream.Run = a.Run
	a.Gen = generations.New(d)
	a.Lock = lock.New(d)
	a.Lock.Run = a.Run
	a.Notify = notify.New(d)
	a.Egress.Notify = func(title, body, key string) { a.Notify.Notify(title, body, key) }
	a.Age = secrets.NewAge(d)
	a.Age.Run = a.Run
	a.Legacy = secrets.NewLegacy()
	a.FW = firewall.New(d, a.Reg, a.GOOS)
	a.FW.Run = a.Run
	a.FW.Out = a.Out
	a.FW.EdgePorts = func() (int, int) { return a.Settings().EdgePorts() }
	a.FW.VPNIPs = func() []string { return a.Settings().Resolve(a.D, a.Det).VPNIPs }
	a.FW.VPNAllow = func() []string { return a.Settings().VPNAllow() }
	a.FW.ExtraTCP = func() string { return a.Settings().Get("OM_FIREWALL_EXTRA_TCP", "") }
	a.FW.ExtraUDP = func() string { return a.Settings().Get("OM_FIREWALL_EXTRA_UDP", "") }
	exe, _ := os.Executable()
	a.Sched = sched.New(a.GOOS, d.Home, []string{exe})
	a.Sched.Run = a.Run
	a.Sched.Out = a.Out
	a.Core = &core.Core{D: d, Reg: a.Reg, Eng: a.Eng, Egress: a.Egress, Stream: a.Stream, Det: a.Det, FW: a.FW, Out: a.Out,
		Settings: a.Settings, Run: a.Run, Now: a.Now, Sleep: a.Sleep, ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup", GOOS: a.GOOS,
		Hostname: func() string { h, _ := os.Hostname(); return h }}
	a.Core.DashboardBinary = func() (string, error) { return linuxBinary(exe, a.GOOS) }
	core.DefaultRunners(a.Core)
	a.Core.Run = a.Run
	a.Core.NewWatcher = core.NewLinuxWatcher(a.Eng)
	a.Net = network.Net{D: d, Eng: a.Eng}
	a.Syncer = &routesync.Syncer{D: d, Reg: a.Reg, Eng: a.Eng, Stream: a.Stream, Out: a.Out,
		Run:               func(cmd []string, dir string, env []string) state.Result { return a.RunIn(cmd, dir, env) },
		VPNAllow:          func() []string { return a.Settings().VPNAllow() },
		NetPolicyEnforced: func(key string, pol map[string]any) bool { return a.FW.NetPolicyEnforced(key, pol) },
		ReloadCaddy:       func(rt, ws string, quiet bool) bool { return a.Core.ReloadCaddy(rt, ws, quiet) }}
	a.Parser = NewParser(a.Version, a.D)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func findRoot() (string, bool) {
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	cur, err := filepath.EvalSymlinks(wd)
	if err != nil {
		cur = wd
	}
	for {
		if st, err := os.Stat(filepath.Join(cur, ".om", "config.json")); err == nil && !st.IsDir() {
			return cur, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
		cur = parent
	}
}

func isTerminal(f *os.File) bool { return isatty(f) }

func settingsVPNHosts(d state.Dirs) []string { return settings.VPNHosts(d) }

// registry_Workspaces is the registry's map type, named here so the command files read well.
type registry_Workspaces = registry.Workspaces

// ensureNet makes sure the workspace network exists and prints what Python's ensure_workspace_network printed.
func (a *App) ensureNet(wsID, rt string) {
	_, lines := a.Net.EnsureWorkspaceNetwork(wsID, rt)
	for _, l := range lines {
		a.p("%s", l)
	}
}

// linuxBinary is the om binary the dashboard container runs: this one on Linux, else the om-linux-<arch> file the
// installer puts next to it (the engine runs in a Linux VM).
func linuxBinary(exe, goos string) (string, error) {
	if goos == "linux" {
		return exe, nil
	}
	p := filepath.Join(filepath.Dir(exe), "om-linux-"+runtime.GOARCH)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%s is missing (the dashboard container needs a Linux build of om)", p)
	}
	return p, nil
}
