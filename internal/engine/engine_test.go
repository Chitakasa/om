package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

func golden(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/golden/engine/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

type canned struct {
	Code int
	Out  string
}

// newFake answers commands from a prefix table (longest prefix wins) and records every call.
func newFake(osName string, table map[string]canned) (*Engine, *[][]string) {
	var calls [][]string
	e := &Engine{
		OS:       osName,
		Getenv:   func(string) string { return "" },
		Sleep:    func(time.Duration) {},
		ProcRoot: "/nonexistent-proc",
		LookPath: func(string) (string, error) { return "", errors.New("none") },
		Run: func(c []string) state.Result {
			calls = append(calls, append([]string(nil), c...))
			k := strings.Join(c, " ")
			best := ""
			for p := range table {
				if strings.HasPrefix(k, p) && len(p) > len(best) {
					best = p
				}
			}
			if best == "" {
				return state.Result{Code: 127, Stderr: "nf"}
			}
			return state.Result{Code: table[best].Code, Stdout: table[best].Out}
		},
	}
	return e, &calls
}

func TestVMSocketMatchesPython(t *testing.T) {
	var g struct {
		Cases map[string]string
		Want  map[string]string
	}
	golden(t, "vm_socket.json", &g)
	for k, in := range g.Cases {
		if got := VMSocketFromConnections(in); got != g.Want[k] {
			t.Errorf("%s: %q want %q", k, got, g.Want[k])
		}
	}
}

func TestEngineInfoMatchesPython(t *testing.T) {
	var g map[string]struct {
		Table   map[string]json.RawMessage
		OS      string
		Runtime string
		Info    struct {
			Runtime   string
			Ok        bool
			Rootless  bool
			Remote_vm bool
			Socket    string
		}
	}
	golden(t, "engine_info.json", &g)
	for name, c := range g {
		table := map[string]canned{}
		for k, raw := range c.Table {
			var m struct {
				Rc  int
				Out string
			}
			json.Unmarshal(raw, &m)
			table[k] = canned{m.Rc, m.Out}
		}
		e, _ := newFake(c.OS, table)
		got := e.EngineInfo(c.Runtime)
		want := Info{c.Info.Runtime, c.Info.Ok, c.Info.Rootless, c.Info.Remote_vm, c.Info.Socket}
		// the Python run was on a host with uid 1000; podman without a socket falls back to /run/user/<uid>
		// (no uid on Windows: no fallback)
		if strings.HasPrefix(want.Socket, "/run/user/1000/") {
			if os.Getuid() >= 0 {
				want.Socket = "/run/user/" + strconv.Itoa(os.Getuid()) + strings.TrimPrefix(want.Socket, "/run/user/1000")
			} else {
				want.Socket = ""
			}
		}
		if got != want {
			t.Errorf("%s:\n go     %+v\n python %+v", name, got, want)
		}
	}
}

func TestSubnetMatchesPython(t *testing.T) {
	var g struct {
		Cases map[string]string
		Want  map[string]*string
	}
	golden(t, "subnet.json", &g)
	for k, in := range g.Cases {
		e, _ := newFake("linux", map[string]canned{"podman network inspect": {0, in}})
		want := ""
		if g.Want[k] != nil {
			want = *g.Want[k]
		}
		if got := e.NetworkSubnet("podman", "n"); got != want {
			t.Errorf("%s: %q want %q", k, got, want)
		}
	}
	e, _ := newFake("linux", nil)
	if e.NetworkSubnet("podman", "n") != "" {
		t.Fatal("failed inspect")
	}
}

func TestConnectRouterMatchesPython(t *testing.T) {
	var g struct {
		Failed []string
		Calls  [][]string
	}
	golden(t, "connect_router.json", &g)
	t.Setenv("OM_STATE_DIR", t.TempDir())
	reg := registry.New(state.NewDirs())
	reg.SetEgressNetworks("b", []string{"b_net_web"})
	e, calls := newFake("linux", nil)
	base := e.Run
	e.Reg = reg
	e.Run = func(c []string) state.Result {
		base(c)
		k := strings.Join(c, " ")
		switch {
		case strings.HasPrefix(k, "podman network inspect"):
			return state.Result{Stdout: "[]"}
		case strings.HasPrefix(k, "podman network ls"):
			if strings.Contains(k, "om.workspace=b") {
				return state.Result{Stdout: "b_net_web\nb_net_db\nb_net_web\n"}
			}
			return state.Result{}
		case strings.HasPrefix(k, "podman network connect"):
			if c[len(c)-2] == "x_net" {
				return state.Result{Code: 1}
			}
		}
		return state.Result{}
	}
	failed := e.ConnectRouter("podman", []string{"b", "a", "b"})
	if len(failed) != len(g.Failed) {
		t.Errorf("failed %v want %v", failed, g.Failed)
	}
	if !reflect.DeepEqual(*calls, g.Calls) {
		t.Errorf("calls differ\n go:     %v\n python: %v", *calls, g.Calls)
	}
}

func TestConnectRouterReportsRealFailures(t *testing.T) {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	e, _ := newFake("linux", nil)
	e.Reg = registry.New(state.NewDirs())
	e.Run = func(c []string) state.Result {
		k := strings.Join(c, " ")
		switch {
		case strings.HasPrefix(k, "podman network inspect"):
			return state.Result{Code: 1}
		case k == "podman network create --internal bad_net":
			return state.Result{Code: 1}
		}
		return state.Result{}
	}
	if got := e.ConnectRouter("podman", []string{"bad"}); !reflect.DeepEqual(got, []string{"bad_net"}) {
		t.Fatal(got)
	}
	e.Run = func(c []string) state.Result {
		if c[1] == "network" && c[2] == "connect" {
			return state.Result{Code: 1, Stdout: "Error: network is Already attached"}
		}
		return state.Result{}
	}
	if got := e.ConnectRouter("podman", []string{"ok"}); len(got) != 0 {
		t.Fatalf("already-connected is not a failure: %v", got)
	}
}

func zombieEngine(t *testing.T) (*Engine, *[][]string, string, string) {
	var g struct{ Lines []string }
	golden(t, "zombies.json", &g)
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	const dead = "1073741824"
	inspect := strings.NewReplacer("ALIVE", "4242", "DEAD", dead).Replace(strings.Join(g.Lines, "\n")) + "\n"
	e, calls := newFake("linux", map[string]canned{
		"podman info":                           {0, "true|unix:///x.sock|false\n"},
		"podman ps":                             {0, "om_caddy\nweb\ndb\nstranger\nzero\njunk\n"},
		"podman container inspect -f {{.Name}}": {0, inspect},
		"podman container inspect -f {{.State.Running}}": {0, "true " + dead},
		"podman start om_caddy":                          {1, ""},
		"podman start web":                               {1, ""},
		"podman start":                                   {0, ""},
		"podman stop":                                    {0, ""},
		"podman rm":                                      {0, ""},
	})
	e.ProcRoot = proc
	return e, calls, "4242", dead
}

func TestZombiesAndReviveMatchPython(t *testing.T) {
	var g struct {
		Zombies     []string
		CallsZombie [][]string `json:"calls_zombie"`
		Revive      [][]string
		CallsRevive [][]string `json:"calls_revive"`
		OMPidsNames []string   `json:"om_pids_names"`
	}
	golden(t, "zombies.json", &g)
	e, calls, _, _ := zombieEngine(t)
	if z := e.ZombieContainers("podman"); !reflect.DeepEqual(z, g.Zombies) {
		t.Fatalf("zombies %v want %v", z, g.Zombies)
	}
	// Python's call list starts with the engine_info probe from its cached _local_engine; same order here
	if !reflect.DeepEqual(*calls, g.CallsZombie) {
		t.Errorf("calls\n go     %v\n python %v", *calls, g.CallsZombie)
	}
	*calls = nil
	rev, failed := e.ReviveZombies("podman")
	if !reflect.DeepEqual([][]string{rev, failed}, g.Revive) {
		t.Fatalf("revive %v %v want %v", rev, failed, g.Revive)
	}
	var sr [][]string
	for _, c := range *calls {
		if c[1] == "stop" || c[1] == "start" || c[1] == "rm" {
			sr = append(sr, c)
		}
	}
	if !reflect.DeepEqual(sr, g.CallsRevive) {
		t.Errorf("revive calls\n go     %v\n python %v", sr, g.CallsRevive)
	}
	var names []string
	for _, n := range e.OMPids("podman") {
		names = append(names, n)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, g.OMPidsNames) {
		t.Errorf("om pids %v want %v", names, g.OMPidsNames)
	}
}

func TestContainerRunningUsesProc(t *testing.T) {
	e, _, alive, dead := zombieEngine(t)
	e.Run = func(c []string) state.Result {
		switch {
		case strings.HasPrefix(strings.Join(c, " "), "podman info"):
			return state.Result{Stdout: "true|unix:///x.sock|false\n"}
		case c[len(c)-1] == "alive":
			return state.Result{Stdout: "true " + alive}
		case c[len(c)-1] == "stopped":
			return state.Result{Stdout: "false 0"}
		}
		return state.Result{Stdout: "true " + dead}
	}
	if !e.ContainerRunning("podman", "alive") || e.ContainerRunning("podman", "dead") || e.ContainerRunning("podman", "stopped") {
		t.Fatal("ContainerRunning")
	}
}

func TestVMEngineUsesTopWithRetry(t *testing.T) {
	var slept []time.Duration
	e, calls := newFake("darwin", map[string]canned{
		"podman info":                   {0, "true|unix:///c.sock|true\n"},
		"podman system connection list": {0, ""},
		"podman container inspect":      {0, "true 77"},
		"podman top web pid":            {1, ""},
		"podman top ok pid":             {0, ""},
	})
	e.Sleep = func(d time.Duration) { slept = append(slept, d) }
	if e.ContainerRunning("podman", "web") {
		t.Fatal("top failing twice means gone")
	}
	if len(slept) != 1 || slept[0] != 1500*time.Millisecond {
		t.Fatalf("one 1.5s pause between the two tries: %v", slept)
	}
	if !e.ContainerRunning("podman", "ok") {
		t.Fatal("top ok")
	}
	_ = calls
	if e.localEngine("podman") || !e.vmEngine("podman") {
		t.Fatal("classification")
	}
}

func TestLifecycleRaisesOOMScore(t *testing.T) {
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	f := filepath.Join(proc, "self", "oom_score_adj")
	os.WriteFile(f, []byte("0\n"), 0o644)
	e, _ := newFake("linux", map[string]canned{
		"podman info": {0, "true|unix:///x.sock|false\n"},
		"systemd-run": {0, "200\n"},
	})
	e.ProcRoot = proc
	e.LookPath = func(string) (string, error) { return "/usr/bin/systemd-run", nil }
	if got := e.Lifecycle("podman", "start", "x"); !reflect.DeepEqual(got, []string{"podman", "start", "x"}) {
		t.Fatal(got)
	}
	if b, _ := os.ReadFile(f); strings.TrimSpace(string(b)) != "200" {
		t.Fatalf("not raised: %q", b)
	}
	os.WriteFile(f, []byte("500\n"), 0o644) // never lowered
	e.Lifecycle("podman", "start", "x")
	if b, _ := os.ReadFile(f); strings.TrimSpace(string(b)) != "500" {
		t.Fatalf("lowered: %q", b)
	}
	// docker: nothing touched
	os.WriteFile(f, []byte("0\n"), 0o644)
	e.Lifecycle("docker", "start", "x")
	if b, _ := os.ReadFile(f); strings.TrimSpace(string(b)) != "0" {
		t.Fatal("docker must not change oom_score_adj")
	}
}

func TestSmallHelpers(t *testing.T) {
	e, _ := newFake("linux", map[string]canned{
		"podman --version": {0, "podman 5"}, "podman compose version": {0, ""},
		"podman network inspect --format": {0, "True\n"}, "podman network ls": {0, "z\na\nz\n"},
	})
	if e.DetectRuntime() != "podman" || !e.ComposeAvailable("podman") || !e.NetworkIsInternal("podman", "n") {
		t.Fatal("basic")
	}
	if got := e.ProjectNetworks("podman", "w"); !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Fatal(got)
	}
	e.Getenv = func(k string) string {
		if k == "OM_RUNTIME" {
			return "nerdctl"
		}
		return ""
	}
	if e.DetectRuntime() != "nerdctl" {
		t.Fatal("forced runtime")
	}
	none, _ := newFake("linux", nil)
	if none.DetectRuntime() != "podman" {
		t.Fatal("default is podman")
	}
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "sys/net/ipv4"), 0o755)
	os.WriteFile(filepath.Join(proc, "sys/net/ipv4/ip_unprivileged_port_start"), []byte("80\n"), 0o644)
	e.ProcRoot = proc
	if n, ok := e.UnprivilegedPortStart(); !ok || n != 80 {
		t.Fatal(n, ok)
	}
}
