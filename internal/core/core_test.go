package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/firewall"
	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/stream"
)

type specStep struct {
	Op       string
	Recreate bool
	Quiet    bool
	Now      *float64
	WS       string
	Table    map[string][]any
	Drop     []string
	ClockAdd float64 `json:"clock_add"`
	Write    map[string]string
	Remove   []string
}

type specCase struct {
	Name  string
	Setup struct {
		Files    map[string]string
		OMEnv    string `json:"om_env"`
		Registry []string
		Table    map[string][]any
		Clock    *float64
	}
	Steps []specStep
}

func loadJSON(t *testing.T, path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestCoreMatchesPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the goldens were recorded on POSIX and hold / paths")
	}
	var spec struct{ Cases []specCase }
	loadJSON(t, "../../testdata/core_spec.json", &spec)
	var gold struct {
		Cases []struct {
			Name  string
			Steps []struct {
				Result any
				Stdout string
				Calls  [][]string
			}
			Files map[string]string
			Clock float64
		}
	}
	loadJSON(t, "../../testdata/golden/core.json", &gold)
	clock := 1_700_000_000.0
	for ci, sc := range spec.Cases {
		g := gold.Cases[ci]
		t.Run(sc.Name, func(t *testing.T) {
			T := t.TempDir()
			t.Setenv("OM_HOME", filepath.Join(T, "home"))
			t.Setenv("OM_STATE_DIR", filepath.Join(T, "state"))
			t.Setenv("OM_CONFIG_DIR", filepath.Join(T, "cfg"))
			put := func(rel, text string) {
				p := filepath.Join(T, filepath.FromSlash(rel))
				os.MkdirAll(filepath.Dir(p), 0o755)
				os.WriteFile(p, []byte(text), 0o644)
			}
			for rel, text := range sc.Setup.Files {
				put(rel, text)
			}
			omEnv := sc.Setup.OMEnv
			if omEnv == "" {
				omEnv = "OM_LAN_IP=192.168.1.10\nOM_WALLPAPERS_DIR=" + filepath.Join(T, "wp") + "\n"
			}
			defaults := map[string]string{"home/core/egress/Containerfile": "FROM x\n", "home/core/compose.yml": "services: {}\n",
				"home/core/caddy/Caddyfile": "# caddyfile\n", "state/data/edge_token": strings.Repeat("a", 64) + "\n", "cfg/om.env": omEnv}
			for rel, text := range defaults {
				if _, err := os.Stat(filepath.Join(T, filepath.FromSlash(rel))); err != nil {
					put(rel, text)
				}
			}
			if sc.Setup.Registry != nil {
				reg := map[string]any{}
				for _, k := range sc.Setup.Registry {
					put("ws/"+k+"/.om/config.json", "{}")
					reg[k] = map[string]any{"id": k, "path": filepath.Join(T, "ws", k)}
				}
				put("state/registry/workspaces.json", py.DumpsCompact(reg))
			}
			if sc.Setup.Clock != nil {
				clock = *sc.Setup.Clock
			}
			table := map[string][]any{}
			for k, v := range sc.Setup.Table {
				table[k] = v
			}
			var calls [][]string
			var out bytes.Buffer
			fake := func(cmd []string, cwd string) state.Result {
				rec := append([]string(nil), cmd...)
				if cwd != "" {
					rec = append(rec, "cwd="+filepath.Base(cwd))
				}
				calls = append(calls, rec)
				k := strings.Join(cmd, " ")
				best := ""
				for p := range table {
					if strings.HasPrefix(k, p) && len(p) > len(best) {
						best = p
					}
				}
				if best == "" {
					return state.Result{Code: 127, Stderr: "not found"}
				}
				v := table[best]
				r := state.Result{}
				if len(v) > 0 {
					c, _ := v[0].(json.Number).Int64()
					r.Code = int(c)
				}
				if len(v) > 1 {
					r.Stdout = v[1].(string)
				}
				if len(v) > 2 {
					r.Stderr = v[2].(string)
				}
				return r
			}
			run := func(cmd []string) state.Result { return fake(cmd, "") }
			d := state.NewDirs()
			reg := registry.New(d)
			now := func() time.Time {
				return time.Unix(int64(clock), int64((clock-float64(int64(clock)))*1e9))
			}
			eng := engine.New(reg)
			eng.Run, eng.Getenv = run, func(string) string { return "" }
			// the goldens were recorded on a host that lets rootless engines bind port 80; the runner's /proc must not decide
			put("proc/sys/net/ipv4/ip_unprivileged_port_start", "80\n")
			eng.ProcRoot = filepath.Join(T, "proc")
			eg := egress.New(d)
			eg.Run, eg.Now = run, now
			st := &stream.Stream{D: d, Eng: eng, Run: run, LookPath: func(string) (string, error) { return "", os.ErrNotExist }}
			det := &netdetect.Detector{OS: "linux", Run: run, ResolvConf: "/nonexistent", Hostname: func() (string, error) { return "MyBox.local", nil },
				PTR: func(string, string, time.Duration) string { return "" }, IsLocal: func(string) bool { return true }}
			load := func() settings.Settings { s, _ := settings.Load(d); return s }
			fw := firewall.New(d, reg, "linux")
			fw.Run = run
			fw.EdgePorts = func() (int, int) { return load().EdgePorts() }
			fw.VPNIPs = func() []string { s := load(); return s.Resolve(d, det).VPNIPs }
			fw.VPNAllow = func() []string { return load().VPNAllow() }
			fw.ExtraTCP = func() string { return load().Get("OM_FIREWALL_EXTRA_TCP", "") }
			fw.ExtraUDP = func() string { return load().Get("OM_FIREWALL_EXTRA_UDP", "") }
			c := &Core{D: d, Reg: reg, Eng: eng, Egress: eg, Stream: st, Det: det, FW: fw, Out: &out, Settings: load, Run: run,
				RunDir: fake, RunTTY: func(cmd []string, dir string) int { return fake(cmd, dir).Code }, Now: now,
				Sleep: func(dur time.Duration) { clock += dur.Seconds() }, Hostname: func() string { return "MyBox.local" },
				ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup", GOOS: "linux"}

			norm := func(s string) string { return strings.ReplaceAll(s, T, "@T@") }
			for si, step := range sc.Steps {
				gs := g.Steps[si]
				out.Reset()
				calls = nil
				var res any
				switch step.Op {
				case "up":
					ok, err := c.Up("podman", step.Recreate, step.Quiet)
					if err != nil {
						t.Fatal(err)
					}
					res = ok
				case "down":
					ok, err := c.Down("podman")
					if err != nil {
						t.Fatal(err)
					}
					res = ok
				case "heal":
					s, err := c.Heal("podman")
					if err != nil {
						t.Fatal(err)
					}
					res = s
				case "drift":
					l := []any{}
					for _, x := range c.RuntimeDrift() {
						l = append(l, x)
					}
					res = l
				case "running":
					res = c.Running("podman")
				case "restart_unhealthy":
					n := 0.0
					if step.Now != nil {
						n = *step.Now
					}
					l, err := c.RestartUnhealthy("podman", n)
					if err != nil {
						t.Fatal(err)
					}
					a := []any{}
					for _, x := range l {
						a = append(a, x)
					}
					res = a
				case "runtime_files":
					if _, err := c.WriteRuntimeFiles("podman"); err != nil {
						t.Fatal(err)
					}
					res = json.Number("10")
				case "reload_caddy":
					res = c.ReloadCaddy("podman", step.WS, step.Quiet)
				case "preflight":
					l := []any{}
					for _, x := range c.Preflight("podman") {
						l = append(l, x)
					}
					res = l
				case "prereq":
					if err := c.EnsureCorePrerequisites(); err != nil {
						t.Fatal(err)
					}
				case "set":
					for k, v := range step.Table {
						table[k] = v
					}
					for _, k := range step.Drop {
						delete(table, k)
					}
					clock += step.ClockAdd
					for rel, text := range step.Write {
						if text == "@REGISTRY_WITH_GAMMA@" {
							m := map[string]any{}
							for _, k := range []string{"alpha", "beta", "gamma"} {
								m[k] = map[string]any{"id": k, "path": filepath.Join(T, "ws", k)}
							}
							text = py.DumpsCompact(m)
						}
						put(rel, text)
					}
					for _, rel := range step.Remove {
						os.Remove(filepath.Join(T, filepath.FromSlash(rel)))
					}
				}
				label := sc.Name + "#" + step.Op
				if step.Op == "preflight" || step.Op == "drift" || step.Op == "restart_unhealthy" {
					// compare only the shape of lists the Python run produced on this machine
					if got, want := mustJSON(res), mustJSON(gs.Result); got != want {
						t.Errorf("%s: result %s, python %s", label, got, want)
					}
				} else if step.Op == "runtime_files" {
					// the count of keys of the resolved dict is a Python implementation detail
				} else if !reflect.DeepEqual(res, gs.Result) && !(res == nil && gs.Result == nil) {
					t.Errorf("%s: result %v, python %v", label, res, gs.Result)
				}
				if got := norm(out.String()); got != gs.Stdout {
					t.Errorf("%s: output\n go:\n%s\n python:\n%s", label, got, gs.Stdout)
				}
				// Python asks the engine about itself on every use, Go remembers the answer: ignore those probes
				dropInfo := func(cs [][]string) [][]string {
					var o [][]string
					for _, c := range cs {
						if !strings.HasPrefix(strings.Join(c, " "), "podman info --format") {
							o = append(o, c)
						}
					}
					return o
				}
				gs.Calls = dropInfo(gs.Calls)
				var gotCalls [][]string
				for _, cl := range dropInfo(calls) {
					var n []string
					for _, a := range cl {
						n = append(n, norm(a))
					}
					gotCalls = append(gotCalls, n)
				}
				if !reflect.DeepEqual(gotCalls, gs.Calls) && !(len(gotCalls) == 0 && len(gs.Calls) == 0) {
					t.Errorf("%s: calls\n go     %v\n python %v", label, gotCalls, gs.Calls)
				}
			}
			files := map[string]string{}
			base := filepath.Join(T, "state")
			filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
				if err == nil && info.Mode().IsRegular() && !strings.HasSuffix(p, ".lock") && !strings.Contains(p, "fragments") && !strings.HasSuffix(p, ".tmp") {
					b, _ := os.ReadFile(p)
					rel, _ := filepath.Rel(base, p)
					files["state/"+filepath.ToSlash(rel)] = norm(string(b))
				}
				return nil
			})
			if !reflect.DeepEqual(files, g.Files) {
				for k, v := range g.Files {
					if files[k] != v {
						t.Errorf("%s: file %s\n go:\n%s\n python:\n%s", sc.Name, k, files[k], v)
					}
				}
				for k := range files {
					if _, ok := g.Files[k]; !ok {
						t.Errorf("%s: extra file %s", sc.Name, k)
					}
				}
			}
		})
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

type fakeWatcher struct {
	rounds [][]string
	i      int
	count  int
	refr   int
}

func (f *fakeWatcher) Refresh() { f.refr++ }
func (f *fakeWatcher) Wait() ([]string, bool) {
	if f.i >= len(f.rounds) {
		return nil, true
	}
	r := f.rounds[f.i]
	f.i++
	return r, false
}
func (f *fakeWatcher) Count() int { return f.count }
func (f *fakeWatcher) Close()     {}

func TestWatchLoop(t *testing.T) {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	d := state.NewDirs()
	reg := registry.New(d)
	var cmds []string
	run := func(c []string) state.Result {
		k := strings.Join(c, " ")
		cmds = append(cmds, k)
		switch {
		case strings.HasPrefix(k, "podman info"):
			return state.Result{Stdout: "true|unix:///x|false\n"}
		case strings.HasPrefix(k, "podman ps --format"):
			return state.Result{Stdout: "web\n"}
		case strings.HasPrefix(k, "podman container inspect -f {{.Name}}"):
			return state.Result{Stdout: "/web|1073741824||ws\n"} // a process that does not exist
		case strings.HasPrefix(k, "podman start"):
			return state.Result{}
		}
		return state.Result{}
	}
	eng := engine.New(reg)
	eng.Run, eng.Getenv = run, func(string) string { return "" }
	eng.ProcRoot = t.TempDir() // no process of any pid exists (macOS and Windows have no /proc)
	var out bytes.Buffer
	var slept []time.Duration
	c := &Core{D: d, Reg: reg, Eng: eng, Out: &out, Run: run, GOOS: "linux",
		Now:   func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		Sleep: func(x time.Duration) { slept = append(slept, x) }}
	fw := &fakeWatcher{rounds: [][]string{{"web"}, {"web"}}, count: 3}
	c.NewWatcher = func(string) (Watcher, error) { return fw, nil }
	if code := c.Watch("podman", 1); code != 0 {
		t.Fatalf("code %d", code)
	}
	got := out.String()
	if !strings.Contains(got, "[2026-01-02 03:04:05] watching 3 container(s)") ||
		!strings.Contains(got, "[2026-01-02 03:04:05] process of web died unseen; restarted ['web']") {
		t.Fatalf("output:\n%s", got)
	}
	if len(slept) != 1 || slept[0] != 2*time.Second {
		t.Fatalf("it waits 2 s for the engine to record a normal exit: %v", slept)
	}
	if fw.refr != 2 { // once at start, once after the exit
		t.Fatalf("refreshes %d", fw.refr)
	}
	// not Linux, or no watcher: it says so and exits 1
	out.Reset()
	c.GOOS = "darwin"
	if c.Watch("podman", 1) != 1 || !strings.Contains(out.String(), "om core watch needs Linux") {
		t.Fatal(out.String())
	}
}

func TestMemorySnapshot(t *testing.T) {
	T := t.TempDir()
	t.Setenv("OM_STATE_DIR", filepath.Join(T, "state"))
	d := state.NewDirs()
	reg := registry.New(d)
	run := func(c []string) state.Result {
		k := strings.Join(c, " ")
		switch {
		case strings.HasPrefix(k, "podman info"):
			return state.Result{Stdout: "true|unix:///x|false\n"}
		case strings.HasPrefix(k, "podman ps --format"):
			return state.Result{Stdout: "om_caddy\nweb\n"}
		case strings.HasPrefix(k, "podman container inspect -f {{.Name}}"):
			return state.Result{Stdout: "/om_caddy|4242|true|\n/web|4243||ws\n"}
		}
		return state.Result{}
	}
	eng := engine.New(reg)
	eng.Run, eng.Getenv = run, func(string) string { return "" }
	proc, cg := filepath.Join(T, "proc"), filepath.Join(T, "cgroup")
	eng.ProcRoot = proc
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	os.WriteFile(filepath.Join(proc, "4242", "cgroup"), []byte("1:name=x:/foo\n0::/user.slice/u.service/libpod-abc.scope/container\n"), 0o644)
	scope := filepath.Join(cg, "user.slice", "u.service", "libpod-abc.scope")
	os.MkdirAll(scope, 0o755)
	os.WriteFile(filepath.Join(scope, "memory.stat"), []byte("anon 12345\nfile 999\n"), 0o644)
	c := &Core{D: d, Reg: reg, Eng: eng, Run: run, GOOS: "linux", ProcRoot: proc, CgroupRoot: cg,
		Now: func() time.Time { return time.Unix(1_700_000_000, 500_000_000) }}
	c.WriteMemorySnapshot("podman")
	b, err := os.ReadFile(filepath.Join(d.State, "registry", "core_memory.json"))
	if err != nil || string(b) != `{"ts": 1700000000.5, "anon": {"om_caddy": 12345}}`+"\n" {
		t.Fatalf("%q %v", b, err)
	}
	os.Remove(filepath.Join(scope, "memory.stat")) // nothing readable: no file is written
	os.Remove(filepath.Join(d.State, "registry", "core_memory.json"))
	c.WriteMemorySnapshot("podman")
	if _, err := os.Stat(filepath.Join(d.State, "registry", "core_memory.json")); err == nil {
		t.Fatal("no data, no snapshot")
	}
}
