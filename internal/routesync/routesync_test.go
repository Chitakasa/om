package routesync

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/policy"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/stream"
	"github.com/Chitakasa/om/internal/workspace"
)

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

type specStep struct {
	Op      string
	WS      string `json:"ws"`
	Rel     string
	Text    string
	Name    string
	Key     string
	Value   bool
	Force   bool
	Quiet   bool
	Reload  bool
	Configs map[string]map[string]any
}

func snapshot(t *testing.T, state string) map[string]any {
	out := map[string]any{}
	for _, sub := range []string{"routes", "registry", "stream"} {
		base := filepath.Join(state, sub)
		filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
			if err != nil || !info.Mode().IsRegular() || strings.HasSuffix(p, ".lock") || strings.HasSuffix(p, ".tmp") || strings.HasSuffix(p, "workspaces.json") {
				return nil
			}
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(base, p)
			key := sub + "/" + filepath.ToSlash(rel)
			if strings.HasSuffix(p, ".json") { // Go writes keys sorted, Python in insertion order: equal as JSON
				var v any
				dec := json.NewDecoder(bytes.NewReader(b))
				dec.UseNumber()
				dec.Decode(&v)
				out[key] = v
			} else {
				out[key] = string(b)
			}
			return nil
		})
	}
	return out
}

func TestScenarioMatchesPython(t *testing.T) {
	var spec struct {
		Workspaces map[string]struct {
			Dir   string
			Files map[string]string
		}
		Enforced  map[string]bool
		PSRunning []string `json:"ps_running"`
		Steps     []specStep
	}
	readJSON(t, "../../testdata/routesync_spec.json", &spec)
	var golden struct {
		Steps []struct {
			Op      string
			Result  any
			Stdout  string
			Files   map[string]any
			Reloads [][]any
		}
	}
	readJSON(t, "../../testdata/golden/routesync.json", &golden)
	for _, g := range golden.Steps { // JSON files compare as JSON (see snapshot)
		for k, v := range g.Files {
			if str, ok := v.(string); ok && strings.HasSuffix(k, ".json") {
				var parsed any
				dec := json.NewDecoder(strings.NewReader(str))
				dec.UseNumber()
				dec.Decode(&parsed)
				g.Files[k] = parsed
			}
		}
	}

	tmp := t.TempDir()
	t.Setenv("OM_STATE_DIR", filepath.Join(tmp, "state"))
	t.Setenv("OM_CONFIG_DIR", filepath.Join(tmp, "cfg"))
	t.Setenv("OM_HOME", filepath.Join(tmp, "home"))
	d := state.NewDirs()
	reg := registry.New(d)
	running := map[string]bool{}
	for _, w := range spec.PSRunning {
		running[w] = true
	}
	run := func(c []string) state.Result {
		k := strings.Join(c, " ")
		if i := strings.Index(k, " ps -q --filter label=workspace.id="); i >= 0 {
			if running[k[strings.LastIndex(k, "=")+1:]] {
				return state.Result{Stdout: "abc123\n"}
			}
			return state.Result{}
		}
		return state.Result{Code: 127}
	}
	eng := &engine.Engine{Run: run, OS: "linux", Reg: reg, Getenv: func(string) string { return "" }, ProcRoot: "/nonexistent"}
	st := &stream.Stream{D: d, Eng: eng, Run: run, LookPath: func(string) (string, error) { return "", errors.New("none") }}
	enforced := spec.Enforced
	var reloads [][]any
	var out bytes.Buffer
	s := &Syncer{D: d, Reg: reg, Eng: eng, Stream: st, Out: &out,
		Run:      func([]string, string, []string) state.Result { return state.Result{Code: 127} },
		VPNAllow: func() []string { return nil },
		NetPolicyEnforced: func(key string, _ map[string]any) bool {
			v, ok := enforced[key]
			return !ok || v
		},
		ReloadCaddy: func(_, ws string, quiet bool) bool {
			var w any = ws
			if ws == "" {
				w = nil
			}
			reloads = append(reloads, []any{w, quiet})
			return true
		},
	}
	roots := map[string]string{}
	for name, w := range spec.Workspaces {
		r := filepath.Join(tmp, w.Dir)
		roots[name] = r
		for rel, text := range w.Files {
			p := filepath.Join(r, filepath.FromSlash(rel))
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(text), 0o644)
		}
		if err := workspace.Register(reg, r, name); err != nil {
			t.Fatal(err)
		}
	}
	for i, step := range spec.Steps {
		g := golden.Steps[i]
		out.Reset()
		n0 := len(reloads)
		var res any
		switch step.Op {
		case "sync":
			var configs map[string]map[string]any
			if step.Configs != nil {
				configs = map[string]map[string]any{}
				for rel, c := range step.Configs {
					configs[filepath.Join(roots[step.WS], rel)] = c
				}
			}
			changed, err := s.SyncCaddyRoutes(roots[step.WS], "om-test-no-engine", true, configs)
			if err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			res = changed
		case "remove_dir":
			os.RemoveAll(filepath.Join(roots[step.WS], step.Rel))
		case "write":
			os.WriteFile(filepath.Join(roots[step.WS], filepath.FromSlash(step.Rel)), []byte(step.Text), 0o644)
		case "set_enforced":
			enforced[step.Key] = step.Value
		case "plant":
			os.WriteFile(filepath.Join(d.Routes, step.Name), []byte(step.Text), 0o644)
		case "orphans":
			p, r := s.OrphanRouteOwners("om-test-no-engine")
			conv := func(o Orphans) map[string]any {
				m := map[string]any{}
				for ws, files := range o.Files {
					l := []any{}
					for _, f := range files {
						l = append(l, filepath.Base(f))
					}
					m[ws] = l
				}
				return m
			}
			res = map[string]any{"prunable": conv(p), "running": conv(r)}
		case "prune":
			removed, err := s.PruneOrphanRoutes("om-test-no-engine", step.Reload, step.Quiet, step.Force)
			if err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			l := []any{}
			for _, f := range removed {
				l = append(l, filepath.Base(f))
			}
			res = l
		}
		if g.Result != nil && !reflect.DeepEqual(res, g.Result) {
			t.Errorf("step %d %s: result %v, python %v", i, step.Op, res, g.Result)
		}
		if normOut(out.String()) != normOut(g.Stdout) {
			t.Errorf("step %d %s: output\n go:\n%q\n python:\n%q", i, step.Op, out.String(), g.Stdout)
		}
		got := snapshot(t, d.State)
		if !reflect.DeepEqual(got, g.Files) {
			for k, v := range g.Files {
				if !reflect.DeepEqual(got[k], v) {
					t.Errorf("step %d %s: %s\n go:\n%v\n python:\n%v", i, step.Op, k, got[k], v)
				}
			}
			for k := range got {
				if _, ok := g.Files[k]; !ok {
					t.Errorf("step %d %s: extra %s", i, step.Op, k)
				}
			}
		}
		gotReloads := reloads[n0:]
		if len(gotReloads) != len(g.Reloads) || (len(gotReloads) > 0 && !reflect.DeepEqual(gotReloads, g.Reloads)) {
			t.Errorf("step %d %s: reloads %v, python %v", i, step.Op, gotReloads, g.Reloads)
		}
	}
}

func TestRouteOwner(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"a.caddy": "# ======\n# Service: web (alpha)\nx\n",
		"b.alias": "# Private Alias: web (beta)\n",
		"c.caddy": "x\ny\nz\n# Service: late (gamma)\n",
		"d.caddy": "x\ny\nz\nw\n# Service: toolate (delta)\n",
		"e.caddy": "# Service: Bad (Eps)\n",
		"f.caddy": "# Service: web (a-b)\r\n",
		"g.caddy": "\xff\xfe# Service: web (z)\n",
	}
	want := map[string]string{"a.caddy": "alpha", "b.alias": "beta", "c.caddy": "gamma", "d.caddy": "", "e.caddy": "", "f.caddy": "a-b", "g.caddy": ""}
	for name, text := range cases {
		os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644)
		if got := RouteOwner(filepath.Join(dir, name)); got != want[name] {
			t.Errorf("%s: %q want %q", name, got, want[name])
		}
	}
	if RouteOwner(filepath.Join(dir, "missing")) != "" {
		t.Error("missing file has no owner")
	}
	_ = py.Strip
	_ = policy.DefaultRun
}

// Python lists a directory in whatever order the filesystem gives, so which of two conflicting alias files it names
// first and the order of "Removed stale route" lines vary between runs; Go sorts. Compare modulo that.
func normOut(s string) string {
	lines := strings.Split(s, "\n")
	var stale []string
	var rest []string
	for _, l := range lines {
		if strings.Contains(l, "Removed stale route") {
			stale = append(stale, l)
			continue
		}
		l = strings.ReplaceAll(l, "alpha-web.private_alias", "alpha-web.X_alias")
		l = strings.ReplaceAll(l, "alpha-web.public_alias", "alpha-web.X_alias")
		rest = append(rest, l)
	}
	sort.Strings(stale)
	return strings.Join(rest, "\n") + "\n" + strings.Join(stale, "\n")
}
