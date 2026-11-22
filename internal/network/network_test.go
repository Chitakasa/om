package network

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

type canned struct {
	Code int
	Out  string
}

// fakeEngine answers by longest command prefix (default: success, no output) and records every call.
func fakeEngine(t *testing.T, table map[string]canned) (*engine.Engine, *[][]string) {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	var calls [][]string
	e := &engine.Engine{OS: "linux", Reg: registry.New(state.NewDirs()), Getenv: func(string) string { return "" }}
	e.Run = func(c []string) state.Result {
		calls = append(calls, append([]string(nil), c...))
		k := strings.Join(c, " ")
		best := ""
		for p := range table {
			if strings.HasPrefix(k, p) && len(p) > len(best) {
				best = p
			}
		}
		if best == "" {
			return state.Result{}
		}
		return state.Result{Code: table[best].Code, Stdout: table[best].Out}
	}
	return e, &calls
}

func load(t *testing.T, v any) {
	b, err := os.ReadFile("../../testdata/golden/network.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestProjectNetworkMatchesPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the goldens were recorded on POSIX and hold / paths")
	}
	var g struct {
		ProjectNetwork map[string]struct {
			Rel    string
			Cfg    map[string]any
			Result []any
			Calls  [][]string
		} `json:"project_network"`
		Fail map[string]struct {
			Result []any
			Calls  [][]string
		}
	}
	load(t, &g)
	for key, c := range g.ProjectNetwork {
		table := map[string]canned{
			"podman network inspect --format": {0, "true\n"}, "podman network inspect": {1, ""},
			"podman network ls": {0, ProjectNetworkName("w", c.Rel) + "\n"},
		}
		e, calls := fakeEngine(t, table)
		n := Net{D: state.NewDirs(), Eng: e}
		net, path, err := n.ProjectNetwork("podman", "w", c.Rel, filepath.Clean("/proj/"+c.Rel), c.Cfg)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		want := c.Result
		if want[0] == nil {
			if net != "" || path != "" {
				t.Errorf("%s: Go made %s, Python none", key, net)
			}
		} else {
			if net != want[0] {
				t.Errorf("%s: net %q want %v", key, net, want[0])
			}
			b, _ := os.ReadFile(path)
			if string(b) != want[1] || filepath.Base(path) != want[2] {
				t.Errorf("%s:\n go:\n%s\n python:\n%v (%v)", key, b, want[1], want[2])
			}
		}
		if !reflect.DeepEqual(*calls, c.Calls) && !(len(*calls) == 0 && len(c.Calls) == 0) {
			t.Errorf("%s: calls\n go     %v\n python %v", key, *calls, c.Calls)
		}
	}
	tables := map[string]map[string]canned{
		"create_fails":    {"podman network inspect": {1, ""}, "podman network create": {1, ""}},
		"not_internal":    {"podman network inspect --format": {0, "false\n"}, "podman network inspect": {0, ""}, "podman network ls": {0, "w_root_net\n"}},
		"not_project_net": {"podman network inspect --format": {0, "true\n"}, "podman network inspect": {0, ""}, "podman network ls": {0, ""}},
	}
	for name, c := range g.Fail {
		table := tables[name]
		if name == "create_fails" {
			table["podman network create"] = canned{1, ""}
		}
		e, calls := fakeEngine(t, table)
		// create_fails' stderr text is part of the message: give the fake a stderr through Stdout
		orig := e.Run
		e.Run = func(cmd []string) state.Result {
			r := orig(cmd)
			if name == "create_fails" && len(cmd) > 2 && cmd[2] == "create" {
				r.Stderr = strings.Repeat("Error: x", 40)
			}
			return r
		}
		n := Net{D: state.NewDirs(), Eng: e}
		_, _, err := n.ProjectNetwork("podman", "w", "", "/proj/x", map[string]any{"services": map[string]any{"web": map[string]any{}, "db": map[string]any{}}, "networks": map[string]any{"default": map[string]any{"name": "w_default"}}})
		if err == nil || err.Error() != c.Result[1] {
			t.Errorf("%s: error %v, python %v", name, err, c.Result[1])
		}
		if !reflect.DeepEqual(*calls, c.Calls) {
			t.Errorf("%s: calls\n go     %v\n python %v", name, *calls, c.Calls)
		}
	}
}

func TestPruneEnsureNamesMatchPython(t *testing.T) {
	var g struct {
		Prune struct {
			Removed []string
			Calls   [][]string
		}
		Ensure map[string]struct {
			Name   string
			Stdout string
			Calls  [][]string
		}
		Names map[string]string
		Keys  []string
	}
	load(t, &g)
	e, calls := fakeEngine(t, map[string]canned{"podman network ls": {0, "w_a_net\nw_b_net\nw_c_net\n"}, "podman network rm w_b_net": {1, ""}})
	n := Net{D: state.NewDirs(), Eng: e}
	if got := n.PruneProjectNetworks("podman", "w", map[string]bool{"w_a_net": true}); !reflect.DeepEqual(got, g.Prune.Removed) || !reflect.DeepEqual(*calls, g.Prune.Calls) {
		t.Errorf("prune: %v %v\n python %v %v", got, *calls, g.Prune.Removed, g.Prune.Calls)
	}
	tabs := map[string]map[string]canned{
		"ok":   {"podman network inspect --format": {0, "true\n"}, "podman network inspect": {0, ""}},
		"open": {"podman network inspect --format": {0, "false\n"}, "podman network inspect": {0, ""}},
		"fail": {"podman network inspect": {1, ""}, "podman network create": {1, ""}},
	}
	for name, c := range g.Ensure {
		e, calls := fakeEngine(t, tabs[name])
		got, out := Net{D: state.NewDirs(), Eng: e}.EnsureWorkspaceNetwork("w", "podman")
		stdout := ""
		for _, l := range out {
			stdout += l + "\n"
		}
		if got != c.Name || stdout != c.Stdout || !reflect.DeepEqual(*calls, c.Calls) {
			t.Errorf("ensure %s: %q %q %v\n python %q %q %v", name, got, stdout, *calls, c.Name, c.Stdout, c.Calls)
		}
	}
	for rel, want := range g.Names {
		if got := ProjectNetworkName("w", rel); got != want {
			t.Errorf("name(%q) = %q want %q", rel, got, want)
		}
	}
	cfg := map[string]any{"networks": map[string]any{"a": map[string]any{"name": "w_net"}, "b": map[string]any{"name": "x"}, "c": nil, "z": map[string]any{"name": "w_net"}}}
	if got := WorkspaceNetworkKeys(cfg, "w"); !reflect.DeepEqual(got, g.Keys) {
		t.Errorf("keys %v want %v", got, g.Keys)
	}
}

func TestServiceProjectNetworkKey(t *testing.T) {
	cfg := map[string]any{
		"networks": map[string]any{"default": map[string]any{"name": "w_x_net"}, "back": map[string]any{"name": "w_back"}, "ext": map[string]any{"external": true}},
		"services": map[string]any{
			"a": map[string]any{},
			"b": map[string]any{"networks": map[string]any{"back": nil}},
			"c": map[string]any{"networks": []any{"ext", "default"}},
			"d": map[string]any{"networks": []any{"ext"}},
		},
	}
	for svc, want := range map[string]string{"a": "default", "b": "back", "c": "default", "d": "om_project", "nope": "default"} {
		if got := ServiceProjectNetworkKey(cfg, svc); got != want {
			t.Errorf("%s: %s want %s", svc, got, want)
		}
	}
	if ServiceProjectNetworkKey(nil, "a") != "om_project" {
		t.Error("nil config")
	}
}
