package stream

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

func loadGolden(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/golden/" + name)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func strs(v any) []string {
	out := []string{}
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func intOf(v any) int { n, _ := v.(json.Number).Int64(); return int(n) }

func bigOf(v any) *big.Int {
	switch x := v.(type) {
	case json.Number:
		b, _ := new(big.Int).SetString(x.String(), 10)
		return b
	case string: // a huge int the recorder stringified
		b, _ := new(big.Int).SetString(x, 10)
		return b
	}
	return big.NewInt(0)
}

func TestRecordedMatchesPython(t *testing.T) {
	var g map[string][]struct {
		Args   map[string]any
		Result any
		Err    *string
	}
	loadGolden(t, "stream_recorded.json", &g)
	for _, c := range g["validate_host_port"] {
		eh, es := 80, 443
		if v, ok := c.Args["edge_http"]; ok {
			eh = intOf(v)
		}
		if v, ok := c.Args["edge_https"]; ok {
			es = intOf(v)
		}
		got := ValidateHostPort(bigOf(c.Args["port"]), eh, es)
		if !reflect.DeepEqual(orEmpty(got), strs(c.Result)) {
			t.Errorf("port %v %d/%d:\n go     %q\n python %q", c.Args["port"], eh, es, got, strs(c.Result))
		}
	}
	for _, c := range g["parse_stream_meta"] {
		if c.Err != nil {
			continue
		}
		labels := map[string]string{}
		for k, v := range c.Args["labels"].(map[string]any) {
			labels[k] = v.(string)
		}
		sname, _ := c.Args["sname"].(string)
		eh, es := 80, 443
		if v, ok := c.Args["edge_http"]; ok {
			eh = intOf(v)
		}
		if v, ok := c.Args["edge_https"]; ok {
			es = intOf(v)
		}
		m, probs := ParseMeta(labels, sname, eh, es)
		want := c.Result.([]any)
		if !reflect.DeepEqual(orEmpty(probs), strs(want[1])) {
			t.Errorf("%v problems:\n go     %q\n python %q", c.Args, probs, strs(want[1]))
		}
		if want[0] == nil {
			if m != nil {
				t.Errorf("%v: Go accepts %+v, Python refuses", c.Args, m)
			}
			continue
		}
		w := want[0].(map[string]any)
		if m == nil {
			t.Errorf("%v: Go refuses, Python accepts %v", c.Args, w)
			continue
		}
		hp := -1
		if m.HostPort != nil {
			hp = *m.HostPort
		}
		whp := -1
		if w["host_port"] != nil {
			whp = intOf(w["host_port"])
		}
		if m.ContainerPort != intOf(w["container_port"]) || hp != whp || m.Scope != w["scope"] || m.Log != w["log"] {
			t.Errorf("%v: %+v vs %v", c.Args, m, w)
		}
	}
	for _, c := range g["_check_structure"] {
		got := CheckStructure(c.Args["content"].(string))
		if !reflect.DeepEqual(orEmpty(got), strs(c.Result)) {
			// Python lists missing backends in set order (random); only the set must match
			if !sameSet(got, strs(c.Result)) {
				t.Errorf("%q:\n go     %q\n python %q", c.Args["content"], got, strs(c.Result))
			}
		}
	}
	for _, c := range g["render_edge_fragment"] {
		log, _ := c.Args["log"].(string)
		if log == "" {
			log = "on"
		}
		if got := RenderEdgeFragment(c.Args["ws_id"].(string), c.Args["sname"].(string), intOf(c.Args["host_port"]), log); got != c.Result.(string) {
			t.Errorf("edge fragment %v:\n%s\n%s", c.Args, got, c.Result)
		}
	}
	for _, c := range g["render_router_fragment"] {
		if got := RenderRouterFragment(c.Args["ws_id"].(string), c.Args["sname"].(string), intOf(c.Args["host_port"]), intOf(c.Args["container_port"])); got != c.Result.(string) {
			t.Errorf("router fragment %v:\n%s\n%s", c.Args, got, c.Result)
		}
	}
}

func sameSet(a, b []string) bool {
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestBaseConfigsAreVerbatim(t *testing.T) {
	if !strings.HasPrefix(BaseEdgeConfig(), "# om Stream Edge Proxy") || !strings.Contains(BaseRouterConfig(), "resolvers docker") {
		t.Fatal("embedded configs")
	}
	if !strings.Contains(HAProxyImage, "@sha256:") {
		t.Fatal("image must be pinned by digest")
	}
}

func newStream(t *testing.T) (*Stream, *int) {
	root := t.TempDir()
	t.Setenv("OM_STATE_DIR", filepath.Join(root, "state"))
	d := state.NewDirs()
	kills := 0
	eng := &engine.Engine{Reg: registry.New(d), OS: "linux", ProcRoot: "/nonexistent", Getenv: func(string) string { return "" },
		Run: func(c []string) state.Result {
			if len(c) > 2 && c[1] == "container" && c[2] == "inspect" {
				if c[len(c)-1] == "om_stream_edge" {
					return state.Result{Stdout: "true 0"} // running (pid 0: not checked)
				}
				return state.Result{Code: 1}
			}
			if len(c) > 1 && c[1] == "info" {
				return state.Result{Code: 1}
			}
			return state.Result{}
		}}
	s := &Stream{D: d, Eng: eng, LookPath: func(string) (string, error) { return "", errors.New("none") }}
	s.Run = func(c []string) state.Result {
		kills++
		return state.Result{}
	}
	return s, &kills
}

func snap(dir string) map[string]string {
	out := map[string]string{}
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() && info.Name() != "stream.lock" {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	return out
}

func svcs(v any) map[string]Service {
	out := map[string]Service{}
	for k, x := range v.(map[string]any) {
		m := x.(map[string]any)
		log, _ := m["log"].(string)
		out[k] = Service{HostPort: intOf(m["host_port"]), ContainerPort: intOf(m["container_port"]), Log: log}
	}
	return out
}

func TestScenarioMatchesPython(t *testing.T) {
	var g struct {
		Steps []struct {
			Op     string
			Args   []any
			Result any
			Stdout string
			Files  map[string]string
			Kills  int
		}
	}
	loadGolden(t, "stream_scenario.json", &g)
	s, kills := newStream(t)
	base := filepath.Join(s.D.State, "stream")
	for i, st := range g.Steps {
		var res any
		var problems []string
		switch st.Op {
		case "sync":
			// the old-name fragment is planted by the Python script before its 6th step, a rogue one before the 7th
			if i == 5 {
				plant(t, base, "a-web.cfg")
			}
			if i == 6 {
				os.WriteFile(filepath.Join(base, "fragments", "edge", "rogue.cfg"), []byte("frontend stream_9\n    bind :9\n    bogus 1\n"), 0o644)
			}
			var err error
			res, problems, err = s.SyncRoutes(st.Args[0].(string), svcs(st.Args[1]), "podman")
			if err != nil {
				t.Fatal(err)
			}
		case "prune":
			var err error
			if res, err = s.PruneFragments(st.Args[0].(string), "podman"); err != nil {
				t.Fatal(err)
			}
		case "ensure":
			os.RemoveAll(filepath.Join(base, "edge.cfg"))
			os.Mkdir(filepath.Join(base, "edge.cfg"), 0o755)
			if err := s.EnsureConfigs(); err != nil {
				t.Fatal(err)
			}
		case "fragment_name":
			res = FragmentName(st.Args[0].(string), st.Args[1].(string))
		}
		if st.Result != nil && !reflect.DeepEqual(res, st.Result) {
			t.Errorf("step %d %s: result %v, python %v", i, st.Op, res, st.Result)
		}
		var printed []string
		for _, p := range problems {
			printed = append(printed, "  \x1b[31m✗ Stream config validation failed: "+p+"\x1b[0m\n")
		}
		if got := strings.Join(printed, ""); got != st.Stdout {
			t.Errorf("step %d %s: problems %q vs python stdout %q", i, st.Op, got, st.Stdout)
		}
		if got := snap(base); !reflect.DeepEqual(got, st.Files) {
			for k, v := range st.Files {
				if got[k] != v {
					t.Errorf("step %d %s: file %s\n go:\n%s\n python:\n%s", i, st.Op, k, got[k], v)
				}
			}
			for k := range got {
				if _, ok := st.Files[k]; !ok {
					t.Errorf("step %d %s: extra file %s", i, st.Op, k)
				}
			}
		}
		if *kills != st.Kills {
			t.Errorf("step %d %s: %d reload kills, python %d", i, st.Op, *kills, st.Kills)
		}
		if i == 6 { // the Python script removes its rogue fragment after this step
			os.Remove(filepath.Join(base, "fragments", "edge", "rogue.cfg"))
		}
	}
}

func plant(t *testing.T, base, name string) {
	edge := "# Service: web (a)\nfrontend stream_25565\n    bind :25565\n    default_backend sock_25565\nbackend sock_25565\n    server s1 /x\n"
	router := "# Service: web (a)\nfrontend sock_25565\n    bind /x\n    default_backend target_25565\nbackend target_25565\n    server s1 a_web:22\n"
	os.WriteFile(filepath.Join(base, "fragments", "edge", name), []byte(edge), 0o644)
	os.WriteFile(filepath.Join(base, "fragments", "router", name), []byte(router), 0o644)
}

func TestValidateSyntaxChoosesHaproxyThenEngineThenStructure(t *testing.T) {
	s, _ := newStream(t)
	var cmds [][]string
	s.Run = func(c []string) state.Result {
		cmds = append(cmds, c)
		return state.Result{Code: 1, Stderr: "  bad config  "}
	}
	s.LookPath = func(n string) (string, error) {
		if n == "haproxy" {
			return "/usr/bin/haproxy", nil
		}
		return "", errors.New("no")
	}
	if got := s.ValidateSyntax("global\n", "podman"); !reflect.DeepEqual(got, []string{"HAProxy validation error: bad config"}) || cmds[0][0] != "/usr/bin/haproxy" || cmds[0][1] != "-c" {
		t.Fatal(got, cmds)
	}
	s.Run = func(c []string) state.Result { return state.Result{Code: 2} } // exit 2: warnings only
	if got := s.ValidateSyntax("global\n", "podman"); got != nil {
		t.Fatal(got)
	}
	s.LookPath = func(n string) (string, error) {
		if n == "podman" {
			return "/usr/bin/podman", nil
		}
		return "", errors.New("no")
	}
	s.Run = func(c []string) state.Result {
		cmds = append(cmds, c)
		return state.Result{Code: 1, Stdout: "engine says no"}
	}
	cmds = nil
	got := s.ValidateSyntax("global\n", "podman")
	if !reflect.DeepEqual(got, []string{"HAProxy engine validation error: engine says no"}) || cmds[0][1] != "run" || !strings.HasSuffix(cmds[0][4], ":/tmp/check.cfg:ro,Z") {
		t.Fatal(got, cmds)
	}
	s.LookPath = func(string) (string, error) { return "", errors.New("no") }
	if got := s.ValidateSyntax("bogus\n", "om-test-no-engine"); len(got) != 1 || !strings.Contains(got[0], "outside any section") {
		t.Fatal(got)
	}
}
