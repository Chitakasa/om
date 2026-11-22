package workspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

func TestSafeNames(t *testing.T) {
	for s, want := range map[string]bool{"web": true, "a-b-1": true, "": false, "-a": false, "A": false, "web\n": false, "a_b": false, strings.Repeat("a", 63): true, strings.Repeat("a", 64): false} {
		if IsSafeName(s) != want {
			t.Errorf("IsSafeName(%q) != %v", s, want)
		}
	}
	if IsValidWorkspaceID("core") || IsValidWorkspaceID("om") || !IsValidWorkspaceID("apps") {
		t.Fatal("reserved ids")
	}
	if !SafeDomainRE.MatchString("a.b-c.d") || SafeDomainRE.MatchString("a.b\n") || SafeDomainRE.MatchString(".a") {
		t.Fatal("domain")
	}
}

type discoverGolden struct {
	Files    map[string]string  `json:"files"`
	Discover map[string][][]any `json:"discover"`
	Ignored  []string           `json:"ignored"`
	Build    map[string]bool    `json:"has_build"`
	Rel      []string           `json:"project_rel"`
}

func TestDiscoverMatchesPython(t *testing.T) {
	var g discoverGolden
	b, err := os.ReadFile("../../testdata/golden/workspace/discover.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "ws")
	for f, c := range g.Files {
		p := filepath.Join(root, filepath.FromSlash(f))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(c), 0o644)
	}
	rel := func(d string) string {
		if d == root {
			return ""
		}
		r, _ := filepath.Rel(root, d)
		return filepath.ToSlash(r)
	}
	for target, want := range g.Discover {
		var got [][]any
		for _, p := range DiscoverComposeDirs(root, target) {
			got = append(got, []any{float64(p.Priority), rel(p.Dir)})
		}
		if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("target %q:\n go     %v\n python %v", target, got, want)
		}
	}
	var ign []string
	for _, d := range IgnoredComposeDirs(root) {
		ign = append(ign, rel(d))
	}
	if !reflect.DeepEqual(ign, g.Ignored) {
		t.Errorf("ignored %v, python %v", ign, g.Ignored)
	}
	for f, want := range g.Build {
		if got, _ := HasBuild(filepath.Join(root, f)); got != want {
			t.Errorf("HasBuild(%s)=%v", f, got)
		}
	}
	if ProjectRel(root, root) != g.Rel[0] || ProjectRel(root, filepath.Join(root, "c", "sub1")) != g.Rel[1] {
		t.Errorf("ProjectRel %v", g.Rel)
	}
	if d, err := ResolveTarget(root, "a"); err != nil || rel(d) != "a" {
		t.Error(d, err)
	}
	if _, err := ResolveTarget(root, "nope"); err == nil || !strings.Contains(err.Error(), "No service or project named 'nope'") {
		t.Error(err)
	}
}

func mkRoot(t *testing.T, cfg string) string {
	root := filepath.Join(t.TempDir(), "My-Apps")
	os.MkdirAll(filepath.Join(root, ".om"), 0o755)
	if cfg != "" {
		os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(cfg), 0o644)
	}
	return root
}

func TestWorkspaceID(t *testing.T) {
	root := mkRoot(t, "{}")
	if id, err := WorkspaceID(root); err != nil || id != "my-apps" {
		t.Fatal(id, err)
	}
	os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(`{"workspace_id":"cfg"}`), 0o644)
	if id, _ := WorkspaceID(root); id != "cfg" {
		t.Fatal(id)
	}
	os.WriteFile(filepath.Join(root, ".om", "local.json"), []byte(`{"workspace_id":"prev"}`), 0o644)
	if id, _ := WorkspaceID(root); id != "prev" {
		t.Fatal("local wins:", id)
	}
	for _, bad := range []string{`{"workspace_id":"core"}`, `{"workspace_id":"Bad Id"}`, `{"workspace_id":5}`, `{"workspace_id":""}`} {
		os.Remove(filepath.Join(root, ".om", "local.json"))
		os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(bad), 0o644)
		if _, err := WorkspaceID(root); err == nil || !strings.HasPrefix(err.Error(), "fatal: invalid workspace id") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestConfigRoundTripKeepsOrder(t *testing.T) {
	root := mkRoot(t, "")
	src := "{\n  \"z\": 1,\n  \"workspace_id\": \"x\",\n  \"gitops\": {\n    \"auto_sync\": true\n  },\n  \"list\": []\n}\n"
	os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(src), 0o644)
	if err := WriteConfig(root, ReadConfig(root)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, ".om", "config.json")); string(b) != src {
		t.Fatalf("round trip changed the file:\n%s", b)
	}
	g := GitopsSettings(root)
	if g["auto_sync"] != true || g["auto_rollback"] != true || g["interval_seconds"] != 300 {
		t.Fatal(g)
	}
	loc := py.NewObject()
	sub := py.NewObject()
	sub.Set("interval_seconds", json.Number("60"))
	loc.Set("gitops", sub)
	os.WriteFile(filepath.Join(root, ".om", "local.json"), []byte(py.Dumps(loc)), 0o644)
	if g := GitopsSettings(root); g["interval_seconds"] != json.Number("60") {
		t.Fatal("local overrides:", g)
	}
}

func TestRegisterRefusesLiveClash(t *testing.T) {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	reg := registry.New(state.NewDirs())
	a, b := t.TempDir(), t.TempDir()
	if err := Register(reg, a, "app"); err != nil {
		t.Fatal(err)
	}
	if err := Register(reg, a, "app"); err != nil {
		t.Fatal("same folder again:", err)
	}
	if err := Register(reg, b, "app"); err == nil || !strings.Contains(err.Error(), "already used by") {
		t.Fatal(err)
	}
	os.RemoveAll(a)
	if err := Register(reg, b, "app"); err != nil {
		t.Fatal("a gone folder frees the id:", err)
	}
	if got := KnownWorkspaces(reg); !reflect.DeepEqual(got, []string{"app"}) {
		t.Fatal(got)
	}
}

func TestEnv(t *testing.T) {
	e := Env("/w/root", "ws", "")
	for k, v := range map[string]string{"WORKSPACE_ID": "ws", "COMPOSE_PROJECT_NAME": "ws", "WORKSPACE_ROOT": "/w/root", "DATA_DIR": "/w/root/data", "WORKSPACE_NET": "ws_net", "DOCKER_SOCK": "/var/run/docker.sock"} {
		if e[k] != v {
			t.Errorf("%s=%q", k, e[k])
		}
	}
	if Env("/w", "x", "/run/p.sock")["DOCKER_SOCK"] != "/run/p.sock" {
		t.Fatal("socket")
	}
}

func TestServiceContainersFallbacks(t *testing.T) {
	root := mkRoot(t, `{"workspace_id":"ws"}`)
	dir := filepath.Join(root, "web")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  a:\n    container_name: ${WORKSPACE_ID}_a\n  b:\n    container_name: \"fixed\"\n"), 0o644)
	got, err := ServiceContainers("/nonexistent/engine", root, dir)
	if err != nil || !reflect.DeepEqual(got, []string{"ws_a", "fixed"}) {
		t.Fatal(got, err)
	}
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services: {}\n"), 0o644)
	if got, _ := ServiceContainers("/nonexistent/engine", root, dir); !reflect.DeepEqual(got, []string{"ws_web"}) {
		t.Fatal(got)
	}
}

func TestFindWorkspaceRootWalksUp(t *testing.T) {
	root := mkRoot(t, "{}")
	deep := filepath.Join(root, "a", "b")
	os.MkdirAll(deep, 0o755)
	t.Chdir(deep)
	got, ok := FindWorkspaceRoot()
	want, _ := filepath.EvalSymlinks(root)
	if !ok || got != want {
		t.Fatal(got, ok)
	}
	t.Chdir(t.TempDir())
	if _, ok := FindWorkspaceRoot(); ok {
		t.Fatal("found a root outside any workspace")
	}
}

func TestComposeCommandLine(t *testing.T) {
	if got := Compose("podman", "/x/compose.yml", "up", "-d"); !reflect.DeepEqual(got, []string{"podman", "compose", "-f", "/x/compose.yml", "up", "-d"}) {
		t.Fatal(got)
	}
}
