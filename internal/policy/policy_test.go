package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

func loadJSON(t *testing.T, name string, v any) {
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

func strList(v any) []string {
	out := []string{}
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

func orNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func extraFrom(v any) []finding {
	var out []finding
	l, _ := v.([]any)
	for _, x := range l {
		p := x.([]any)
		out = append(out, finding{p[0].(string), p[1].(string)})
	}
	return out
}

func TestRecordedMatchesPython(t *testing.T) {
	var g map[string][]struct {
		Args   map[string]any
		Result any
		Err    *string
	}
	loadJSON(t, "policy_recorded.json", &g)
	for _, c := range g["_sensitive_source"] {
		home, _ := c.Args["home"].(string)
		if got := sensitiveSource(c.Args["src"].(string), home); got != c.Result.(bool) {
			t.Errorf("sensitive(%q, %q) = %v, python %v", c.Args["src"], home, got, c.Result)
		}
	}
	for _, c := range g["mode"] {
		s := settings.Settings{}
		if m, ok := c.Args["settings"].(map[string]any); ok {
			for k, v := range m {
				s[k] = v.(string)
			}
		}
		if Mode(s) != c.Result.(string) {
			t.Errorf("mode %v", c.Args)
		}
	}
	n := 0
	for _, c := range g["evaluate_service"] {
		if c.Err != nil {
			continue
		}
		svc, _ := c.Args["svc"].(map[string]any)
		home, _ := c.Args["home"].(string)
		if home == "" {
			home = homeDir()
		}
		viol, waived := evaluateService(c.Args["name"].(string), svc, home, extraFrom(c.Args["extra"]))
		want := c.Result.([]any)
		if !reflect.DeepEqual(orNil(viol), strList(want[0])) || !reflect.DeepEqual(orNil(waived), strList(want[1])) {
			t.Errorf("service %v:\n go     %q | %q\n python %v", c.Args, viol, waived, want)
		}
		n++
	}
	for _, c := range g["evaluate_config"] {
		if c.Err != nil {
			continue
		}
		cfg, _ := c.Args["cfg"].(map[string]any)
		home, _ := c.Args["home"].(string)
		wsNet, _ := c.Args["ws_net"].(string)
		viol, waived := EvaluateConfig(cfg, home, wsNet)
		want := c.Result.([]any)
		wv := strList(want[0])
		if anyPlaintext(wv) && !reflect.DeepEqual(orNil(viol), wv) {
			continue // the recorded run had a plaintext secret file that is gone now
		}
		if !reflect.DeepEqual(orNil(viol), wv) || !reflect.DeepEqual(orNil(waived), strList(want[1])) {
			t.Errorf("config %v:\n go     %q | %q\n python %v", c.Args, viol, waived, want)
		}
		n++
	}
	for _, c := range g["egress_services"] {
		cfg, _ := c.Args["cfg"].(map[string]any)
		got := map[string]any{}
		for k, r := range EgressServices(cfg) {
			if r.Mode != "" {
				got[k] = r.Mode
			} else {
				l := []any{}
				for _, h := range r.Hosts {
					l = append(l, h)
				}
				got[k] = l
			}
		}
		if len(got) == 0 && len(c.Result.(map[string]any)) == 0 {
			continue
		}
		if b1, b2 := mustJSON(got), mustJSON(c.Result); b1 != b2 {
			t.Errorf("egress_services %v: %s vs %s", c.Args, b1, b2)
		}
	}
	t.Log(n, "service/config cases")
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func anyPlaintext(l []string) bool {
	for _, s := range l {
		if strings.Contains(s, "is plaintext in the workspace") {
			return true
		}
	}
	return false
}

func TestManualMatchesPython(t *testing.T) {
	var g struct {
		Sensitive []struct {
			Src, Home string
			Out       bool
		}
		Configs []struct {
			Name       string
			Cfg        map[string]any
			WsNet      *string `json:"ws_net"`
			Violations []string
			Waived     []string
		}
		EgressServices []struct {
			Cfg map[string]any
			Out map[string]any
		} `json:"egress_services"`
		Mode []struct {
			S   map[string]string
			Out string
		}
	}
	loadJSON(t, "policy_manual.json", &g)
	for _, c := range g.Sensitive {
		if got := sensitiveSource(c.Src, c.Home); got != c.Out {
			t.Errorf("sensitive(%q, %q) = %v, python %v", c.Src, c.Home, got, c.Out)
		}
	}
	for _, c := range g.Configs {
		wsNet := ""
		if c.WsNet != nil {
			wsNet = *c.WsNet
		}
		viol, waived := EvaluateConfig(c.Cfg, "/home/u", wsNet)
		wv := orNil(c.Violations)
		if c.Name == "secrets_plain" {
			// the golden's secret files lived in a temp dir that is gone; check the rule on a real tree below
			continue
		}
		if !reflect.DeepEqual(orNil(viol), wv) || !reflect.DeepEqual(orNil(waived), orNil(c.Waived)) {
			t.Errorf("%s (ws_net %v):\n go     %q | %q\n python %q | %q", c.Name, wsNet, viol, waived, wv, c.Waived)
		}
	}
	for _, c := range g.Mode {
		if Mode(settings.Settings(c.S)) != c.Out {
			t.Errorf("mode %v", c.S)
		}
	}
	for _, c := range g.EgressServices {
		got := map[string]any{}
		for k, r := range EgressServices(c.Cfg) {
			if r.Mode != "" {
				got[k] = r.Mode
			} else {
				l := []any{}
				for _, h := range r.Hosts {
					l = append(l, h)
				}
				got[k] = l
			}
		}
		if mustJSON(got) != mustJSON(c.Out) {
			t.Errorf("egress_services: %s vs %s", mustJSON(got), mustJSON(c.Out))
		}
	}
}

func TestSecretFindingsOnRealFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("x"), 0o600)
	os.Mkdir(filepath.Join(dir, "dir"), 0o755)
	cfg := map[string]any{"secrets": map[string]any{
		"s1": map[string]any{"file": filepath.Join(dir, "plain.txt")},
		"s2": map[string]any{"file": filepath.Join(dir, "missing")},
		"s3": map[string]any{"file": filepath.Join(dir, "dir")},
		"s4": map[string]any{}, "s5": nil, "s0": map[string]any{"file": ""},
	}}
	got := SecretFindings(cfg)
	want := []string{"secret s1: plain.txt is plaintext in the workspace — `om secrets set <project>/s1`, then delete it"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
}

// The one deliberate difference from Python: a leading double slash no longer hides a sensitive path.
func TestDoubleSlashIsNotABypass(t *testing.T) {
	for _, src := range []string{"//etc", "//etc/passwd", "//var/run", "//root/.ssh", "//home/u/.ssh"} {
		if !sensitiveSource(src, "/home/u") {
			t.Errorf("%s must be sensitive", src)
		}
	}
	if sensitiveSource("//srv/data", "/home/u") {
		t.Error("//srv/data is fine")
	}
}

func TestComposeConfigRunner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the expected folder is a POSIX path")
	}
	var gotCmd []string
	var gotDir string
	run := func(cmd []string, dir string, env []string) state.Result {
		gotCmd, gotDir = cmd, dir
		return state.Result{Stdout: `{"services":{"a":{}}}`}
	}
	cfg, msg := ComposeConfig(run, "podman", "/w/p/compose.yml", []string{"A=1"})
	if msg != "" || cfg["services"] == nil || gotDir != "/w/p" || !reflect.DeepEqual(gotCmd, []string{"podman", "compose", "-f", "/w/p/compose.yml", "config", "--format", "json"}) {
		t.Fatal(cfg, msg, gotCmd, gotDir)
	}
	fail := func([]string, string, []string) state.Result {
		return state.Result{Code: 1, Stderr: "  boom  ", Stdout: "ignored"}
	}
	if _, m := ComposeConfig(fail, "podman", "/f", nil); m != "/f: `compose config` failed: boom" {
		t.Fatal(m)
	}
	bad := func([]string, string, []string) state.Result { return state.Result{Stdout: "not json"} }
	if _, m := ComposeConfig(bad, "podman", "/f", nil); m != "/f: `compose config` did not return JSON" {
		t.Fatal(m)
	}
	long := func([]string, string, []string) state.Result {
		return state.Result{Code: 1, Stderr: strings.Repeat("é", 500)}
	}
	if _, m := ComposeConfig(long, "podman", "/f", nil); len([]rune(strings.TrimPrefix(m, "/f: `compose config` failed: "))) != 300 {
		t.Fatal("last 300 characters")
	}
	if v, w := EvaluateCompose(nil, "no config", "ws_net"); len(v) != 1 || v[0] != "no config" || len(w) != 0 {
		t.Fatal(v, w)
	}
}
