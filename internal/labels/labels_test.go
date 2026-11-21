package labels

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/golden/workspace/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestParseLimitsMatchesPython(t *testing.T) {
	var cases []struct {
		Labels   map[string]any    `json:"labels"`
		Dumps    map[string]string `json:"dumps"`
		Problems []string          `json:"problems"`
	}
	b, _ := os.ReadFile("../../testdata/golden/workspace/limits_parse.json")
	dec := json.NewDecoder(bytesReader(b))
	dec.UseNumber() // labels keep their written form, as the engine's JSON gives them
	if err := dec.Decode(&cases); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		lim, probs := ParseLimits(c.Labels)
		got := map[string]string{}
		for _, l := range lim {
			got[l.Key] = l.Value
		}
		if !reflect.DeepEqual(got, c.Dumps) && !(len(got) == 0 && len(c.Dumps) == 0) {
			t.Errorf("%d %v: limits %v, python %v", i, c.Labels, got, c.Dumps)
		}
		if !reflect.DeepEqual(probs, c.Problems) && !(len(probs) == 0 && len(c.Problems) == 0) {
			t.Errorf("%d %v: problems %q, python %q", i, c.Labels, probs, c.Problems)
		}
	}
}

func TestWriteOverrideMatchesPython(t *testing.T) {
	var g struct {
		Cfg        map[string]any `json:"cfg"`
		ProjectDir string         `json:"project_dir"`
		Problems   []string       `json:"problems"`
		File, Name string
	}
	load(t, "limits_override.json", &g)
	t.Setenv("OM_STATE_DIR", t.TempDir())
	d := state.NewDirs()
	path, probs, err := WriteOverride(d, "w", g.ProjectDir, g.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != g.Name {
		t.Errorf("name %s, python %s", filepath.Base(path), g.Name)
	}
	if b, _ := os.ReadFile(path); string(b) != g.File {
		t.Errorf("file\n%s\npython\n%s", b, g.File)
	}
	if !reflect.DeepEqual(probs, g.Problems) {
		t.Errorf("problems %q, python %q", probs, g.Problems)
	}
	// no limits left: the stale file goes away
	path2, _, err := WriteOverride(d, "w", g.ProjectDir, map[string]any{"services": map[string]any{"web": map[string]any{}}})
	if err != nil || path2 != "" {
		t.Fatal(path2, err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("stale override left")
	}
}

func TestServiceLabelForms(t *testing.T) {
	m := Service(map[string]any{"labels": []any{"a=b", "bare", "c=d=e"}})
	if !reflect.DeepEqual(m, map[string]any{"a": "b", "bare": "", "c": "d=e"}) {
		t.Fatal(m)
	}
	if len(Service(nil)) != 0 || len(Service(map[string]any{"labels": nil})) != 0 {
		t.Fatal("empty")
	}
	_ = py.Str
}

func bytesReader(b []byte) *bytesRd { return &bytesRd{b: b} }

type bytesRd struct {
	b []byte
	i int
}

func (r *bytesRd) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
