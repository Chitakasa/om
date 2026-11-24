package scaffold

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func gold(t *testing.T) (g struct {
	Plans []struct {
		Args   map[string]any
		Result map[string]any
	}
	Rendered []struct {
		Name         string
		ProjectFiles map[string]string `json:"project_files"`
		Compose      string
		Hardening    string
	}
	Menu         string
	MenuIndent2  string `json:"menu_indent2"`
	LabelUpdates []struct {
		Args   map[string]any
		Result [][]string
		Err    string
	} `json:"label_updates"`
	Safe map[string]bool
}) {
	b, err := os.ReadFile("../../testdata/golden/scaffold.json")
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&g); err != nil {
		t.Fatal(err)
	}
	return
}

func str(m map[string]any, k string) string   { s, _ := m[k].(string); return s }
func boolean(m map[string]any, k string) bool { b, _ := m[k].(bool); return b }
func intv(m map[string]any, k string) int {
	n, _ := m[k].(json.Number)
	i, _ := n.Int64()
	return int(i)
}

func TestPlansAndRenderMatchPython(t *testing.T) {
	g := gold(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "services", "taken"), 0o755)
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	var okPlans []Plan
	for _, c := range g.Plans {
		a := AddArgs{Name: str(c.Args, "name"), Image: str(c.Args, "image"), Domain: str(c.Args, "domain"), Icon: str(c.Args, "icon"),
			Desc: str(c.Args, "desc"), Port: intv(c.Args, "port"), Project: boolean(c.Args, "project"), NoWeb: boolean(c.Args, "no_web"), Public: boolean(c.Args, "public")}
		p, err := MakePlan(a, "wsid", root, exists)
		if msg, bad := c.Result["err"].(string); bad {
			if err == nil || strings.ReplaceAll(err.Error(), root, "@ROOT@") != strings.ReplaceAll(msg, "@ROOT@", "@ROOT@") && err.Error() != msg {
				// Python's message names its own temp path; compare up to it
				if err == nil || !strings.HasPrefix(err.Error(), strings.SplitN(msg, " at ", 2)[0]) {
					t.Errorf("%v: Go %v, Python refuses with %q", c.Args, err, msg)
				}
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: Go refuses (%v), Python accepts", c.Args, err)
			continue
		}
		want := c.Result["ok"].(map[string]any)
		if p.Name != str(want, "name") || p.Image != str(want, "image") || p.Port != intv(want, "port") || p.Domain != str(want, "domain") ||
			p.Icon != str(want, "icon") || p.Desc != str(want, "desc") || p.IsProject != boolean(want, "is_project") ||
			p.CustomImage != boolean(want, "custom_image") || p.Public != boolean(want, "public") || p.NoWeb != boolean(want, "no_web") ||
			filepath.Base(filepath.Dir(p.Dest)) != filepath.Base(filepath.Dir(str(want, "dest"))) {
			t.Errorf("%v: %+v vs %v", c.Args, p, want)
		}
		okPlans = append(okPlans, p)
	}
	if len(okPlans) != len(g.Rendered) {
		t.Fatalf("%d plans, %d rendered", len(okPlans), len(g.Rendered))
	}
	for i, r := range g.Rendered {
		p := okPlans[i]
		if got := RenderCompose(p); got != r.Compose {
			t.Errorf("compose of %s:\n%s\npython:\n%s", r.Name, got, r.Compose)
		}
		if got := ProjectFiles(p); !reflect.DeepEqual(got, r.ProjectFiles) && !(len(got) == 0 && len(r.ProjectFiles) == 0) {
			t.Errorf("project files of %s: %v vs %v", r.Name, got, r.ProjectFiles)
		}
		if Hardening(p.CustomImage) != r.Hardening {
			t.Errorf("hardening of %s", r.Name)
		}
	}
	if MenuText("      ") != g.Menu || MenuText("  ") != g.MenuIndent2 {
		t.Errorf("label menu differs:\n%s", MenuText("      "))
	}
	for v, want := range g.Safe {
		if YAMLLabelSafe(v) != want {
			t.Errorf("YAMLLabelSafe(%q)", v)
		}
	}
}

func TestLabelEditingMatchesPython(t *testing.T) {
	g := gold(t)
	for _, c := range g.LabelUpdates {
		a := EditArgs{Scope: str(c.Args, "scope"), Icon: str(c.Args, "icon"), Desc: str(c.Args, "desc"), Name: str(c.Args, "name"), Port: intv(c.Args, "port")}
		got, err := LabelUpdates(a)
		if c.Err != "" {
			if err == nil || err.Error() != c.Err {
				t.Errorf("%v: %v, python %q", c.Args, err, c.Err)
			}
			continue
		}
		var pairs [][]string
		for _, kv := range got {
			pairs = append(pairs, []string{kv.Key, kv.Value})
		}
		if err != nil || !reflect.DeepEqual(pairs, c.Result) {
			t.Errorf("%v: %v %v, python %v", c.Args, pairs, err, c.Result)
		}
	}
}

func TestActiveLabelsListed(t *testing.T) {
	names := map[string]bool{}
	for _, l := range ActiveLabels {
		names[l.Name] = true
	}
	for _, want := range []string{"workspace.id", "dashboard.name", "dashboard.port", "dashboard.scope", "dashboard.web"} {
		if !names[want] {
			t.Errorf("missing %s", want)
		}
	}
}

func TestExtraLabelsAreWrittenAsActiveLabelsAndValidated(t *testing.T) {
	exists := func(string) bool { return false }
	p, err := MakePlan(AddArgs{Name: "api", Image: "docker.io/library/redis:7", Port: 6379, NoWeb: true,
		Extra: []KV{{"om.tcp", "6379"}, {"om.egress", "learn"}, {"om.mem", "256m"}}}, "ws", "/w", exists)
	if err != nil {
		t.Fatal(err)
	}
	text := RenderCompose(p)
	for _, want := range []string{"      - \"om.tcp=6379\"\n", "      - \"om.egress=learn\"\n", "      - \"om.mem=256m\"\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	// the active labels come before the commented menu, in the order given
	if strings.Index(text, "om.tcp=6379") > strings.Index(text, "# More om labels") {
		t.Error("extra labels must precede the commented menu")
	}
	for _, bad := range []AddArgs{
		{Name: "a", Extra: []KV{{"om.nonsense", "x"}}},
		{Name: "a", Extra: []KV{{"om.mem", ""}}},
		{Name: "a", Extra: []KV{{"om.mem", "1\"\n  privileged: true"}}},
	} {
		if _, err := MakePlan(bad, "ws", "/w", exists); err == nil {
			t.Errorf("accepted %v", bad.Extra)
		}
	}
}
