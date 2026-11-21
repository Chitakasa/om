package egress

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Chitakasa/om/internal/state"
)

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/golden/egress/" + name)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func norm(v any) any {
	b, _ := json.Marshal(v)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	dec.Decode(&out)
	return out
}

func ruleJSON(r Rule, ok bool) any {
	if !ok {
		return nil
	}
	return r.json()
}

func TestPureFunctionsMatchPython(t *testing.T) {
	var g struct {
		ValidHost  map[string]bool
		ParseLabel []struct {
			In  any
			Out any
		} `json:"parse_label"`
		ParseTTL []struct {
			In  any
			Out any
		} `json:"parse_ttl"`
		MergeJava []struct {
			In  []any
			Out string
		} `json:"merge_java"`
		IsJVM []struct {
			In  map[string]any
			Out any
		} `json:"is_jvm"`
		Suggestion []struct {
			In  []any
			Out string
		}
	}
	load(t, "pure.json", &g)
	for h, want := range g.ValidHost {
		if ValidHost(h) != want {
			t.Errorf("ValidHost(%q)", h)
		}
	}
	for _, c := range g.ParseLabel {
		got := ruleJSON(ParseLabel(c.In))
		if !reflect.DeepEqual(norm(got), norm(c.Out)) {
			t.Errorf("ParseLabel(%v) = %v, python %v", c.In, got, c.Out)
		}
	}
	for _, c := range g.ParseTTL {
		if s, ok := c.Out.(string); ok && strings.HasPrefix(s, "PYEXC") {
			continue // Python raises (inf overflow); Go answers the default
		}
		if got := ParseTTL(c.In); norm(got) != c.Out && !reflect.DeepEqual(norm(got), c.Out) {
			t.Errorf("ParseTTL(%v) = %v, python %v", c.In, got, c.Out)
		}
	}
	for _, c := range g.MergeJava {
		p, _ := c.In[2].(json.Number).Int64()
		var ex string
		if c.In[0] != nil {
			ex = c.In[0].(string)
		}
		if got := MergeJavaProxyOpts(ex, c.In[1].(string), int(p), c.In[3].(string)); got != c.Out {
			t.Errorf("MergeJavaProxyOpts(%v) = %q, python %q", c.In, got, c.Out)
		}
	}
	for _, c := range g.IsJVM {
		if s, ok := c.Out.(string); ok && strings.HasPrefix(s, "PYEXC") {
			continue
		}
		if got := IsJVMService(c.In); got != c.Out.(bool) {
			t.Errorf("IsJVMService(%v) = %v", c.In, got)
		}
	}
	for _, c := range g.Suggestion {
		var rule Rule
		has := false
		switch cur := c.In[0].(type) {
		case string:
			rule, has = ParseLabel(cur)
		case []any:
			has = true
			for _, h := range cur {
				rule.Hosts = append(rule.Hosts, h.(string))
			}
		}
		var nh []string
		for _, h := range c.In[1].([]any) {
			nh = append(nh, h.(string))
		}
		if got := Suggestion(rule, has, nh); got != c.Out {
			t.Errorf("Suggestion(%v) = %q, python %q", c.In, got, c.Out)
		}
	}
}

type step struct {
	Op      string
	Args    []any
	Result  any
	Err     *string
	Files   map[string]string
	Reloads int
	Notes   int
	Clock   float64
}

func rulesFrom(v any) map[string]Rule {
	out := map[string]Rule{}
	for k, x := range v.(map[string]any) {
		r, _ := ruleFromJSON(x)
		out[k] = r
	}
	return out
}

func strMapOrNil(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		out[k] = x.(string)
	}
	return out
}

func strOrEmpty(v any) string { s, _ := v.(string); return s }

func hostsJSON(m map[string]map[string]bool) any {
	out := map[string]any{}
	for k, set := range m {
		var l []string
		for h := range set {
			l = append(l, h)
		}
		sort.Strings(l)
		a := make([]any, len(l))
		for i, h := range l {
			a[i] = h
		}
		out[k] = a
	}
	return out
}

func snapshot(t *testing.T, dir string) map[string]string {
	out := map[string]string{}
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	return out
}

func TestScenarioMatchesPython(t *testing.T) {
	var g struct{ Steps []step }
	load(t, "scenario.json", &g)
	root := t.TempDir()
	t.Setenv("OM_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("OM_HOME", filepath.Join(root, "home"))
	d := state.NewDirs()
	clock := time.Unix(1_700_000_000, 500_000_000)
	reloads, notes := 0, 0
	e := New(d)
	e.Now = func() time.Time { return clock }
	e.Notify = func(string, string, string) { notes++ }
	e.Run = func(c []string) state.Result {
		if len(c) > 3 && c[1] == "exec" && c[3] == "squid" {
			reloads++
		}
		return state.Result{}
	}
	for i, s := range g.Steps {
		clock = time.Unix(0, int64(s.Clock*1e9))
		var res any
		var err error
		a := s.Args
		switch s.Op {
		case "alloc":
			res, err = e.AllocateServiceIP(a[0].(string), a[1].(string), strOrEmpty(a[2]))
		case "render_acl":
			var ips map[string]string
			res, err = e.RenderACL(a[0].(string), rulesFrom(a[1]), ips)
		case "render_workspace":
			res, err = e.RenderWorkspace("podman", a[0].(string), rulesFrom(a[1]), a[2].(bool), strMapOrNil(a[3]))
		case "write_override":
			var p string
			cfg, _ := a[2].(map[string]any)
			p, err = e.WriteOverride(a[0].(string), a[1].(string), cfg, strMapOrNil(a[3]), strOrEmpty(a[4]), strMapOrNil(a[5]))
			if p != "" {
				res = filepath.Base(p)
			}
		case "init_learn":
			ttl, _ := a[2].(json.Number).Int64()
			res, err = e.InitLearn(a[0].(string), a[1].(string), int(ttl), a[3].(bool))
		case "learn_remaining":
			res = e.LearnRemaining(a[0].(string), a[1].(string))
		case "is_learn_expired":
			res = e.IsLearnExpired(a[0].(string), a[1].(string))
		case "record":
			var ts float64
			if n, ok := a[3].(json.Number); ok {
				ts, _ = n.Float64()
			}
			err = e.RecordLearnedHost(a[0].(string), a[1].(string), a[2].(string), ts)
		case "denied", "used":
			f := e.DeniedHosts
			if s.Op == "used" {
				f = e.UsedHosts
			}
			var m map[string]map[string]bool
			m, err = f(a[0].(string), strMapOrNil(a[1]))
			res = hostsJSON(m)
		case "all_service_ips":
			res = e.AllServiceIPs()
		default:
			t.Fatalf("step %d: unknown op %s", i, s.Op)
		}
		if err != nil && s.Err == nil {
			t.Fatalf("step %d %s %v: %v", i, s.Op, a, err)
		}
		if s.Result != nil && !reflect.DeepEqual(norm(res), s.Result) {
			t.Errorf("step %d %s %v:\n go     %v\n python %v", i, s.Op, a, norm(res), s.Result)
		}
		if got := snapshot(t, filepath.Join(d.State, "egress")); !reflect.DeepEqual(got, s.Files) {
			for k, v := range s.Files {
				if got[k] != v {
					t.Errorf("step %d %s %v: file %s\n go:\n%s\n python:\n%s", i, s.Op, a, k, got[k], v)
				}
			}
			for k := range got {
				if _, ok := s.Files[k]; !ok {
					t.Errorf("step %d %s: extra file %s", i, s.Op, k)
				}
			}
		}
		if reloads != s.Reloads || notes != s.Notes {
			t.Errorf("step %d %s: reloads %d/%d notes %d/%d", i, s.Op, reloads, s.Reloads, notes, s.Notes)
		}
		if i+1 < len(g.Steps) {
			clock = time.Unix(0, int64(g.Steps[i+1].Clock*1e9)) // the golden's clock before the next step
		}
	}
}

func TestEditsMatchPython(t *testing.T) {
	var g struct {
		Texts map[string]string
		Edits []struct {
			Name  string
			Svc   string
			Span  []any
			Ok    bool
			After string
		}
	}
	load(t, "edits.json", &g)
	for _, c := range g.Edits {
		txt := g.Texts[c.Name]
		s, e, ind, ok := FindServiceSpan(txt, c.Svc)
		if (c.Span != nil) != ok {
			t.Errorf("%s/%s: span found %v, python %v", c.Name, c.Svc, ok, c.Span)
		} else if ok {
			want := []any{json.Number(itoa(s)), json.Number(itoa(e)), json.Number(itoa(ind))}
			if !reflect.DeepEqual(want, c.Span) {
				t.Errorf("%s/%s: span %v python %v", c.Name, c.Svc, want, c.Span)
			}
		}
		p := filepath.Join(t.TempDir(), "edit.yml")
		os.WriteFile(p, []byte(txt), 0o644)
		if got := ApplyEgressLabel(p, c.Svc, []string{"new.example.com", "a.b"}); got != c.Ok {
			t.Errorf("%s/%s: applied %v, python %v", c.Name, c.Svc, got, c.Ok)
		}
		if b, _ := os.ReadFile(p); string(b) != c.After {
			t.Errorf("%s/%s:\n go:\n%q\n python:\n%q", c.Name, c.Svc, b, c.After)
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestBaseConfIsPythonsAndPortMatches(t *testing.T) {
	if !strings.Contains(BaseConf, "http_port 3128\n") || Port != 3128 {
		t.Fatal("port drifted from the embedded squid.conf")
	}
	if !strings.Contains(BaseConf, "fe80::/10") {
		t.Fatal("IPv6 private ranges missing")
	}
}

func TestImageTracksContainerfile(t *testing.T) {
	t.Setenv("OM_HOME", t.TempDir())
	e := New(state.NewDirs())
	empty := e.Image()
	dir := filepath.Join(e.D.Core, "egress")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "Containerfile"), []byte("FROM x\n"), 0o644)
	a := e.Image()
	os.WriteFile(filepath.Join(dir, "Containerfile"), []byte("FROM y\n"), 0o644)
	if a == empty || a == e.Image() || !strings.HasPrefix(a, "localhost/om-egress:") || len(a) != len("localhost/om-egress:")+12 {
		t.Fatal(empty, a, e.Image())
	}
}
