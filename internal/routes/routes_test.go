package routes

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type gcase struct {
	Args   map[string]any `json:"args"`
	Result any            `json:"result"`
	Stdout string         `json:"stdout"`
	Err    *string        `json:"err"`
}

func loadGolden(t *testing.T, name string) map[string][]gcase {
	t.Helper()
	b, err := os.ReadFile("../../testdata/golden/" + name)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string][]gcase
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func strMap(v any) map[string]string {
	out := map[string]string{}
	m, _ := v.(map[string]any)
	for k, x := range m {
		out[k] = x.(string)
	}
	return out
}

func strList(v any) []string {
	out := []string{}
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

func warnText(ws []Warning) string {
	var b strings.Builder
	for _, w := range ws {
		b.WriteString(w.String() + "\n")
	}
	return b.String()
}

func optionsFrom(v any) Options {
	m, _ := v.(map[string]any)
	o := Options{Log: "on"}
	if m == nil {
		return Options{}
	}
	o.KeepPrefix, _ = m["keep_prefix"].(bool)
	o.Aliases = strList(m["aliases"])
	o.DashboardPaths = strList(m["dashboard_paths"])
	if s, ok := m["log"].(string); ok {
		o.Log = s
	} else {
		o.Log = ""
	}
	o.Snippet = str(m, "snippet")
	return o
}

func netJSON(p *NetPolicy) any {
	if p == nil {
		return nil
	}
	var allow any
	if p.Allow != nil {
		allow = stringsToAny(p.Allow)
	}
	return map[string]any{"allow": allow, "deny": stringsToAny(p.Deny)}
}

func stringsToAny(l []string) []any {
	out := []any{}
	for _, s := range l {
		out = append(out, s)
	}
	return out
}

func normalize(v any) any {
	b, _ := json.Marshal(v)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	dec.Decode(&out)
	return out
}

func eachGolden(t *testing.T, fn string, f func(t *testing.T, c gcase)) {
	for _, file := range []string{"routes_recorded.json", "routes_manual.json"} {
		for i, c := range loadGolden(t, file)[fn] {
			if c.Err != nil {
				continue
			}
			t.Run(file[:len(file)-5]+"/"+fn, func(t *testing.T) { _ = i; f(t, c) })
		}
	}
}

func TestComposeLabelsMatchesPython(t *testing.T) {
	n := 0
	eachGolden(t, "compose_labels", func(t *testing.T, c gcase) {
		n++
		if got, want := ComposeLabels(str(c.Args, "content")), strMap(c.Result); !reflect.DeepEqual(got, want) {
			t.Errorf("%q\n go     %v\n python %v", c.Args["content"], got, want)
		}
	})
	t.Log(n, "cases")
}

func TestLabelPathsMatchesPython(t *testing.T) {
	eachGolden(t, "label_paths", func(t *testing.T, c gcase) {
		got, warns := LabelPaths(strMap(c.Args["labels"]), str(c.Args, "key"), str(c.Args, "sname"))
		if g, w := normalize(append([]string{}, got...)), normalize(c.Result); !reflect.DeepEqual(g, w) && !(len(got) == 0 && len(strList(c.Result)) == 0) {
			t.Errorf("%v: %v want %v", c.Args, got, c.Result)
		}
		if warnText(warns) != c.Stdout {
			t.Errorf("%v: warnings %q want %q", c.Args, warnText(warns), c.Stdout)
		}
	})
}

func TestNetPolicyMatchesPython(t *testing.T) {
	eachGolden(t, "net_policy", func(t *testing.T, c gcase) {
		p, probs := ParseNetPolicy(strMap(c.Args["labels"]), strList(c.Args["vpn_allow"]))
		want := c.Result.([]any)
		if !reflect.DeepEqual(normalize(netJSON(p)), normalize(want[0])) {
			t.Errorf("%v:\n go     %v\n python %v", c.Args, netJSON(p), want[0])
		}
		if !reflect.DeepEqual(normalize(stringsToAny(probs)), normalize(want[1])) {
			t.Errorf("%v: problems %q want %v", c.Args, probs, want[1])
		}
	})
}

func TestRouteOptionsMatchesPython(t *testing.T) {
	eachGolden(t, "route_options", func(t *testing.T, c gcase) {
		var labels map[string]string
		if l, ok := c.Args["labels"].(map[string]any); ok {
			labels = strMap(l)
		}
		// route_options asks the settings for the VPN allow-list; the recorded run had none (its net_policy cases
		// that need it are in the net_policy corpus)
		o, warns := RouteOptions(str(c.Args, "content"), str(c.Args, "sname"), labels, nil)
		want := c.Result.(map[string]any)
		delete(want, "snippet") // added to the returned dict by the caller after the call
		if mentionsVPNKeyword(c) {
			return // the recorded run read a VPN allow-list from its settings; net_policy's corpus covers `vpn`
		}
		got := map[string]any{
			"keep_prefix": o.KeepPrefix, "aliases": stringsToAny(o.Aliases), "dashboard_paths": stringsToAny(o.DashboardPaths),
			"net": netJSON(o.Net), "net_problems": stringsToAny(o.NetProblems), "log": o.Log,
		}
		if !reflect.DeepEqual(normalize(got), normalize(want)) {
			t.Errorf("%v:\n go     %v\n python %v", c.Args, got, want)
		}
		if warnText(warns) != c.Stdout {
			t.Errorf("%v: warnings %q want %q", c.Args, warnText(warns), c.Stdout)
		}
	})
}

func TestConfigMetaMatchesPython(t *testing.T) {
	eachGolden(t, "config_meta", func(t *testing.T, c gcase) {
		cfg, _ := c.Args["cfg"].(map[string]any)
		port, pub, noWeb, labels := ConfigMeta(cfg, str(c.Args, "sname"))
		want := c.Result.([]any)
		meta := want[0].([]any)
		wp, _ := meta[0].(json.Number).Int64()
		if int64(port) != wp || pub != meta[1].(bool) || noWeb != meta[2].(bool) {
			t.Errorf("%v: %d %v %v want %v", c.Args["cfg"], port, pub, noWeb, meta)
		}
		if !reflect.DeepEqual(labels, strMap(want[1])) {
			t.Errorf("%v: labels %v want %v", c.Args["cfg"], labels, want[1])
		}
	})
}

func TestParseServiceMetaMatchesPython(t *testing.T) {
	eachGolden(t, "parse_service_meta", func(t *testing.T, c gcase) {
		port, pub, noWeb := ParseServiceMeta(str(c.Args, "content"), "s")
		want := c.Result.([]any)
		wp, _ := want[0].(json.Number).Int64()
		if int64(port) != wp || pub != want[1].(bool) || noWeb != want[2].(bool) {
			t.Errorf("%q: %d %v %v want %v", c.Args["content"], port, pub, noWeb, want)
		}
	})
}

func TestValidateSnippetMatchesPython(t *testing.T) {
	n := 0
	eachGolden(t, "validate_snippet", func(t *testing.T, c gcase) {
		n++
		got := ValidateSnippet(str(c.Args, "text"))
		if !reflect.DeepEqual(normalize(stringsToAny(got)), normalize(c.Result)) {
			t.Errorf("%q:\n go     %q\n python %v", c.Args["text"], got, c.Result)
		}
	})
	t.Log(n, "cases")
}

func TestAliasIsReservedMatchesPython(t *testing.T) {
	eachGolden(t, "alias_is_reserved", func(t *testing.T, c gcase) {
		if AliasIsReserved(str(c.Args, "path")) != c.Result.(bool) {
			t.Errorf("%q", c.Args["path"])
		}
	})
}

func TestRenderVhostMatchesPython(t *testing.T) {
	eachGolden(t, "render_vhost", func(t *testing.T, c gcase) {
		slot := -1
		if n, ok := c.Args["slot"].(json.Number); ok {
			v, _ := n.Int64()
			slot = int(v)
		}
		port, _ := c.Args["port"].(json.Number).Int64()
		pub, _ := c.Args["is_public"].(bool)
		o := optionsFrom(c.Args["opts"])
		if got := RenderVhost(str(c.Args, "ws_id"), str(c.Args, "sname"), int(port), o, slot, pub); got != c.Result.(string) {
			t.Errorf("%v:\n%s\npython:\n%s", c.Args, got, c.Result)
		}
	})
}

func TestRenderAliasMatchesPython(t *testing.T) {
	eachGolden(t, "render_alias", func(t *testing.T, c gcase) {
		port, _ := c.Args["port_no"].(json.Number).Int64()
		pub, _ := c.Args["is_public"].(bool)
		if got := RenderAlias(str(c.Args, "ws_id"), str(c.Args, "sname"), int(port), pub, optionsFrom(c.Args["opts"])); got != c.Result.(string) {
			t.Errorf("%v:\n%s\npython:\n%s", c.Args, got, c.Result)
		}
	})
}

func mentionsVPNKeyword(c gcase) bool {
	text := strings.ToLower(str(c.Args, "content"))
	if l, ok := c.Args["labels"].(map[string]any); ok {
		for k, v := range l {
			text += "\n" + strings.ToLower(k) + "=" + strings.ToLower(asStr(v))
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "om.net.allow") && strings.Contains(line, "vpn") {
			return true
		}
	}
	return false
}

func asStr(v any) string { s, _ := v.(string); return s }
