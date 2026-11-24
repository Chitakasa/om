package cli

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/composefix"
)

// project is the set of compose files an import brings in: the main file plus the files it `include:`s or `extends:`
// from, all inside the staged folder. Each is edited as text by composefix; the engine's resolved config is the truth
// about what a service ends up with (anchors, merge keys, extends and includes are resolved there), and is used to
// read what is inherited and to prove afterwards that nothing but ports and labels changed.
type project struct {
	dir   string   // the staged folder
	files []string // paths relative to dir, main first
	orig  map[string]string
	notes []string
}

// loadProject reads the main compose file and follows include: and extends: files that are inside the folder.
func loadProject(dir, mainFile string) (*project, error) {
	rel, err := filepath.Rel(dir, mainFile)
	if err != nil {
		return nil, err
	}
	p := &project{dir: dir, orig: map[string]string{}}
	queue := []string{filepath.ToSlash(rel)}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		if _, done := p.orig[f]; done {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil {
			if f == filepath.ToSlash(rel) {
				return nil, err
			}
			p.notes = append(p.notes, f+" is named by the compose file but is not in the folder")
			continue
		}
		p.files = append(p.files, f)
		p.orig[f] = string(b)
		doc, err := composefix.Parse(string(b))
		refs := []string{}
		if err == nil {
			refs = append(refs, doc.Includes()...)
			for _, svc := range doc.Services() {
				if file, _, ok := doc.Extends(svc); ok && file != "" {
					refs = append(refs, file)
				}
			}
		}
		for _, r := range refs {
			if r == "" || strings.Contains(r, "${") {
				continue
			}
			t := path.Clean(path.Join(path.Dir(f), r))
			if t == ".." || strings.HasPrefix(t, "../") || path.IsAbs(t) {
				p.notes = append(p.notes, f+" refers to "+r+", outside the folder; om cannot change it")
				continue
			}
			queue = append(queue, t)
		}
	}
	return p, nil
}

// cfgServices are the engine's resolved services (nil without a config).
func cfgServices(cfg map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	m, _ := cfg["services"].(map[string]any)
	for k, v := range m {
		if sv, ok := v.(map[string]any); ok {
			out[k] = sv
		}
	}
	return out
}

// cfgPorts are the container ports a resolved service publishes, as expose entries ("80", "53/udp").
func cfgPorts(sv map[string]any) []string {
	var out []string
	list, _ := sv["ports"].([]any)
	for _, it := range list {
		m, _ := it.(map[string]any)
		t, ok := m["target"].(float64)
		if !ok {
			continue
		}
		cp := strconv.Itoa(int(t))
		if pr, _ := m["protocol"].(string); pr != "" && pr != "tcp" {
			cp += "/" + pr
		}
		out = appendUnique(out, cp)
	}
	return out
}

func cfgExpose(sv map[string]any) []string {
	var out []string
	list, _ := sv["expose"].([]any)
	for _, it := range list {
		out = appendUnique(out, fmt.Sprint(it))
	}
	return out
}

func cfgLabels(sv map[string]any) []composefix.KV {
	m, _ := sv["labels"].(map[string]any)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]composefix.KV, 0, len(keys))
	for _, k := range keys {
		out = append(out, composefix.KV{Key: k, Value: fmt.Sprint(m[k])})
	}
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func quoteAll(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = `"` + p + `"`
	}
	return out
}

// apply makes the edits on fresh copies of the original text: ports become expose on every service, and the main
// service gets the labels (defaults keep what the author wrote; chosen ones replace). cfg is the engine's resolved
// config of the original, or nil when there is no engine.
func (p *project) apply(cfg map[string]any, main, wsID, name string, defaults, chosen []composefix.KV, others map[string][]composefix.KV) (texts map[string]string, changes, advice []string, err error) {
	docs := map[string]*composefix.Doc{}
	owner := map[string]string{}
	var order []string
	for _, f := range p.files {
		d, perr := composefix.Parse(p.orig[f])
		if perr != nil {
			if f == p.files[0] {
				return nil, nil, nil, perr
			}
			continue
		}
		docs[f] = d
		for _, svc := range d.Services() {
			owner[svc] = f
			order = append(order, svc)
		}
	}
	resolved := cfgServices(cfg)
	done := map[string]bool{}

	var portsOf func(file, svc string, depth int)
	portsOf = func(file, svc string, depth int) {
		key := file + "\x00" + svc
		if done[key] || depth > 8 {
			return
		}
		done[key] = true
		doc := docs[file]
		inh, ierr := doc.Inherits(svc)
		if ierr != nil {
			advice = append(advice, svc+": "+ierr.Error())
			return
		}
		if inh.Alias {
			if err = doc.ExpandAlias(svc); err != nil {
				return
			}
			inh.Merge = true
		}
		if c, berr := doc.Blockify(svc); berr != nil {
			advice = append(advice, berr.Error())
			return
		} else if len(c) > 0 {
			changes = append(changes, c...)
		}
		sv := resolved[svc]
		have := cfgPorts(sv)
		inherited := inh.Merge || contains(inh.AliasFields, "ports") || contains(inh.AliasFields, "expose")
		switch {
		case inherited && len(have) > 0:
			if cfg == nil {
				advice = append(advice, svc+": it takes ports from a merge key or alias, which needs the compose engine to resolve; change them to `expose:` yourself")
				return
			}
			exp := cfgExpose(sv)
			for _, cp := range have {
				exp = appendUnique(exp, cp)
			}
			if err = doc.ReplaceList(svc, "ports", nil); err != nil {
				return
			}
			if err = doc.ReplaceList(svc, "expose", quoteAll(exp)); err != nil {
				return
			}
			changes = append(changes, fmt.Sprintf("%s: ports (inherited) becomes expose %s", svc, strings.Join(have, ", ")))
		case doc.HasField(svc, "ports"):
			c, _, adv, perr := doc.PortsToExpose(svc)
			if perr != nil {
				advice = append(advice, svc+": "+perr.Error())
				return
			}
			changes, advice = append(changes, c...), append(advice, adv...)
		}
		if bf, bs, ok := doc.Extends(svc); ok { // ports come in through extends: change the base
			target := file
			if bf != "" {
				target = path.Clean(path.Join(path.Dir(file), bf))
			}
			if _, known := docs[target]; known {
				portsOf(target, bs, depth+1)
			}
		}
	}
	for _, svc := range order {
		portsOf(owner[svc], svc, 0)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if f, ok := owner[main]; ok {
		doc := docs[f]
		inh, _ := doc.Inherits(main)
		if inh.Alias {
			if err = doc.ExpandAlias(main); err != nil {
				return nil, nil, nil, err
			}
			inh.Merge = true
		}
		if inh.Merge && !doc.HasField(main, "labels") || contains(inh.AliasFields, "labels") {
			if cfg == nil {
				advice = append(advice, main+": its labels come from an alias or merge key, which needs the compose engine to resolve; add the labels yourself")
			} else if err = doc.ReplaceLabels(main, cfgLabels(resolved[main])); err != nil {
				return nil, nil, nil, err
			}
		}
		// the edge reaches the service as <workspace>_<folder>, on the workspace network
		cn := "${WORKSPACE_ID:-" + wsID + "}_" + name
		if err = doc.SetScalar(main, "container_name", cn); err != nil {
			return nil, nil, nil, err
		}
		if err = doc.EnsureNetworkRef(main, "default"); err != nil {
			advice = append(advice, err.Error())
		}
		changes = append(changes, main+": named "+wsID+"_"+name+" so the edge can reach it")
		root := docs[p.files[0]]
		replaced, nerr := root.EnsureDefaultNetwork("${WORKSPACE_NET:-" + wsID + "_net}")
		if nerr != nil {
			advice = append(advice, nerr.Error())
		} else {
			changes = append(changes, pick(replaced, "networks: your default network is now the workspace network", "networks: added the workspace network (external), so the edge reaches the service"))
		}
		if err = doc.AddLabels(main, defaults, false); err != nil {
			return nil, nil, nil, err
		}
		if err = doc.AddLabels(main, chosen, true); err != nil {
			return nil, nil, nil, err
		}
	} else {
		return nil, nil, nil, fmt.Errorf("service %s was not found in the files", main)
	}
	for svc, kvs := range others {
		f, ok := owner[svc]
		if !ok || len(kvs) == 0 {
			continue
		}
		d := docs[f]
		inh, _ := d.Inherits(svc)
		if inh.Merge && !d.HasField(svc, "labels") || contains(inh.AliasFields, "labels") {
			if cfg == nil {
				advice = append(advice, svc+": its labels come from an alias or merge key, which needs the compose engine to resolve; add them yourself")
				continue
			}
			if err = d.ReplaceLabels(svc, cfgLabels(resolved[svc])); err != nil {
				return nil, nil, nil, err
			}
		}
		if _, err = d.Blockify(svc); err != nil {
			return nil, nil, nil, err
		}
		if err = d.AddLabels(svc, kvs, true); err != nil {
			return nil, nil, nil, err
		}
	}
	texts = map[string]string{}
	for f, d := range docs {
		texts[f] = d.String()
	}
	for f, t := range p.orig {
		if _, ok := texts[f]; !ok {
			texts[f] = t
		}
	}
	return texts, changes, advice, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// verify compares the engine's resolved config before and after the edit and returns every difference that is not
// the intended one: ports gone and the same container ports exposed, labels kept (except the ones chosen), and
// nothing else changed.
func verifyImport(before, after map[string]any, chosen []composefix.KV, main, wsID, name string) []string {
	var bad []string
	b, a := cfgServices(before), cfgServices(after)
	if len(b) != len(a) {
		bad = append(bad, fmt.Sprintf("the number of services changed (%d to %d)", len(b), len(a)))
	}
	rewrite := map[string]bool{}
	for _, kv := range chosen {
		rewrite[kv.Key] = true
	}
	for name2, sb := range b {
		sa, ok := a[name2]
		if !ok {
			bad = append(bad, name2+": the service is missing after the edit")
			continue
		}
		keys := map[string]bool{}
		for k := range sb {
			keys[k] = true
		}
		for k := range sa {
			keys[k] = true
		}
		for k := range keys {
			switch k {
			case "ports", "expose", "labels":
				continue
			case "container_name", "networks":
				if name2 == main {
					continue
				}
			}
			if !reflect.DeepEqual(sb[k], sa[k]) {
				bad = append(bad, fmt.Sprintf("%s: %s changed", name2, k))
			}
		}
		if p := cfgPorts(sa); len(p) > 0 {
			bad = append(bad, name2+": still publishes host ports")
		}
		want := cfgExpose(sb)
		for _, cp := range cfgPorts(sb) {
			want = appendUnique(want, cp)
		}
		got := cfgExpose(sa)
		sort.Strings(want)
		sort.Strings(got)
		if !reflect.DeepEqual(want, got) {
			bad = append(bad, fmt.Sprintf("%s: exposed ports are %v, expected %v", name2, got, want))
		}
		lb, la := cfgLabelMap(sb), cfgLabelMap(sa)
		for k, v := range lb {
			if got, ok := la[k]; !ok || (got != v && !rewrite[k]) {
				bad = append(bad, fmt.Sprintf("%s: label %s was %q and is now %q", name2, k, v, got))
			}
		}
	}
	for _, key := range []string{"volumes", "secrets", "configs"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			bad = append(bad, key+" changed")
		}
	}
	if sa, ok := a[main]; ok {
		if cn := fmt.Sprint(sa["container_name"]); cn != wsID+"_"+name {
			bad = append(bad, fmt.Sprintf("%s: container_name is %s, expected %s_%s", main, cn, wsID, name))
		}
		if nets, _ := sa["networks"].(map[string]any); nets == nil {
			bad = append(bad, main+": is not on the workspace network")
		} else if _, ok := nets["default"]; !ok {
			bad = append(bad, main+": is not on the workspace network")
		}
	}
	bn, _ := before["networks"].(map[string]any)
	an, _ := after["networks"].(map[string]any)
	if def, _ := an["default"].(map[string]any); def == nil || def["external"] != true {
		bad = append(bad, "the default network is not the external workspace network")
	}
	for k, v := range bn {
		if k != "default" && !reflect.DeepEqual(v, an[k]) {
			bad = append(bad, "network "+k+" changed")
		}
	}
	for k := range an {
		if _, had := bn[k]; !had && k != "default" {
			bad = append(bad, "network "+k+" appeared")
		}
	}
	sort.Strings(bad)
	return bad
}

func cfgLabelMap(sv map[string]any) map[string]string {
	out := map[string]string{}
	for _, kv := range cfgLabels(sv) {
		out[kv.Key] = kv.Value
	}
	return out
}
