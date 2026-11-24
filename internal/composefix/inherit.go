package composefix

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var mergeRE = regexp.MustCompile(`^\s*<<:\s*(\*|\[)`)

// Inheritance says how a service gets content from somewhere else in the file.
type Inheritance struct {
	Alias       bool     // `web: *common`: the whole service is another one
	Merge       bool     // `<<: *common` inside the service
	AliasFields []string // fields written as `key: *anchor`
	Flow        bool     // the service is written as `web: {image: x, ...}`
}

// Inherits reports how the service gets content from elsewhere (an alias, a merge key, aliased fields).
func (d *Doc) Inherits(service string) (Inheritance, error) {
	var inh Inheritance
	for _, sp := range d.spans() {
		if sp.name != service {
			continue
		}
		head := strings.TrimSpace(keyRE.FindStringSubmatch(d.lines[sp.start])[3])
		switch {
		case strings.HasPrefix(head, "*"):
			inh.Alias = true
		case strings.HasPrefix(head, "{"):
			inh.Flow = true
		case head != "" && !strings.HasPrefix(head, "#") && !strings.HasPrefix(head, "&"):
			return inh, fmt.Errorf("service %s is written in a form om cannot read", service)
		}
		if inh.Alias || inh.Flow {
			return inh, nil
		}
		for i := sp.start + 1; i < sp.end; i++ {
			if mergeRE.MatchString(d.lines[i]) {
				inh.Merge = true
			}
		}
		fs, _ := d.fields(sp)
		for _, f := range fs {
			if strings.HasPrefix(f.inline, "*") {
				inh.AliasFields = append(inh.AliasFields, f.name)
			}
		}
		return inh, nil
	}
	return inh, fmt.Errorf("no service named %s", service)
}

// Blockify rewrites a service that is written in flow style (`web: {image: x, ports: [...]}`) as a block mapping, and
// turns its labels, ports and expose into block lists when they are flow collections that span lines or hold mappings
// (a one-line list of plain ports is left alone: it is edited in place). Comments inside the rewritten flow text are
// lost, and what it did is returned in words.
func (d *Doc) Blockify(service string) (changed []string, err error) {
	sp, err := d.span0(service)
	if err != nil {
		return nil, err
	}
	head := strings.TrimSpace(keyRE.FindStringSubmatch(d.lines[sp.start])[3])
	if strings.HasPrefix(head, "{") {
		end := d.lastReal(sp.start, sp.end) + 1
		text := head
		for i := sp.start + 1; i < end; i++ {
			text += "\n" + d.lines[i]
		}
		n, perr := parseFlow(text)
		if perr != nil || n.kind != 'm' {
			return nil, fmt.Errorf("service %s: cannot read its flow mapping: %v", service, perr)
		}
		block := append([]string{pad(d.svcIndent) + keyRE.FindStringSubmatch(d.lines[sp.start])[2] + ":"}, n.lines(d.svcIndent+2)...)
		d.replace(sp.start, end, block)
		changed = append(changed, service+": rewrote its one-line mapping as a block")
	}
	sp, err = d.span(service)
	if err != nil {
		return changed, err
	}
	for _, name := range []string{"labels", "ports", "expose", "networks"} {
		fs, fi := d.fields(sp)
		f, ok := findField(fs, name)
		if !ok || !(strings.HasPrefix(f.inline, "[") || strings.HasPrefix(f.inline, "{")) {
			continue
		}
		end := d.lastReal(f.line, f.end) + 1
		text := d.lines[f.line][strings.Index(d.lines[f.line], ":")+1:]
		for i := f.line + 1; i < end; i++ {
			text += "\n" + d.lines[i]
		}
		simple := name != "labels" && name != "networks" && end == f.line+1 && !strings.Contains(f.inline, "{")
		if simple {
			continue
		}
		n, perr := parseFlow(text)
		if perr != nil {
			return changed, fmt.Errorf("service %s: cannot read its %s: %v", service, name, perr)
		}
		block := append([]string{pad(fi) + name + ":" + commentOf(d.lines[f.line])}, n.lines(fi+2)...)
		d.replace(f.line, end, block)
		changed = append(changed, service+": rewrote "+name+" as a block list")
		if sp, err = d.span(service); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// span0 is span without the refusal for an opaque (alias or flow) service.
func (d *Doc) span0(service string) (span, error) {
	for _, s := range d.spans() {
		if s.name == service {
			return s, nil
		}
	}
	return span{}, fmt.Errorf("no service named %s", service)
}

func (d *Doc) replace(from, to int, with []string) {
	d.lines = append(d.lines[:from], append(append([]string{}, with...), d.lines[to:]...)...)
	d.svcEnd += len(with) - (to - from)
}

// ExpandAlias turns `web: *common` into a block that merges it (`<<: *common`), so the service can carry its own keys.
func (d *Doc) ExpandAlias(service string) error {
	sp, err := d.span0(service)
	if err != nil {
		return err
	}
	m := keyRE.FindStringSubmatch(d.lines[sp.start])
	rest := strings.TrimSpace(m[3])
	if !strings.HasPrefix(rest, "*") {
		return fmt.Errorf("service %s is not an alias", service)
	}
	ref, note := rest, ""
	if loc := cutCommentRE.FindStringIndex(rest); loc != nil {
		ref, note = strings.TrimSpace(rest[:loc[0]]), rest[loc[0]:]
	}
	d.replace(sp.start, sp.start+1, []string{pad(d.svcIndent) + m[2] + ":" + note, pad(d.svcIndent+2) + "<<: " + ref})
	return nil
}

// ReplaceList sets a service's key to a block list of the given (already quoted) items, replacing whatever form it had
// (an alias, a one-line list, a mapping). No items writes `key: []`. A merge key in the service stays, and the new key
// overrides what it brought in.
func (d *Doc) ReplaceList(service, key string, items []string) error {
	sp, err := d.span(service)
	if err != nil {
		return err
	}
	fs, fi := d.fields(sp)
	var block []string
	if len(items) == 0 {
		block = []string{pad(fi) + key + ": []"}
	} else {
		block = []string{pad(fi) + key + ":"}
		for _, it := range items {
			block = append(block, pad(fi+2)+"- "+it)
		}
	}
	if f, ok := findField(fs, key); ok {
		d.replace(f.line, d.lastReal(f.line, f.end)+1, block)
		return nil
	}
	if fi == d.svcIndent+2 && len(fs) == 0 && d.lastReal(sp.start+1, sp.end) < sp.start+1 {
		fi = d.svcIndent + 2
	}
	d.insert(d.lastReal(sp.start+1, sp.end)+1, block...)
	return nil
}

// ReplaceLabels sets a service's labels to exactly these, as a block list.
func (d *Doc) ReplaceLabels(service string, kvs []KV) error {
	items := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		items = append(items, quoteYAML(kv.Key+"="+kv.Value))
	}
	return d.ReplaceList(service, "labels", items)
}

// HasField reports whether the service itself writes the key (not through a merge key or an alias).
func (d *Doc) HasField(service, key string) bool {
	sp, err := d.span(service)
	if err != nil {
		return false
	}
	fs, _ := d.fields(sp)
	_, ok := findField(fs, key)
	return ok
}

// Extends reads the service's `extends:`: the file it names (empty for the same file) and the service it extends.
func (d *Doc) Extends(service string) (file, base string, ok bool) {
	sp, err := d.span(service)
	if err != nil {
		return "", "", false
	}
	fs, _ := d.fields(sp)
	f, found := findField(fs, "extends")
	if !found {
		return "", "", false
	}
	if f.inline != "" && !strings.HasPrefix(f.inline, "{") {
		return "", unquote(f.inline), true
	}
	text := f.inline
	for i := f.line + 1; i < f.end; i++ {
		if !skippable(d.lines[i]) {
			text += "\n" + strings.TrimSpace(d.lines[i])
		}
	}
	if f.inline != "" {
		n, err := parseFlow(text)
		if err != nil || n.kind != 'm' {
			return "", "", false
		}
		file, base = scalarOf(n.get("file")), scalarOf(n.get("service"))
		return file, base, base != ""
	}
	for _, l := range strings.Split(text, "\n") {
		if m := longKeyRE.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			v := unquote(strings.TrimSpace(cutCommentRE.ReplaceAllString(m[2], "")))
			switch m[1] {
			case "file":
				file = v
			case "service":
				base = v
			}
		}
	}
	return file, base, base != ""
}

func scalarOf(n *node) string {
	if n == nil || n.kind != 's' {
		return ""
	}
	return unquote(n.s)
}

// Includes are the files named by the top-level `include:` (a list of paths, or entries with `path:`).
func (d *Doc) Includes() []string {
	var out []string
	in := false
	for _, l := range d.lines {
		if indentOf(l) == 0 && !skippable(l) {
			in = strings.HasPrefix(l, "include:")
			if in {
				if rest := strings.TrimSpace(strings.TrimPrefix(l, "include:")); strings.HasPrefix(rest, "[") {
					if n, err := parseFlow(rest); err == nil {
						for _, it := range n.list {
							out = append(out, scalarOf(it)+scalarOf(it.get("path")))
						}
					}
				}
			}
			continue
		}
		if !in || skippable(l) {
			continue
		}
		t := strings.TrimSpace(cutCommentRE.ReplaceAllString(l, ""))
		t = strings.TrimSpace(strings.TrimPrefix(t, "- "))
		if m := longKeyRE.FindStringSubmatch(t); m != nil && m[1] == "path" {
			if v := strings.TrimSpace(m[2]); strings.HasPrefix(v, "[") {
				if n, err := parseFlow(v); err == nil {
					for _, it := range n.list {
						out = append(out, scalarOf(it))
					}
				}
			} else {
				out = append(out, unquote(v))
			}
		} else if m == nil && t != "" && !strings.HasPrefix(t, "-") {
			out = append(out, unquote(t))
		}
	}
	return out
}

// LabelNames are the label keys a service writes itself (list or map form).
func (d *Doc) LabelNames(service string) []string {
	sp, err := d.span(service)
	if err != nil {
		return nil
	}
	fs, _ := d.fields(sp)
	f, ok := findField(fs, "labels")
	if !ok {
		return nil
	}
	var out []string
	for i := f.line + 1; i < f.end; i++ {
		t := strings.TrimSpace(cutCommentRE.ReplaceAllString(d.lines[i], ""))
		if strings.HasPrefix(t, "- ") {
			k, _, _ := strings.Cut(unquote(strings.TrimSpace(strings.TrimPrefix(t, "- "))), "=")
			out = append(out, k)
		} else if m := keyRE.FindStringSubmatch(d.lines[i]); m != nil {
			out = append(out, unquote(m[2]))
		}
	}
	return out
}

// quoteYAML writes any string as a YAML double-quoted scalar (JSON strings are valid ones).
func quoteYAML(s string) string {
	b, _ := json.Marshal(s)
	return strings.ReplaceAll(string(b), `\u0026`, "&")
}

// RemoveLabels deletes the named labels from a service's own labels (list or map form). A label it does not have is
// ignored; if none are left the field becomes `labels: []`.
func (d *Doc) RemoveLabels(service string, keys []string) error {
	sp, err := d.span(service)
	if err != nil {
		return err
	}
	fs, fi := d.fields(sp)
	lab, ok := findField(fs, "labels")
	if !ok {
		return nil
	}
	if lab.inline != "" {
		return fmt.Errorf("labels of %s are written in a form om will not edit; run Blockify first", service)
	}
	drop := map[string]bool{}
	for _, k := range keys {
		drop[k] = true
	}
	remaining := 0
	var del []int
	for i := lab.line + 1; i < lab.end; i++ {
		if skippable(d.lines[i]) {
			continue
		}
		t := strings.TrimSpace(cutCommentRE.ReplaceAllString(d.lines[i], ""))
		var k string
		if strings.HasPrefix(t, "- ") {
			k, _, _ = strings.Cut(unquote(strings.TrimSpace(strings.TrimPrefix(t, "- "))), "=")
		} else if m := keyRE.FindStringSubmatch(d.lines[i]); m != nil {
			k = unquote(m[2])
		}
		if drop[k] {
			del = append(del, i)
		} else {
			remaining++
		}
	}
	for j := len(del) - 1; j >= 0; j-- {
		d.replace(del[j], del[j]+1, nil)
	}
	if remaining == 0 && len(del) > 0 {
		d.replace(lab.line, lab.line+1, []string{pad(fi) + "labels: []"})
	}
	return nil
}

// SetScalar sets a one-line key of a service (container_name, restart...), replacing it when it is there.
func (d *Doc) SetScalar(service, key, value string) error {
	sp, err := d.span(service)
	if err != nil {
		return err
	}
	fs, fi := d.fields(sp)
	line := pad(fi) + key + ": " + value
	if f, ok := findField(fs, key); ok {
		d.replace(f.line, d.lastReal(f.line, f.end)+1, []string{line + commentOf(d.lines[f.line])})
		return nil
	}
	d.insert(d.lastReal(sp.start+1, sp.end)+1, line)
	return nil
}

// EnsureNetworkRef makes a service that lists its networks include the named one (a service with no `networks:`
// already uses `default`).
func (d *Doc) EnsureNetworkRef(service, name string) error {
	sp, err := d.span(service)
	if err != nil {
		return err
	}
	fs, _ := d.fields(sp)
	f, ok := findField(fs, "networks")
	if !ok {
		return nil
	}
	if f.inline != "" {
		return fmt.Errorf("%s: its networks are written in a form om will not edit; add `%s` to them yourself", service, name)
	}
	first := -1
	for i := f.line + 1; i < f.end; i++ {
		if !skippable(d.lines[i]) {
			first = i
			break
		}
	}
	if first < 0 {
		return nil
	}
	ind := indentOf(d.lines[first])
	list := strings.HasPrefix(strings.TrimSpace(d.lines[first]), "- ")
	for i := f.line + 1; i < f.end; i++ {
		t := strings.TrimSpace(cutCommentRE.ReplaceAllString(d.lines[i], ""))
		if list && strings.HasPrefix(t, "- ") && unquote(strings.TrimSpace(strings.TrimPrefix(t, "- "))) == name {
			return nil
		}
		if m := keyRE.FindStringSubmatch(d.lines[i]); !list && m != nil && indentOf(d.lines[i]) == ind && unquote(m[2]) == name {
			return nil
		}
	}
	at := d.lastReal(f.line+1, f.end) + 1
	if list {
		d.insert(at, pad(ind)+"- "+name)
	} else {
		d.insert(at, pad(ind)+name+":")
	}
	return nil
}

// EnsureDefaultNetwork makes the file's `default` network the workspace network: external, with the given name
// expression. Other networks are kept; an existing `default` entry is replaced.
func (d *Doc) EnsureDefaultNetwork(nameExpr string) (replaced bool, err error) {
	entry := func(ind int) []string {
		return []string{pad(ind) + "default:", pad(ind+2) + "name: " + nameExpr, pad(ind+2) + "external: true"}
	}
	at := -1
	for i, l := range d.lines {
		if strings.HasPrefix(l, "networks:") {
			at = i
			break
		}
	}
	if at < 0 {
		tail := []string{"", "networks:"}
		if len(d.lines) > 0 && skippable(d.lines[len(d.lines)-1]) {
			tail = tail[1:]
		}
		d.lines = append(d.lines, append(tail, entry(2)...)...)
		return false, nil
	}
	rest := strings.TrimSpace(cutCommentRE.ReplaceAllString(strings.TrimPrefix(d.lines[at], "networks:"), ""))
	end := len(d.lines)
	for i := at + 1; i < len(d.lines); i++ {
		if !skippable(d.lines[i]) && indentOf(d.lines[i]) == 0 {
			end = i
			break
		}
	}
	last := d.lastReal(at+1, end) + 1
	if rest != "" {
		if rest != "{}" {
			n, perr := parseFlow(rest)
			if perr != nil || n.kind != 'm' {
				return false, fmt.Errorf("networks is written in a form om will not edit; make its default network `name: %s, external: true` yourself", nameExpr)
			}
			if n.get("default") != nil {
				replaced = true
			}
			var keep []string
			for i, k := range n.keys {
				if unquote(k) != "default" {
					keep = append(keep, pad(2)+k+": "+n.vals[i].inline())
				}
			}
			d.replace(at, at+1, append([]string{"networks:" + commentOf(d.lines[at])}, append(entry(2), keep...)...))
			return replaced, nil
		}
		d.replace(at, at+1, append([]string{"networks:" + commentOf(d.lines[at])}, entry(2)...))
		return false, nil
	}
	ind := 2
	for i := at + 1; i < last; i++ {
		if !skippable(d.lines[i]) {
			ind = indentOf(d.lines[i])
			break
		}
	}
	for i := at + 1; i < last; i++ {
		if m := keyRE.FindStringSubmatch(d.lines[i]); m != nil && indentOf(d.lines[i]) == ind && unquote(m[2]) == "default" {
			stop := last
			for j := i + 1; j < last; j++ {
				if !skippable(d.lines[j]) && indentOf(d.lines[j]) <= ind {
					stop = j
					break
				}
			}
			d.replace(i, d.lastReal(i, stop)+1, entry(ind))
			return true, nil
		}
	}
	d.replace(at+1, at+1, entry(ind))
	return false, nil
}
