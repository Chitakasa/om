// Package composefix makes the small edits om needs in a compose file somebody else wrote: add labels to a service and
// turn its `ports:` into `expose:`. It works on the text, line by line, so comments, ordering, quoting and anchors
// survive, and it touches only the lines it names. There is no YAML library behind it, so it supports the common
// layouts (block mappings, list or map labels, a block or one-line `ports:` list) and says plainly when it meets
// anything else, instead of rewriting it.
package composefix

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// KV is one label.
type KV struct{ Key, Value string }

// Doc is a compose file read as lines.
type Doc struct {
	lines     []string // without line terminators
	crlf      bool
	finalNL   bool
	svcIndent int
	svcStart  int // first line of the services mapping's children
	svcEnd    int // one past the last
}

// ErrNoServices is returned when the file has no top-level `services:` mapping.
var ErrNoServices = errors.New("no services: block found")

var (
	servicesRE = regexp.MustCompile(`^services:\s*(#.*)?$`)
	keyRE      = regexp.MustCompile(`^( *)("[^"]+"|'[^']+'|[A-Za-z0-9_.-]+):(.*)$`)
)

func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

func skippable(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.HasPrefix(t, "#")
}

// hasValue reports whether the text after a key's colon holds a value (not empty, not only a comment).
func hasValue(rest string) bool {
	t := strings.TrimSpace(rest)
	return t != "" && !strings.HasPrefix(t, "#")
}

// Parse reads a compose file's text.
func Parse(text string) (*Doc, error) {
	d := &Doc{crlf: strings.Contains(text, "\r\n"), finalNL: strings.HasSuffix(text, "\n")}
	text = strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	d.lines = strings.Split(text, "\n")
	at := -1
	for i, l := range d.lines {
		if servicesRE.MatchString(l) {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, ErrNoServices
	}
	d.svcStart = -1
	for i := at + 1; i < len(d.lines); i++ {
		if skippable(d.lines[i]) {
			continue
		}
		if indentOf(d.lines[i]) == 0 {
			break
		}
		d.svcIndent, d.svcStart = indentOf(d.lines[i]), i
		break
	}
	if d.svcStart < 0 {
		return nil, ErrNoServices
	}
	d.svcEnd = len(d.lines)
	for i := d.svcStart; i < len(d.lines); i++ {
		if !skippable(d.lines[i]) && indentOf(d.lines[i]) < d.svcIndent {
			d.svcEnd = i
			break
		}
	}
	return d, nil
}

// String is the file's text again, with its original line endings.
func (d *Doc) String() string {
	nl := "\n"
	if d.crlf {
		nl = "\r\n"
	}
	s := strings.Join(d.lines, nl)
	if d.finalNL {
		s += nl
	}
	return s
}

type span struct {
	name       string
	start, end int  // the key line and one past the block
	opaque     bool // `name: *alias` or a flow mapping: nothing to edit line by line
}

func unquote(s string) string {
	if n := len(s); n >= 2 && (s[0] == '"' || s[0] == '\'') && s[n-1] == s[0] {
		return s[1 : n-1]
	}
	return s
}

func (d *Doc) spans() []span {
	var out []span
	for i := d.svcStart; i < d.svcEnd; i++ {
		if skippable(d.lines[i]) || indentOf(d.lines[i]) != d.svcIndent {
			continue
		}
		m := keyRE.FindStringSubmatch(d.lines[i])
		if m == nil {
			continue
		}
		out = append(out, span{name: unquote(m[2]), start: i, opaque: hasValue(m[3])})
	}
	for k := range out {
		out[k].end = d.svcEnd
		if k+1 < len(out) {
			out[k].end = out[k+1].start
		}
	}
	return out
}

// Services are the service names in file order.
func (d *Doc) Services() []string {
	var names []string
	for _, s := range d.spans() {
		names = append(names, s.name)
	}
	return names
}

func (d *Doc) span(service string) (span, error) {
	for _, s := range d.spans() {
		if s.name == service {
			if s.opaque {
				return s, fmt.Errorf("service %s is written as an alias or a one-line mapping", service)
			}
			return s, nil
		}
	}
	return span{}, fmt.Errorf("no service named %s", service)
}

type field struct {
	name      string
	line, end int
	inline    string // text after the colon on the key line, comments removed
	indent    int
}

// fields are the keys directly under a service, with the line range each one owns.
func (d *Doc) fields(sp span) ([]field, int) {
	fi := -1
	for i := sp.start + 1; i < sp.end; i++ {
		if !skippable(d.lines[i]) {
			fi = indentOf(d.lines[i])
			break
		}
	}
	if fi < 0 {
		return nil, d.svcIndent + 2
	}
	var out []field
	for i := sp.start + 1; i < sp.end; i++ {
		if skippable(d.lines[i]) || indentOf(d.lines[i]) != fi {
			continue
		}
		if m := keyRE.FindStringSubmatch(d.lines[i]); m != nil {
			rest := m[3]
			if j := strings.Index(rest, " #"); j >= 0 {
				rest = rest[:j]
			}
			out = append(out, field{name: unquote(m[2]), line: i, indent: fi, inline: strings.TrimSpace(rest)})
		}
	}
	for k := range out {
		out[k].end = sp.end
		if k+1 < len(out) {
			out[k].end = out[k+1].line
		}
	}
	return out, fi
}

func findField(fs []field, name string) (field, bool) {
	for _, f := range fs {
		if f.name == name {
			return f, true
		}
	}
	return field{}, false
}

// lastReal is the index of the last line in [from, to) that is neither blank nor a comment, or from-1.
func (d *Doc) lastReal(from, to int) int {
	for i := to - 1; i >= from; i-- {
		if !skippable(d.lines[i]) {
			return i
		}
	}
	return from - 1
}

func (d *Doc) insert(at int, lines ...string) {
	d.lines = append(d.lines[:at], append(append([]string{}, lines...), d.lines[at:]...)...)
	d.svcEnd += len(lines)
}

func pad(n int) string { return strings.Repeat(" ", n) }

func safeValue(v string) error {
	if v == "" || strings.ContainsAny(v, "\"\\\n\r") {
		return fmt.Errorf("a label value must not be empty or contain quotes, backslashes or line breaks: %q", v)
	}
	return nil
}

// AddLabels sets labels on a service: an existing label of the same name is replaced in place when replace is true and
// kept when it is false (a default must not overwrite what the author wrote); the others are added after the last one
// (or in a new `labels:` block). Both the list form (- "k=v") and the map form (k: v) are kept.
func (d *Doc) AddLabels(service string, kvs []KV, replace bool) error {
	for _, kv := range kvs {
		if err := safeValue(kv.Value); err != nil {
			return err
		}
	}
	sp, err := d.span(service)
	if err != nil {
		return err
	}
	fs, fi := d.fields(sp)
	lab, ok := findField(fs, "labels")
	if !ok {
		at := d.lastReal(sp.start+1, sp.end) + 1
		if at <= sp.start {
			at = sp.start + 1
		}
		block := []string{pad(fi) + "labels:"}
		for _, kv := range kvs {
			block = append(block, pad(fi+2)+`- "`+kv.Key+"="+kv.Value+`"`)
		}
		d.insert(at, block...)
		return nil
	}
	if lab.inline == "[]" || lab.inline == "{}" { // empty: it becomes a block that can be added to
		d.lines[lab.line] = pad(fi) + "labels:" + commentOf(d.lines[lab.line])
		lab.inline = ""
	}
	if lab.inline != "" {
		return fmt.Errorf("labels of %s are written as a one-line list, an alias or a mapping om will not edit", service)
	}
	first := -1
	for i := lab.line + 1; i < lab.end; i++ {
		if !skippable(d.lines[i]) {
			first = i
			break
		}
	}
	listForm := first < 0 || strings.HasPrefix(strings.TrimSpace(d.lines[first]), "- ") || strings.TrimSpace(d.lines[first]) == "-"
	itemIndent := fi + 2
	if first >= 0 {
		itemIndent = indentOf(d.lines[first])
	}
	for _, kv := range kvs {
		replaced := false
		for i := lab.line + 1; i < lab.end && !replaced; i++ {
			if skippable(d.lines[i]) {
				continue
			}
			t := strings.TrimSpace(d.lines[i])
			if listForm && strings.HasPrefix(t, "- ") {
				body := unquote(strings.TrimSpace(strings.TrimPrefix(t, "- ")))
				if j := strings.Index(body, " #"); j >= 0 {
					body = strings.TrimSpace(body[:j])
				}
				if k, _, _ := strings.Cut(unquote(body), "="); k == kv.Key {
					if !replace {
						replaced = true
						continue
					}
					quote := `"`
					if strings.Contains(t, "'") && !strings.Contains(t, `"`) {
						quote = "'"
					}
					d.lines[i] = pad(indentOf(d.lines[i])) + "- " + quote + kv.Key + "=" + kv.Value + quote
					replaced = true
				}
			} else if !listForm {
				if m := keyRE.FindStringSubmatch(d.lines[i]); m != nil && unquote(m[2]) == kv.Key {
					if !replace {
						replaced = true
						continue
					}
					d.lines[i] = pad(indentOf(d.lines[i])) + kv.Key + `: "` + kv.Value + `"`
					replaced = true
				}
			}
		}
		if replaced {
			continue
		}
		at := d.lastReal(lab.line+1, lab.end) + 1
		if at <= lab.line {
			at = lab.line + 1
		}
		if listForm {
			d.insert(at, pad(itemIndent)+`- "`+kv.Key+"="+kv.Value+`"`)
		} else {
			d.insert(at, pad(itemIndent)+kv.Key+`: "`+kv.Value+`"`)
		}
		for i := range fs { // the labels field grew: the end of its range moved
			if fs[i].line == lab.line {
				lab.end++
			}
		}
	}
	return nil
}

var (
	portNumRE    = regexp.MustCompile(`^(\d+(-\d+)?|\$\{[^}]+\})$`)
	longKeyRE    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*):(?:\s+(.*))?$`)
	cutCommentRE = regexp.MustCompile(`\s+#.*$`)
)

// splitOutside splits s on sep, ignoring separators inside ${...} and [...].
func splitOutside(s string, sep byte) []string {
	var parts []string
	depth, from := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '{' || s[i] == '[':
			depth++
		case (s[i] == '}' || s[i] == ']') && depth > 0:
			depth--
		case s[i] == sep && depth == 0:
			parts = append(parts, s[from:i])
			from = i + 1
		}
	}
	return append(parts, s[from:])
}

// containerPort is the container side of a short port spec ("8080:80", "127.0.0.1:8080:80/tcp", "80"), with its
// protocol if it had one; ok is false for a form it does not understand.
func containerPort(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	proto := ""
	if i := strings.LastIndex(spec, "/"); i >= 0 && !strings.Contains(spec[i:], "}") {
		spec, proto = spec[:i], spec[i:]
	}
	parts := splitOutside(spec, ':')
	last := parts[len(parts)-1]
	if !portNumRE.MatchString(last) {
		return "", false
	}
	return last + proto, true
}

// PortsToExpose replaces a service's `ports:` (which publishes host ports) with `expose:` (the edge routes to it) and
// returns what it changed in words and the container ports. A form it does not handle (the long syntax, a multi-line
// flow list) comes back as advice and the lines stay as they are. An existing block-list `expose:` is merged into.
func (d *Doc) PortsToExpose(service string) (changes, ports, advice []string, err error) {
	sp, err := d.span(service)
	if err != nil {
		return nil, nil, nil, err
	}
	fs, fi := d.fields(sp)
	pf, ok := findField(fs, "ports")
	if !ok {
		return nil, nil, nil, nil
	}
	exp, hasExp := findField(fs, "expose")
	type entry struct {
		start, end int // the lines the entry owns (block form)
		long       bool
		before     string // the spec as written
		quote      string
		cp         string
		note       string // trailing comment of a short entry, with its leading space
		dup        bool
	}
	var items []entry
	oneLine := false
	bad := func(msg string) ([]string, []string, []string, error) {
		return nil, nil, []string{service + ": " + msg}, nil
	}
	if pf.inline != "" {
		if !(strings.HasPrefix(pf.inline, "[") && strings.HasSuffix(pf.inline, "]")) {
			return bad("ports is written in a form om will not rewrite; change it to `expose:` with the container port yourself")
		}
		oneLine = true
		for _, raw := range splitOutside(strings.Trim(pf.inline, "[]"), ',') {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			spec := unquote(strings.TrimSpace(raw))
			cp, ok := containerPort(spec)
			if !ok {
				return bad("the port " + strings.TrimSpace(raw) + " is in a form om does not recognise; change ports to expose yourself")
			}
			items = append(items, entry{before: spec, cp: cp})
		}
	} else {
		ind := -1
		var starts []int
		for i := pf.line + 1; i < pf.end; i++ {
			if skippable(d.lines[i]) {
				continue
			}
			if ind < 0 {
				ind = indentOf(d.lines[i])
			}
			t := strings.TrimSpace(d.lines[i])
			switch {
			case indentOf(d.lines[i]) == ind && (strings.HasPrefix(t, "- ") || t == "-"):
				starts = append(starts, i)
			case indentOf(d.lines[i]) <= ind:
				return bad("ports has a layout om does not recognise; change it to `expose:` yourself")
			}
		}
		last := d.lastReal(pf.line+1, pf.end) + 1
		for k, st := range starts {
			end := last
			if k+1 < len(starts) {
				end = starts[k+1]
			}
			for end > st+1 && skippable(d.lines[end-1]) {
				end--
			}
			first := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d.lines[st]), "-"))
			if longKeyRE.MatchString(first) || first == "" {
				kv := map[string]string{}
				for i := st; i < end; i++ {
					t := strings.TrimSpace(d.lines[i])
					if i == st {
						t = first
					}
					if m := longKeyRE.FindStringSubmatch(t); m != nil {
						v := strings.TrimSpace(strings.SplitN(cutCommentRE.ReplaceAllString(m[2], ""), "#", 2)[0])
						kv[m[1]] = unquote(v)
					}
				}
				tp := kv["target"]
				if tp == "" || !portNumRE.MatchString(tp) {
					return bad("a port entry has no usable `target:`; change ports to `expose:` yourself")
				}
				cp := tp
				if pr := kv["protocol"]; pr != "" && pr != "tcp" {
					cp += "/" + pr
				}
				items = append(items, entry{start: st, end: end, long: true, before: "target " + tp, cp: cp})
				continue
			}
			if end != st+1 {
				return bad("a port entry spans several lines; change ports to `expose:` yourself")
			}
			body := first
			note := ""
			if loc := cutCommentRE.FindStringIndex(body); loc != nil {
				note, body = body[loc[0]:], strings.TrimSpace(body[:loc[0]])
			}
			quote := ""
			if body != "" && (body[0] == '"' || body[0] == '\'') {
				quote = body[:1]
			}
			cp, ok := containerPort(unquote(body))
			if !ok {
				return bad("the port " + body + " is in a form om does not recognise; change ports to expose yourself")
			}
			items = append(items, entry{start: st, end: end, before: unquote(body), quote: quote, cp: cp, note: note})
		}
	}
	seen := map[string]bool{}
	for i := range items {
		it := &items[i]
		if seen[it.cp] {
			it.dup = true
			continue
		}
		seen[it.cp] = true
		ports = append(ports, it.cp)
		if it.before != it.cp {
			changes = append(changes, fmt.Sprintf("%s: ports %s becomes expose %s", service, it.before, it.cp))
		}
	}
	if len(changes) == 0 && len(ports) > 0 {
		changes = append(changes, fmt.Sprintf("%s: ports becomes expose %s", service, strings.Join(ports, ", ")))
	}
	if len(items) == 0 {
		return nil, nil, nil, nil
	}

	switch {
	case oneLine && !hasExp:
		d.lines[pf.line] = pad(fi) + `expose: [` + strings.Join(quoteAll(ports), ", ") + `]` + commentOf(d.lines[pf.line])
	case hasExp:
		if exp.inline != "" { // expose is a one-line list: merge into it and drop ports
			n, perr := parseFlow(exp.inline)
			if perr != nil || n.kind != 'l' {
				return bad("its expose is written in a form om will not rewrite; add the container ports there yourself")
			}
			have := map[string]bool{}
			for _, it := range n.list {
				have[unquote(it.s)] = true
			}
			for _, p := range ports {
				if !have[p] {
					n.list = append(n.list, &node{kind: 's', s: `"` + p + `"`})
				}
			}
			cut := d.lastReal(pf.line+1, pf.end) + 1
			d.lines[exp.line] = pad(fi) + "expose: " + n.inline() + commentOf(d.lines[exp.line])
			d.lines = append(d.lines[:pf.line], d.lines[cut:]...)
			d.svcEnd -= cut - pf.line
			break
		}
		have := map[string]bool{}
		for i := exp.line + 1; i < exp.end; i++ {
			if t := strings.TrimSpace(d.lines[i]); strings.HasPrefix(t, "- ") {
				have[unquote(strings.TrimSpace(strings.TrimPrefix(cutCommentRE.ReplaceAllString(t, ""), "- ")))] = true
			}
		}
		ind := fi + 2
		for i := exp.line + 1; i < exp.end; i++ {
			if !skippable(d.lines[i]) {
				ind = indentOf(d.lines[i])
				break
			}
		}
		var add []string
		for _, p := range ports {
			if !have[p] {
				add = append(add, pad(ind)+`- "`+p+`"`)
			}
		}
		// delete the ports field first (it may come before or after expose), then add to expose
		cut := d.lastReal(pf.line+1, pf.end) + 1
		d.lines = append(d.lines[:pf.line], d.lines[cut:]...)
		d.svcEnd -= cut - pf.line
		if exp.line > pf.line {
			exp.line -= cut - pf.line
			exp.end -= cut - pf.line
		}
		if len(add) > 0 {
			d.insert(d.lastReal(exp.line+1, exp.end)+1, add...)
		}
	default:
		d.lines[pf.line] = pad(fi) + "expose:" + commentOf(d.lines[pf.line])
		for k := len(items) - 1; k >= 0; k-- { // from the end, so the line numbers above stay right
			it := items[k]
			var repl []string
			if !it.dup {
				q := it.quote
				if q == "" {
					q = `"`
				}
				repl = []string{pad(indentOf(d.lines[it.start])) + "- " + q + it.cp + q + it.note}
			}
			d.lines = append(d.lines[:it.start], append(repl, d.lines[it.end:]...)...)
			d.svcEnd += len(repl) - (it.end - it.start)
		}
	}
	return changes, ports, nil, nil
}

func quoteAll(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = `"` + p + `"`
	}
	return out
}

// commentOf is the trailing comment of a `key:` line, with its leading space, or "".
func commentOf(line string) string {
	if loc := cutCommentRE.FindStringIndex(line); loc != nil {
		return line[loc[0]:]
	}
	return ""
}

// Diff shows what changed between two texts as -/+ lines with one line of context; "" when they are equal.
func Diff(oldText, newText string) string {
	a, b := strings.Split(oldText, "\n"), strings.Split(newText, "\n")
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	type op struct {
		tag  byte
		text string
	}
	var ops []op
	for i, j := 0, 0; i < n || j < m; {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, op{' ', a[i]})
			i++
			j++
		case i < n && (j >= m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', a[i]})
			i++
		default:
			ops = append(ops, op{'+', b[j]})
			j++
		}
	}
	show := make([]bool, len(ops))
	changed := false
	for i, o := range ops {
		if o.tag != ' ' {
			changed = true
			for k := i - 1; k <= i+1; k++ {
				if k >= 0 && k < len(ops) {
					show[k] = true
				}
			}
		}
	}
	if !changed {
		return ""
	}
	var out []string
	gap := false
	for i, o := range ops {
		if !show[i] {
			gap = true
			continue
		}
		if gap && len(out) > 0 {
			out = append(out, "  ...")
		}
		gap = false
		out = append(out, string(o.tag)+" "+o.text)
	}
	return strings.Join(out, "\n") + "\n"
}
