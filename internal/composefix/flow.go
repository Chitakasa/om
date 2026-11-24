package composefix

import (
	"fmt"
	"strings"
)

// node is a value read from a flow collection ([a, b] or {k: v}) or a scalar. Scalars keep their text as written
// (quotes included), so writing a node out again never changes how a value is quoted.
type node struct {
	kind byte // 's' scalar, 'l' list, 'm' mapping
	s    string
	list []*node
	keys []string
	vals []*node
}

type flowReader struct {
	s string
	i int
}

func (r *flowReader) skip() {
	for r.i < len(r.s) {
		switch c := r.s[r.i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			r.i++
		case c == '#' && (r.i == 0 || strings.ContainsRune(" \t\n", rune(r.s[r.i-1]))):
			for r.i < len(r.s) && r.s[r.i] != '\n' {
				r.i++
			}
		default:
			return
		}
	}
}

func (r *flowReader) scalar(stop string) (string, error) {
	r.skip()
	start := r.i
	if r.i < len(r.s) && (r.s[r.i] == '"' || r.s[r.i] == '\'') {
		q := r.s[r.i]
		r.i++
		for r.i < len(r.s) {
			if r.s[r.i] == '\\' && q == '"' {
				r.i += 2
				continue
			}
			if r.s[r.i] == q {
				if q == '\'' && r.i+1 < len(r.s) && r.s[r.i+1] == '\'' {
					r.i += 2
					continue
				}
				r.i++
				return r.s[start:r.i], nil
			}
			r.i++
		}
		return "", fmt.Errorf("unterminated quote in %q", r.s)
	}
	depth := 0
	for r.i < len(r.s) {
		c := r.s[r.i]
		if c == '$' && r.i+1 < len(r.s) && r.s[r.i+1] == '{' {
			depth++
			r.i += 2
			continue
		}
		if c == '}' && depth > 0 {
			depth--
			r.i++
			continue
		}
		if depth == 0 && (strings.IndexByte(stop, c) >= 0 || c == '\n') {
			break
		}
		if depth == 0 && c == ':' && (r.i+1 >= len(r.s) || strings.ContainsRune(" \t\n,]}", rune(r.s[r.i+1]))) {
			break
		}
		r.i++
	}
	return strings.TrimSpace(r.s[start:r.i]), nil
}

func (r *flowReader) value() (*node, error) {
	r.skip()
	if r.i >= len(r.s) {
		return nil, fmt.Errorf("unexpected end of %q", r.s)
	}
	switch r.s[r.i] {
	case '[':
		r.i++
		n := &node{kind: 'l'}
		for {
			r.skip()
			if r.i >= len(r.s) {
				return nil, fmt.Errorf("unterminated [ in %q", r.s)
			}
			if r.s[r.i] == ']' {
				r.i++
				return n, nil
			}
			item, err := r.value()
			if err != nil {
				return nil, err
			}
			r.skip()
			if r.i < len(r.s) && r.s[r.i] == ':' { // [a: b] is a one-pair mapping
				r.i++
				v, err := r.value()
				if err != nil {
					return nil, err
				}
				item = &node{kind: 'm', keys: []string{item.s}, vals: []*node{v}}
				r.skip()
			}
			n.list = append(n.list, item)
			if r.i < len(r.s) && r.s[r.i] == ',' {
				r.i++
			}
		}
	case '{':
		r.i++
		n := &node{kind: 'm'}
		for {
			r.skip()
			if r.i >= len(r.s) {
				return nil, fmt.Errorf("unterminated { in %q", r.s)
			}
			if r.s[r.i] == '}' {
				r.i++
				return n, nil
			}
			k, err := r.scalar(",}")
			if err != nil {
				return nil, err
			}
			r.skip()
			v := &node{kind: 's'}
			if r.i < len(r.s) && r.s[r.i] == ':' {
				r.i++
				if v, err = r.value(); err != nil {
					return nil, err
				}
			}
			n.keys, n.vals = append(n.keys, k), append(n.vals, v)
			r.skip()
			if r.i < len(r.s) && r.s[r.i] == ',' {
				r.i++
			}
		}
	}
	s, err := r.scalar(",]}")
	return &node{kind: 's', s: s}, err
}

// parseFlow reads one flow collection (it may span lines and hold comments) or a scalar.
func parseFlow(text string) (*node, error) {
	r := &flowReader{s: text}
	n, err := r.value()
	if err != nil {
		return nil, err
	}
	if r.skip(); r.i < len(r.s) {
		return nil, fmt.Errorf("unexpected text after the value: %q", r.s[r.i:])
	}
	return n, nil
}

// get is the value of a mapping key, or nil.
func (n *node) get(key string) *node {
	for i, k := range n.keys {
		if unquote(k) == key {
			return n.vals[i]
		}
	}
	return nil
}

// lines writes the node as block style at the given indent; an empty collection stays inline (`[]`, `{}`).
func (n *node) lines(indent int) []string {
	pad := strings.Repeat(" ", indent)
	switch n.kind {
	case 'l':
		var out []string
		for _, it := range n.list {
			if it.kind == 's' || len(it.list)+len(it.keys) == 0 {
				out = append(out, pad+"- "+it.inline())
				continue
			}
			sub := it.lines(indent + 2)
			sub[0] = pad + "- " + strings.TrimLeft(sub[0], " ")
			out = append(out, sub...)
		}
		return out
	case 'm':
		var out []string
		for i, k := range n.keys {
			v := n.vals[i]
			if v.kind == 's' || len(v.list)+len(v.keys) == 0 {
				out = append(out, pad+k+": "+v.inline())
				continue
			}
			out = append(out, pad+k+":")
			out = append(out, v.lines(indent+2)...)
		}
		return out
	}
	return []string{pad + n.s}
}

// inline is the node as a one-line value.
func (n *node) inline() string {
	switch n.kind {
	case 'l':
		parts := make([]string, len(n.list))
		for i, it := range n.list {
			parts[i] = it.inline()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case 'm':
		parts := make([]string, len(n.keys))
		for i, k := range n.keys {
			parts[i] = k + ": " + n.vals[i].inline()
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return n.s
}
