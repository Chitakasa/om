package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// A YAML subset: block maps and lists, quoted and plain scalars, `[a, b]` and `{k: v}` flow values, comments. It reads
// what om scaffolds and generates (compose files and overrides) and nothing fancier.

type yline struct {
	indent int
	text   string
}

func parseYAML(src string) any {
	var lines []yline
	for _, raw := range strings.Split(src, "\n") {
		raw = strings.TrimRight(raw, " \t\r")
		t := strings.TrimLeft(raw, " ")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		lines = append(lines, yline{len(raw) - len(t), stripComment(t)})
	}
	if len(lines) == 0 {
		return map[string]any{}
	}
	v, _ := parseBlock(lines, 0, lines[0].indent)
	return v
}

func stripComment(s string) string {
	q := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && i > 0 && s[i-1] == ' ':
			return strings.TrimRight(s[:i], " ")
		}
	}
	return s
}

func parseBlock(lines []yline, i, indent int) (any, int) {
	if strings.HasPrefix(lines[i].text, "- ") || lines[i].text == "-" {
		var list []any
		for i < len(lines) && lines[i].indent == indent && (strings.HasPrefix(lines[i].text, "- ") || lines[i].text == "-") {
			rest := strings.TrimPrefix(strings.TrimPrefix(lines[i].text, "-"), " ")
			if rest == "" {
				i++
				if i < len(lines) && lines[i].indent > indent {
					var v any
					v, i = parseBlock(lines, i, lines[i].indent)
					list = append(list, v)
				} else {
					list = append(list, nil)
				}
				continue
			}
			if k, _, ok := splitKey(rest); ok && k != "" {
				// a map that starts on the dash line: re-read it with the dash replaced by spaces
				sub := []yline{{indent + 2, rest}}
				j := i + 1
				for j < len(lines) && lines[j].indent > indent {
					sub = append(sub, lines[j])
					j++
				}
				v, _ := parseBlock(sub, 0, indent+2)
				list = append(list, v)
				i = j
				continue
			}
			list = append(list, scalar(rest))
			i++
		}
		return list, i
	}
	m := map[string]any{}
	for i < len(lines) && lines[i].indent == indent && !strings.HasPrefix(lines[i].text, "- ") {
		k, rest, ok := splitKey(lines[i].text)
		if !ok {
			i++
			continue
		}
		i++
		if rest != "" {
			m[k] = scalar(rest)
			continue
		}
		if i < len(lines) && (lines[i].indent > indent || (lines[i].indent == indent && strings.HasPrefix(lines[i].text, "- "))) {
			var v any
			v, i = parseBlock(lines, i, lines[i].indent)
			m[k] = v
		} else {
			m[k] = nil
		}
	}
	return m, i
}

// splitKey splits `key: rest` (the key may be quoted).
func splitKey(s string) (key, rest string, ok bool) {
	if strings.HasPrefix(s, "\"") {
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' {
				i++
			} else if s[i] == '"' {
				if i+1 < len(s) && s[i+1] == ':' && (i+2 == len(s) || s[i+2] == ' ') {
					var k string
					json.Unmarshal([]byte(s[:i+1]), &k)
					return k, strings.TrimSpace(s[i+2:]), true
				}
				return "", "", false
			}
		}
		return "", "", false
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return "", "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ') {
			return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
		}
		if s[i] == '"' || s[i] == '\'' {
			return "", "", false
		}
	}
	return "", "", false
}

func scalar(s string) any {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "["):
		return flowList(s)
	case strings.HasPrefix(s, "{"):
		return flowMap(s)
	case strings.HasPrefix(s, "\""):
		var v string
		if json.Unmarshal([]byte(s), &v) == nil {
			return v
		}
		return strings.Trim(s, "\"")
	case strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") && len(s) >= 2:
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	case "null", "~", "":
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && !strings.HasPrefix(s, "0") || s == "0" {
		return float64(n)
	}
	return s
}

func splitFlow(s string) []string {
	var parts []string
	depth, q, start := 0, byte(0), 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		parts = append(parts, t)
	}
	return parts
}

func flowList(s string) any {
	out := []any{}
	for _, p := range splitFlow(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")) {
		out = append(out, scalar(p))
	}
	return out
}

func flowMap(s string) any {
	out := map[string]any{}
	for _, p := range splitFlow(strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")) {
		if k, rest, ok := splitKey(p); ok {
			out[k] = scalar(rest)
		}
	}
	return out
}
