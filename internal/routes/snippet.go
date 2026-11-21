package routes

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/py"
)

// A service's own Caddy rules: `om.caddy` next to its compose file, added to all of its sites (its .localhost name
// and its own ports) and run before om proxies the request. Only directives that shape the request or the answer
// are allowed: nothing that reads files, reaches another upstream, or reads om's environment (the edge token is in
// it). Checked by ValidateSnippet.
const SnippetFile = "om.caddy"

var (
	snippetContainers = map[string]bool{"handle": true, "handle_path": true, "route": true}
	snippetDirectives = setOf("handle", "handle_path", "route", "header", "request_header", "redir", "rewrite", "uri",
		"respond", "encode", "basic_auth", "request_body", "error", "abort", "vars", "map", "method")
	snippetMatchers = setOf("path", "path_regexp", "host", "method", "header", "header_regexp", "query",
		"protocol", "expression", "not", "vars", "vars_regexp")
	snippetForbidden = []string{"{$", "{env.", "{file.", "<<", "import"}
	// The edge sees every client as one internal address (rootless port forwarding), so a rule on the client
	// address would match everyone or no one: refused, pointing to om.net.allow / om.net.deny.
	snippetClientAddress = []string{"remote_ip", "client_ip", "{remote", "{http.request.remote"}

	directiveList = joinSorted(snippetDirectives)
	matcherList   = joinSorted(snippetMatchers)
)

func setOf(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

func joinSorted(m map[string]bool) string {
	l := make([]string, 0, len(m))
	for k := range m {
		l = append(l, k)
	}
	sort.Strings(l)
	return strings.Join(l, ", ")
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ValidateSnippet returns the problems in a service's om.caddy (empty = allowed). Context-aware: directives where
// directives go, matcher types inside @matcher blocks, other blocks' contents unchecked except for the forbidden
// placeholders, which are refused anywhere.
func ValidateSnippet(text string) []string {
	var problems []string
	stack := []string{"directives"}
	add := func(n int, format string, a ...any) {
		problems = append(problems, "line "+strconv.Itoa(n)+": "+fmt.Sprintf(format, a...))
	}
	for i, raw := range py.SplitLines(text) {
		n := i + 1
		line := py.Strip(raw)
		// Every line is checked, comments included: a "comment" line can be the inside of a multi-line quoted
		// string (`respond "` then `# {$OM_EDGE_TOKEN}"`), where Caddy reads it as text and substitutes the
		// placeholder.
		for _, bad := range snippetForbidden {
			if strings.Contains(line, bad) {
				add(n, "`%s` is not allowed (it could read files or om's environment)", bad)
			}
		}
		for _, bad := range snippetClientAddress {
			if strings.Contains(line, bad) {
				add(n, "`%s`: the edge cannot see client addresses; restrict by address with %s / %s labels instead", bad, NetAllow, NetDeny)
			}
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := py.Fields(line)
		if len(tokens) == 1 && tokens[0] == "}" {
			if len(stack) == 1 {
				add(n, "unbalanced }")
			} else {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if contains(tokens[:len(tokens)-1], "{") || contains(tokens, "}") {
			add(n, "put each block's { at the end of a line and } on its own line")
			continue
		}
		opens := tokens[len(tokens)-1] == "{"
		head := tokens[0]
		switch ctx := stack[len(stack)-1]; ctx {
		case "directives":
			if strings.HasPrefix(head, "@") {
				if len(tokens) > 1 && tokens[1] != "{" && !snippetMatchers[tokens[1]] {
					add(n, "matcher type `%s` is not allowed (allowed: %s)", tokens[1], matcherList)
				}
				if opens {
					stack = append(stack, "matcher")
				}
				continue
			}
			if !snippetDirectives[head] {
				add(n, "directive `%s` is not allowed (allowed: %s)", head, directiveList)
			}
			if opens {
				if snippetContainers[head] {
					stack = append(stack, "directives")
				} else {
					stack = append(stack, "opaque")
				}
			}
		case "matcher":
			if !snippetMatchers[head] {
				add(n, "matcher type `%s` is not allowed", head)
			}
			if opens {
				stack = append(stack, "opaque")
			}
		default:
			if opens {
				stack = append(stack, "opaque")
			}
		}
	}
	if len(stack) != 1 {
		problems = append(problems, "unbalanced { }")
	}
	return problems
}
