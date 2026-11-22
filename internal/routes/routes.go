// Package routes is the pure route logic: compose labels, route options, service metadata, the om.caddy snippet
// validator and the Caddy vhost/alias renderers. No engine or registry access. Port of lib/gitops/routes.py.
//
// Where Python prints a warning, these functions return it (Warning); the CLI prints it.
package routes

import (
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

// Warning is a message om prints in yellow after a ⚠ and a two-space indent.
type Warning string

// String is the exact line Python prints (without the newline).
func (w Warning) String() string { return "  \033[33m⚠ " + string(w) + "\033[0m" }

// ws is Python's `\s` for str patterns (Go's is ASCII only): the characters str.isspace() accepts.
const ws = `\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`

var (
	labelRE     = regexp.MustCompile(`^-?[` + ws + `]*["']?((?:dashboard|om)\.[a-z0-9_.]+)[` + ws + `]*[=:][` + ws + `]*["']?(.*?)["']?[` + ws + `]*$`)
	routePathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*\*?$`) // Go's `$` is Python's `\Z`
)

// ComposeLabels returns the dashboard.* / om.* labels of a compose file, in list (`- k=v`) or map (`k: v`) form.
func ComposeLabels(content string) map[string]string {
	labels := map[string]string{}
	for _, line := range py.SplitLines(content) {
		if m := labelRE.FindStringSubmatch(py.Strip(line)); m != nil {
			labels[m[1]] = py.Strip(m[2])
		}
	}
	return labels
}

// LabelPaths returns the comma-separated route paths of a label. Anything that is not a plain path is dropped, so
// a compose file can never inject Caddy directives into the edge config.
func LabelPaths(labels map[string]string, key, sname string) ([]string, []Warning) {
	var paths []string
	var warns []Warning
	for _, x := range strings.Split(labels[key], ",") {
		p := py.Strip(x)
		if p == "" {
			continue
		}
		if routePathRE.MatchString(p) && !strings.Contains(p, "//") && !strings.Contains(p+"/", "/../") {
			paths = append(paths, p)
		} else {
			warns = append(warns, Warning(sname+": ignoring invalid path '"+p+"' in "+key))
		}
	}
	return paths, warns
}

// Who may connect to a service's own ports, by source address (IPv4/IPv6 address or CIDR range):
//
//	om.net.allow=100.101.0.7,192.168.1.0/24   only these (and this machine)
//	om.net.deny=192.168.1.66                   everyone but these (deny wins over allow)
//
// Enforced by the host firewall: the edge cannot see client addresses, because rootless port forwarding hands it
// every connection from one internal address.
const (
	NetAllow   = "om.net.allow"
	NetDeny    = "om.net.deny"
	VPNKeyword = "vpn" // om.net.allow=vpn: the OM_VPN_ALLOW devices, expanded by the firewall when it renders
)

// NetPolicy is a service's address policy. Allow == nil means no allow-list; an empty non-nil Allow (every
// entry was invalid) fails closed.
type NetPolicy struct {
	Allow []string
	Deny  []string
}

// ParseNetPolicy returns the policy and its problems, or nil when neither label is set. vpnAllow is the
// OM_VPN_ALLOW list (what `om.net.allow=vpn` refers to).
func ParseNetPolicy(labels map[string]string, vpnAllow []string) (*NetPolicy, []string) {
	var problems []string
	out := map[string][]string{}
	for _, f := range []struct{ key, field string }{{NetAllow, "allow"}, {NetDeny, "deny"}} {
		var items []string
		for _, x := range strings.Split(labels[f.key], ",") {
			if x = py.Strip(x); x != "" {
				items = append(items, x)
			}
		}
		var nets []netip.Prefix
		keyword := false
		for _, x := range items {
			if strings.ToLower(x) == VPNKeyword {
				switch {
				case f.field == "deny":
					problems = append(problems, f.key+": `"+VPNKeyword+"` is only for "+NetAllow)
				case len(vpnAllow) == 0:
					problems = append(problems, f.key+": `"+VPNKeyword+"` needs a VPN allow-list first (om vpn allow <device>)")
				default:
					keyword = true
				}
				continue
			}
			// a scope id (`fe80::1%eth0`) parses elsewhere, but no firewall rule can carry it: ParseNetwork refuses it
			if n, ok := settings.ParseNetwork(x); ok {
				p, _ := netip.ParsePrefix(n)
				nets = append(nets, p)
			} else {
				problems = append(problems, f.key+": `"+x+"` is not an IP address or range")
			}
		}
		if len(items) > 0 {
			list := []string{}
			if keyword {
				list = append(list, VPNKeyword)
			}
			for _, n := range sortedUnique(nets) {
				list = append(list, n.String())
			}
			out[f.field] = list
		}
	}
	if len(out) == 0 {
		return nil, problems
	}
	deny := out["deny"]
	if deny == nil {
		deny = []string{}
	}
	return &NetPolicy{Allow: out["allow"], Deny: deny}, problems
}

// sortedUnique is sorted(set(nets), key=(version, network_address, prefixlen)).
func sortedUnique(nets []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var u []netip.Prefix
	for _, n := range nets {
		if !seen[n] {
			seen[n] = true
			u = append(u, n)
		}
	}
	sort.Slice(u, func(i, j int) bool {
		a, b := u[i], u[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	return u
}

// ReservedDashboardPaths are the paths the dashboard itself answers on its address. A redirect there (an alias
// label, or a service named `api`) would send the dashboard's own requests to a service: a hijack of the
// dashboard origin or a dashboard that cannot load.
var ReservedDashboardPaths = []string{"/api", "/opensearch.xml", "/healthz"}

// AliasIsReserved is true for an alias that is empty (it would redirect every request) or is, or is under, a
// dashboard path. Caddy matches paths case-insensitively, so the comparison does too.
func AliasIsReserved(path string) bool {
	p := strings.ToLower(path)
	if p == "" {
		return true
	}
	for _, r := range ReservedDashboardPaths {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func aliases(labels map[string]string, sname string) ([]string, []Warning) {
	var out []string
	paths, warns := LabelPaths(labels, "om.route.aliases", sname)
	for _, p := range paths {
		alias := strings.TrimRight(strings.TrimRight(p, "*"), "/")
		if AliasIsReserved(alias) {
			warns = append(warns, Warning(sname+": ignoring alias '"+p+"' in om.route.aliases: it would redirect the dashboard's own address"))
		} else {
			out = append(out, alias)
		}
	}
	return out, warns
}

// Options shape one service's routes.
//
//	om.route.keep_prefix=true          the app serves under /<svc>/ (its own base URL): its root redirects there
//	om.route.aliases=/a,/b             top-level paths on the dashboard's address redirected to the service's
//	                                   own port (path and query kept)
//	om.route.dashboard_paths=/api/x*   paths on the service's address answered by the om dashboard instead
type Options struct {
	KeepPrefix     bool
	Aliases        []string
	DashboardPaths []string
	Net            *NetPolicy
	NetProblems    []string
	Log            string // "off": no access log at the edge and no connection log in the firewall
	Snippet        string // the service's om.caddy, already validated
}

// RouteOptions reads a service's options from its compose file text, or from labels if given.
func RouteOptions(content, sname string, labels map[string]string, vpnAllow []string) (Options, []Warning) {
	if labels == nil {
		labels = ComposeLabels(content)
	}
	net, netProblems := ParseNetPolicy(labels, vpnAllow)
	al, w1 := aliases(labels, sname)
	dp, w2 := LabelPaths(labels, "om.route.dashboard_paths", sname)
	log := "on"
	if strings.ToLower(py.Strip(labels["om.log"])) == "off" {
		log = "off"
	}
	return Options{
		KeepPrefix:     strings.ToLower(labels["om.route.keep_prefix"]) == "true",
		Aliases:        al,
		DashboardPaths: dp,
		Net:            net,
		NetProblems:    netProblems,
		Log:            log,
	}, append(w1, w2...)
}

// atoi is int() for digits-only text; a value too large for int saturates (it can never be a usable port).
func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return math.MaxInt
	}
	return n
}

// ConfigMeta returns (port, is_public, no_web) and the dashboard.*/om.* labels from the engine's normalized
// `compose config`: no regex over YAML, so comments, anchors and multi-line values cannot mislead it. Services are
// read in sorted order, as compose prints them.
func ConfigMeta(cfg map[string]any, sname string) (port int, public, noWeb bool, labels map[string]string) {
	labels = map[string]string{}
	var expose []string
	services, _ := cfg["services"].(map[string]any)
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		svc, _ := services[n].(map[string]any)
		for k, v := range serviceLabels(svc) {
			if strings.HasPrefix(k, "dashboard.") || strings.HasPrefix(k, "om.") {
				labels[k] = v
			}
		}
		if list, ok := svc["expose"].([]any); ok {
			for _, e := range list {
				expose = append(expose, strings.SplitN(py.Str(e), "/", 2)[0])
			}
		}
		// `ports:` (refused by the policy gate, but run under OM_POLICY=warn): the container side
		if list, ok := svc["ports"].([]any); ok {
			for _, p := range list {
				if m, ok := p.(map[string]any); ok {
					t := ""
					if v, has := m["target"]; has {
						t = py.Str(v)
					}
					expose = append(expose, t)
				}
			}
		}
	}
	exposed := 0
	for _, e := range expose {
		if state.IsNumber(e) {
			exposed = atoi(e)
			break
		}
	}
	if p := labels["dashboard.port"]; state.IsNumber(p) {
		port = atoi(p)
	} else if exposed != 0 {
		port = exposed
	} else {
		port = 8080
	}
	return port, strings.ToLower(labels["dashboard.scope"]) == "public", strings.ToLower(labels["dashboard.web"]) == "false", labels
}

// serviceLabels is labels.Service with every key and value as text (str(k), str(v)).
func serviceLabels(svc map[string]any) map[string]string {
	out := map[string]string{}
	switch l := svc["labels"].(type) {
	case map[string]any:
		for k, v := range l {
			out[k] = py.Str(v)
		}
	case []any:
		for _, item := range l {
			if s, ok := item.(string); ok {
				k, v, _ := strings.Cut(s, "=")
				out[k] = v
			}
		}
	}
	return out
}

func stripQuotes(s string) string { return strings.Trim(strings.Trim(s, `"`), `'`) }

// ParseServiceMeta extracts (port, is_public, no_web) from compose file text without an engine. Public requires
// an explicit dashboard.scope=public.
func ParseServiceMeta(content, sname string) (port int, public, noWeb bool) {
	labelPort, mappedPort := 0, 0
	scope := ""
	after := func(line, key string) string { return strings.Split(line, key)[1] }
	for _, line := range py.SplitLines(content) {
		line = py.Strip(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.Contains(line, "dashboard.port=") || strings.Contains(line, "dashboard.port:"):
			if p := stripQuotes(strings.TrimLeft(after(line, "dashboard.port"), "=: ")); state.IsNumber(p) {
				labelPort = atoi(p)
			}
		case strings.Contains(line, "dashboard.scope=") || strings.Contains(line, "dashboard.scope:"):
			scope = strings.ToLower(stripQuotes(strings.TrimLeft(after(line, "dashboard.scope"), "=: ")))
		case strings.Contains(line, "dashboard.web=") || strings.Contains(line, "dashboard.web:"):
			noWeb = strings.ToLower(stripQuotes(strings.TrimLeft(after(line, "dashboard.web"), "=: "))) == "false"
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "- /"):
			cand := stripQuotes(py.Strip(line[1:]))
			if state.IsNumber(cand) {
				mappedPort = atoi(cand)
			} else if strings.Contains(cand, ":") {
				parts := strings.Split(cand, ":")
				last := strings.SplitN(parts[len(parts)-1], "/", 2)[0]
				if state.IsNumber(last) {
					mappedPort = atoi(last)
				}
			}
		}
	}
	switch {
	case labelPort != 0:
		port = labelPort
	case mappedPort != 0:
		port = mappedPort
	default:
		port = 8080
	}
	return port, scope == "public", noWeb
}

// NoNetworkServices names the services of a compose file's text that run with `network_mode: none`, without an
// engine: such a service reaches nothing and nothing reaches it, so it has no route and no exposure. It reads the
// block style compose files are written in (a service at the first indent under `services:`, the key below it).
func NoNetworkServices(content string) []string {
	var out []string
	inServices, cur, svcIndent, keyIndent := false, "", -1, -1
	for _, raw := range py.SplitLines(content) {
		line := strings.TrimRight(raw, " \t\r")
		trim := strings.TrimLeft(line, " \t")
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(line) - len(trim)
		if indent == 0 {
			inServices, cur, svcIndent, keyIndent = strings.HasPrefix(trim, "services:"), "", -1, -1
			continue
		}
		if !inServices {
			continue
		}
		if svcIndent < 0 {
			svcIndent = indent
		}
		if indent == svcIndent {
			if i := strings.Index(trim, ":"); i > 0 {
				cur, keyIndent = stripQuotes(trim[:i]), -1
			}
			continue
		}
		if keyIndent < 0 {
			keyIndent = indent // the indent of a service's own keys; a deeper network_mode belongs to something else
		}
		if indent == keyIndent && cur != "" && strings.HasPrefix(trim, "network_mode:") {
			v := strings.TrimSpace(strings.SplitN(trim[len("network_mode:"):], "#", 2)[0])
			if stripQuotes(v) == "none" {
				out = append(out, cur)
			}
		}
	}
	return out
}
