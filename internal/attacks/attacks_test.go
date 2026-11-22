package attacks

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/labels"
	"github.com/Chitakasa/om/internal/policy"
	"github.com/Chitakasa/om/internal/previews"
	"github.com/Chitakasa/om/internal/routes"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/secrets"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/stream"
	"github.com/Chitakasa/om/internal/workspace"
)

func rng(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) }

func pick[T any](r *rand.Rand, l []T) T { return l[r.IntN(len(l))] }

// ---- hostile names ----

func TestNamesIDsAndDomainsHoleTrailingNewline(t *testing.T) {
	// `$` matched before a final newline: a folder called "web\n" was a "safe" service name
	names := []string{"web\n", "web\r\n", "web\x00", "web ", "\nweb", " web", "Web", "wéb", "٣web", "web;rm", "web$(id)", "web`id`",
		"web/../x", "../web", "-web", strings.Repeat("a", 64), "web.localhost", "web:80", "web}", "web{", "web#", "web\t", "", "web\u2028x"}
	for _, n := range names {
		if workspace.IsSafeName(n) || workspace.IsValidWorkspaceID(n) {
			t.Errorf("%q accepted as a name", n)
		}
	}
	for _, d := range []string{"a.localhost\n", "a b", "a;b", "a.com/x", "-a.com", "a.com\r\nHost: evil", "a\x00.com", ""} {
		if workspace.SafeDomainRE.MatchString(d) {
			t.Errorf("domain %q accepted", d)
		}
	}
}

func TestEgressHostsHoleTrailingNewline(t *testing.T) {
	for _, h := range []string{"a.com\n", "*.com\n", "a.com;", "a.com\nhttp_access allow all", "a b.com", "_a.com", "a.com.", "*.*.a.com",
		"a.c", "a.com\x00", "A.com", "a.com/x", "-a.com", "a.b" + strings.Repeat("c", 70)} {
		if egress.ValidHost(h) {
			t.Errorf("host %q accepted", h)
		}
	}
	for _, ok := range []string{"a.example.com", "*.example.com", "x-y.example.org"} {
		if !egress.ValidHost(ok) {
			t.Errorf("host %q refused", ok)
		}
	}
}

func TestRoutePathsHoleTrailingNewline(t *testing.T) {
	for _, p := range []string{"/x y", "/x{", "/x}", `/x"`, `/x\`, "/x\x00", "/x%0a", "x", "", "/x`", "/x$y", "/x;y", "/x\r\nrespond evil"} {
		got, _ := routes.LabelPaths(map[string]string{"k": p}, "k", "svc")
		if len(got) != 0 {
			t.Errorf("path %q accepted: %v", p, got)
		}
	}
	got, _ := routes.LabelPaths(map[string]string{"k": "/a, /b/*,/../x, //y, /ok"}, "k", "svc")
	if strings.Join(got, " ") != "/a /b/* /ok" {
		t.Errorf("paths: %v", got)
	}
}

func TestSecretNamesAndLimitsHoleTrailingNewline(t *testing.T) {
	for _, n := range []string{"a\n", "../a", "a/b", "", "a b", "a\x00", "." + strings.Repeat("a", 70)} {
		if secrets.NameRE.MatchString(n) {
			t.Errorf("secret name %q accepted", n)
		}
	}
	for _, raw := range []string{"0m", "5 m", "-1m", "5tb"} {
		lim, _ := labels.ParseLimits(map[string]any{"om.mem": raw})
		for _, l := range lim {
			if l.Key == "mem_limit" {
				t.Errorf("memory limit %q accepted", raw)
			}
		}
	}
	lim, _ := labels.ParseLimits(map[string]any{"om.mem": "256m\n"}) // a label value is stripped first
	if len(lim) != 1 || lim[0].Key != "mem_limit" || lim[0].Value != `"256m"` {
		t.Errorf("a stripped value: %v", lim)
	}
}

// ---- Caddy snippets ----

var badSnippets = []string{
	"reverse_proxy evil:80", "file_server", "root * /etc", "import /etc/caddy/*", "respond {$OM_EDGE_TOKEN}",
	"header X-T {env.OM_EDGE_TOKEN}", "respond {file./data/edge_token}", "handle {\n  reverse_proxy om_router:80\n}",
	"handle { respond ok }", "respond ok }\nreverse_proxy x", "@m remote_ip 1.2.3.4", "@m client_ip 1.2.3.4",
	"@m {\n  file\n}\nrespond @m ok", "abort\n}\nhttp://evil.example {\n", "tls internal", "log {\n output file /x\n}",
	"respond ok\r\n}\r\nhttp://evil {", "route {\n  respond ok\n}\n}\nmetrics", "templates", "php_fastcgi x", "exec cmd",
	"respond <<EOF\nx\nEOF", "header X {env.HOME}", "respond {http.request.remote.host}", "forward_auth evil:80",
	"handle {\n  import snippet\n}", "map {host} {x} {\n  default y\n}\nimport evil", "root * /data",
	// a "comment" line that is the inside of a multi-line quoted string: Caddy substitutes the placeholder there (hole)
	"respond \"\n# {$OM_EDGE_TOKEN}\"", "respond `\n# {env.HOME}`", "respond \"x\n# {file./data/edge_token}\"",
	"# {$OM_EDGE_TOKEN}", "# import /etc/caddy/*",
}

var goodSnippets = []string{"header X-Frame-Options DENY", "handle /api/* {\n    respond \"ok\" 200\n}", "redir /old /new permanent",
	"@api path /api/*\nrespond @api \"ok\"", "encode gzip",
	"basic_auth {\n    user $2a$14$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz0123456\n}"}

func TestKnownBadSnippetsAreRefused(t *testing.T) {
	for _, s := range badSnippets {
		if len(routes.ValidateSnippet(s)) == 0 {
			t.Errorf("accepted: %q", s)
		}
	}
}

func TestKnownGoodSnippetsStillPass(t *testing.T) {
	for _, s := range goodSnippets {
		if p := routes.ValidateSnippet(s); len(p) != 0 {
			t.Errorf("refused %q: %v", s, p)
		}
	}
}

func TestFuzzedSnippetsNeverSmuggleAForbiddenTokenOrUnbalancedBlock(t *testing.T) {
	pool := []string{"respond", "handle", "route", "header", "redir", "rewrite", "abort", "@m", "path", "{", "}", "{$X}", "{env.A}", "{file.f}",
		"import", "reverse_proxy", "file_server", "remote_ip", "client_ip", "<<EOF", "ok", "/x", "*", `"`, "'", `\`, "#", "{http.request.uri}",
		"a b", "\t", "\r"}
	r := rng(1234)
	forbidden := append(append([]string{}, routes.SnippetForbidden...), routes.SnippetClientAddress...)
	accepted := 0
	for i := 0; i < 4000; i++ {
		var lines []string
		for n := 1 + r.IntN(6); n > 0; n-- {
			var words []string
			for m := 1 + r.IntN(5); m > 0; m-- {
				words = append(words, pick(r, pool))
			}
			lines = append(lines, strings.Join(words, " "))
		}
		text := strings.Join(lines, "\n")
		if len(routes.ValidateSnippet(text)) != 0 {
			continue
		}
		accepted++
		for _, bad := range forbidden {
			if strings.Contains(text, bad) {
				t.Fatalf("accepted a snippet containing %q: %q", bad, text)
			}
		}
		depth := 0
		for _, line := range strings.Split(text, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasSuffix(l, "{") {
				depth++
			}
			if l == "}" {
				depth--
			}
			if depth < 0 {
				t.Fatalf("closes more than it opens: %q", text)
			}
		}
		if depth != 0 {
			t.Fatalf("unbalanced: %q", text)
		}
	}
	if accepted <= 20 {
		t.Errorf("the fuzzer reached only %d accepted snippets, so the checks above barely ran", accepted)
	}
}

// ---- the policy gate ----

type m = map[string]any
type l = []any

func gate(svc m, extra m, home string) []string {
	cfg := m{"services": m{"s": svc}}
	for k, v := range extra {
		cfg[k] = v
	}
	v, _ := policy.EvaluateConfig(cfg, home, "")
	return v
}

func bind(src string) m { return m{"type": "bind", "source": src, "target": "/h"} }

func TestEveryComposeBypassIsRefused(t *testing.T) {
	cases := []struct {
		name  string
		svc   m
		extra m
	}{
		{"privileged", m{"image": "x", "privileged": true}, nil},
		{"host network", m{"image": "x", "network_mode": "host"}, nil},
		{"join another container's network", m{"image": "x", "network_mode": "container:om_caddy"}, nil},
		{"host pid", m{"image": "x", "pid": "host"}, nil},
		{"host ipc", m{"image": "x", "ipc": "host"}, nil},
		{"host uts", m{"image": "x", "uts": "host"}, nil},
		{"host userns", m{"image": "x", "userns_mode": "host"}, nil},
		{"host cgroup", m{"image": "x", "cgroup": "host"}, nil},
		{"published port", m{"image": "x", "ports": l{m{"target": 80, "published": 8080}}}, nil},
		{"SYS_ADMIN", m{"image": "x", "cap_add": l{"SYS_ADMIN"}}, nil},
		{"CAP_ prefix, lowercase", m{"image": "x", "cap_add": l{"cap_sys_admin"}}, nil},
		{"ALL caps", m{"image": "x", "cap_add": l{"ALL"}}, nil},
		{"NET_ADMIN", m{"image": "x", "cap_add": l{"NET_ADMIN"}}, nil},
		{"devices", m{"image": "x", "devices": l{"/dev/mem:/dev/mem"}}, nil},
		{"seccomp unconfined", m{"image": "x", "security_opt": l{"seccomp=unconfined"}}, nil},
		{"seccomp unconfined with spaces", m{"image": "x", "security_opt": l{"seccomp = unconfined"}}, nil},
		{"apparmor unconfined", m{"image": "x", "security_opt": l{"apparmor:unconfined"}}, nil},
		{"label disable", m{"image": "x", "security_opt": l{"label=disable"}}, nil},
		{"no-new-privileges off (hole)", m{"image": "x", "security_opt": l{"no-new-privileges:false"}}, nil},
		{"engine socket", m{"image": "x", "volumes": l{bind("/run/user/1000/podman/podman.sock")}}, nil},
		{"docker.sock", m{"image": "x", "volumes": l{bind("/var/run/docker.sock")}}, nil},
		{"root filesystem", m{"image": "x", "volumes": l{bind("/")}}, nil},
		{"etc", m{"image": "x", "volumes": l{bind("/etc")}}, nil},
		{"etc by path trick", m{"image": "x", "volumes": l{bind("/tmp/../etc")}}, nil},
		{"ssh keys", m{"image": "x", "volumes": l{bind("/home/u/.ssh")}}, nil},
		{"om state", m{"image": "x", "volumes": l{bind("/home/u/.local/state/om/data")}}, nil},
		{"home itself", m{"image": "x", "volumes": l{bind("/home/u")}}, nil},
		{"named volume binding /etc (hole)", m{"image": "x", "volumes": l{m{"type": "volume", "source": "v", "target": "/h"}}},
			m{"volumes": m{"v": m{"driver": "local", "driver_opts": m{"type": "none", "o": "bind", "device": "/etc"}}}}},
		{"named volume binding ~/.ssh (hole)", m{"image": "x", "volumes": l{m{"type": "volume", "source": "v", "target": "/h"}}},
			m{"volumes": m{"v": m{"driver_opts": m{"type": "none", "o": "rw,bind", "device": "/home/u/.ssh"}}}}},
		{"config from ~/.ssh (hole)", m{"image": "x", "configs": l{"c"}}, m{"configs": m{"c": m{"file": "/home/u/.ssh/id_ed25519"}}}},
		{"config long syntax from /etc (hole)", m{"image": "x", "configs": l{m{"source": "c"}}}, m{"configs": m{"c": m{"file": "/etc/shadow"}}}},
		{"secret from the engine socket (hole)", m{"image": "x", "secrets": l{"s"}}, m{"secrets": m{"s": m{"file": "/run/podman/podman.sock"}}}},
		{"container_name squatting a core name (hole)", m{"image": "x", "container_name": "om_router"}, nil},
		{"volumes_from another container (hole)", m{"image": "x", "volumes_from": l{"om_dashboard"}}, nil},
		{"volumes_from container: form (hole)", m{"image": "x", "volumes_from": l{"container:om_dashboard:ro"}}, nil},
		{"open egress with a writable volume", m{"image": "x", "labels": m{"om.egress": "internet"}, "cap_drop": l{"ALL"},
			"volumes": l{m{"type": "volume", "source": "d", "target": "/d"}}}, nil},
		{"egress without dropping NET_RAW", m{"image": "x", "labels": m{"om.egress": "a.example.com"}}, nil},
		{"egress with NET_ADMIN", m{"image": "x", "labels": m{"om.egress": "a.example.com"}, "cap_add": l{"NET_ADMIN"}}, nil},
		{"egress learn with secrets", m{"image": "x", "labels": m{"om.egress": "learn"}, "cap_drop": l{"ALL"}, "secrets": l{"s"}}, nil},
		{"egress host that is an acl line", m{"image": "x", "labels": m{"om.egress": "a.com\nhttp_access allow all"}, "cap_drop": l{"ALL"}}, nil},
	}
	for _, c := range cases {
		if len(gate(c.svc, c.extra, "/home/u")) == 0 {
			t.Errorf("the gate let this through: %s", c.name)
		}
	}
}

func TestLawsCannotBeWaivedByLabel(t *testing.T) {
	for _, rule := range []string{"privileged", "ports", "core-names"} {
		svc := m{"image": "x", "privileged": true, "ports": l{m{"target": 80}}, "container_name": "om_x", "labels": m{"om.policy.allow": rule}}
		found := strings.Join(gate(svc, nil, "/home/u"), "\n")
		if !strings.Contains(found, "`"+rule+"` is a law") {
			t.Errorf("%s: no 'is a law' in\n%s", rule, found)
		}
		ok := false
		for _, word := range []string{"privileged: true", "publishes host ports", "belong to the core"} {
			ok = ok || strings.Contains(found, word)
		}
		if !ok {
			t.Errorf("%s: the violation itself is missing:\n%s", rule, found)
		}
	}
}

func TestTheOMPrefixAndCoreAreNotWorkspaceIDsHoleOMWorkspace(t *testing.T) {
	// a workspace `om` would own containers named om_dashboard, om_router ...
	if workspace.IsValidWorkspaceID("om") || workspace.IsValidWorkspaceID("core") || !workspace.IsValidWorkspaceID("om2") || !workspace.IsValidWorkspaceID("my-om") {
		t.Error("reserved workspace ids")
	}
}

func TestAnOrdinaryServiceAndItsOwnVolumesAreFine(t *testing.T) {
	svc := m{"image": "x", "cap_drop": l{"ALL"}, "volumes_from": l{"db:ro"}, "volumes": l{
		m{"type": "bind", "source": "/home/u/projects/data", "target": "/d"}, m{"type": "bind", "source": "/media/disk", "target": "/m"}}}
	v, _ := policy.EvaluateConfig(m{"services": m{"s": svc, "db": m{"image": "d"}}}, "/home/u", "")
	if len(v) != 0 {
		t.Errorf("refused an ordinary service: %v", v)
	}
}

func TestDangerousWaivableRulesStayVisibleWhenWaived(t *testing.T) {
	svc := m{"image": "x", "cap_add": l{"SYS_ADMIN"}, "labels": m{"om.policy.allow": "caps"}}
	v, waived := policy.EvaluateConfig(m{"services": m{"s": svc}}, "/home/u", "")
	if len(v) != 0 || len(waived) == 0 {
		t.Errorf("violations %v, waived %v (`om policy check` keeps listing a waived rule)", v, waived)
	}
}

// ---- generated configs keep their shape ----

func routeOpts(lbl map[string]string) routes.Options {
	o, _ := routes.RouteOptions("", "s", lbl, nil)
	return o
}

func TestCaddyRoutePathsCannotAddDirectives(t *testing.T) {
	r := rng(7)
	alphabet := append(strings.Split("/ab*._~-{}\"'\\;$`%\n\r\t ,#", ""), "respond", "evil", "\n}\nrespond injected\n")
	base := routes.RenderVhost("w", "s", 80, routeOpts(nil), 3, true) + routes.RenderAlias("w", "s", 20003, false, routeOpts(nil))
	baseLines := map[string]bool{}
	for _, ln := range strings.Split(base, "\n") {
		baseLines[ln] = true
	}
	shape := regexp.MustCompile(`^\s*(handle \{|handle /[A-Za-z0-9._~/*-]* \{|import to_dashboard(_public)?|import to_workspace \S+:\d+|\}|redir /[A-Za-z0-9._~/*-]* http://\{host\}:\d+[A-Za-z0-9._~/{}*-]*)\s*$`)
	for i := 0; i < 1500; i++ {
		var raw strings.Builder
		for n := 1 + r.IntN(14); n > 0; n-- {
			raw.WriteString(pick(r, alphabet))
		}
		opts := routeOpts(map[string]string{"om.route.aliases": raw.String(), "om.route.dashboard_paths": raw.String()})
		out := routes.RenderVhost("w", "s", 80, opts, 3, true) + routes.RenderAlias("w", "s", 20003, false, opts)
		for _, line := range strings.Split(out, "\n") {
			if !baseLines[line] && !shape.MatchString(line) {
				t.Fatalf("label %q produced %q", raw.String(), line)
			}
		}
	}
}

func TestAnAliasCannotRedirectTheDashboardsOwnAddressHoleEmptyAlias(t *testing.T) {
	// `om.route.aliases=/` rendered `redir /* http://<service>`: every request on the dashboard's address went to that service
	for _, alias := range []string{"/", "/*", "/api", "/API/x", "/api/services", "/opensearch.xml", "/healthz", "/healthz/"} {
		opts := routeOpts(map[string]string{"om.route.aliases": alias})
		if len(opts.Aliases) != 0 {
			t.Errorf("alias %q kept: %v", alias, opts.Aliases)
		}
		text := routes.RenderAlias("w", "s", 20003, false, opts)
		if regexp.MustCompile(`(?m)^redir\s+(/\*|http)`).MatchString(text) {
			t.Errorf("alias %q rendered %q", alias, text)
		}
	}
	if got := routeOpts(map[string]string{"om.route.aliases": "/apix, /my-app, /a/b"}).Aliases; strings.Join(got, " ") != "/apix /my-app /a/b" {
		t.Errorf("good aliases: %v", got)
	}
}

func TestSquidACLOnlyContainsValidHosts(t *testing.T) {
	r := rng(11)
	alphabet := append(strings.Split("ab.*-_,; \n\r\t#", ""), "example", "com", "http_access allow all", "\nacl x dstdomain evil.com")
	lineOK := regexp.MustCompile(`^(# .*|acl [sd]_\w+ src \d+\.\d+\.\d+\.\d+/32|acl d_\w+ dstdomain ( ?\.?[a-z0-9.-]+)+|http_access allow s_\w+( d_\w+)?)$`)
	e := egress.New(state.NewDirs())
	for i := 0; i < 2000; i++ {
		var raw strings.Builder
		for n := 1 + r.IntN(30); n > 0; n-- {
			raw.WriteString(pick(r, alphabet))
		}
		rule, ok := egress.ParseLabel(raw.String())
		if !ok || rule.Mode != "" {
			continue
		}
		for _, h := range rule.Hosts {
			if !egress.ValidHost(h) {
				t.Fatalf("%q from %q", h, raw.String())
			}
		}
		acl, err := e.RenderACL("ws", map[string]egress.Rule{"svc": rule}, map[string]string{"svc": "10.89.1.2"})
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimRight(acl, "\n"), "\n") {
			if !lineOK.MatchString(line) {
				t.Fatalf("label %q produced %q", raw.String(), line)
			}
		}
	}
}

func TestHAProxyFragmentsForValidNamesHaveOnlyKnownLines(t *testing.T) {
	ok := regexp.MustCompile(`^(|# Service: [a-z0-9-]+ \([a-z0-9-]+\)|(frontend|backend) \w+|    (bind \S+( mode \d+)?|log global|option tcplog|default_backend \w+|server s1 \S+( resolvers docker init-addr libc,none check inter 5s)?))$`)
	for _, name := range []string{"web", "a-b-c", "x1"} {
		for _, frag := range []string{stream.RenderEdgeFragment("ws", name, 25565, ""), stream.RenderRouterFragment("ws", name, 25565, 80)} {
			for _, line := range strings.Split(frag, "\n") {
				if !ok.MatchString(line) {
					t.Errorf("%s: unexpected line %q", name, line)
				}
			}
		}
	}
}

func TestStreamLabelsCannotNameReservedOrHostilePorts(t *testing.T) {
	for _, port := range []string{"80", "443", "8080", "8443", "20000", "21199", "22000", "22199", "1023", "65536", "-1", "25565.0", "2e4", "0x50", "80 80"} {
		meta, problems := stream.ParseMeta(map[string]string{"om.tcp": "80", "om.tcp.port": port}, "s", 80, 443)
		if meta != nil || len(problems) == 0 {
			t.Errorf("host port %q: %v %v", port, meta, problems)
		}
	}
	for _, bad := range []string{"0", "65536", "-5", "80\n80", "eighty", "８０"} {
		if meta, _ := stream.ParseMeta(map[string]string{"om.tcp": bad}, "s", 80, 443); meta != nil {
			t.Errorf("container port %q accepted", bad)
		}
	}
}

func TestYAMLLabelValuesCannotBreakOutOfAQuotedString(t *testing.T) {
	for _, v := range []string{`a"b`, `a\b`, "a\nb", "a\rb"} {
		if scaffold.YAMLLabelSafe(v) {
			t.Errorf("%q is not safe", v)
		}
	}
	if !scaffold.YAMLLabelSafe("a normal value: with symbols # & *") {
		t.Error("a normal value is refused")
	}
}

func TestAPreviewBranchCannotBeAGitOptionHoleNoValidation(t *testing.T) {
	for _, b := range []string{"--detach", "-b", "--orphan=x", "a b", "a..b", "a\nb", "a;rm", "a@{1}", "a~1", "a^", "a:b", `a\b`, "", strings.Repeat("a", 150), "/a", "a/", "a//b", ".a", "a.lock"} {
		if previews.ValidBranch(b) {
			t.Errorf("branch %q accepted", b)
		}
	}
	for _, b := range []string{"main", "feature/login", "fix_123", "release-1.2"} {
		if !previews.ValidBranch(b) {
			t.Errorf("branch %q refused", b)
		}
	}
}

var _ = fmt.Sprintf
