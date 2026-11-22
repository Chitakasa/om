package attacks

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/firewall"
	"github.com/Chitakasa/om/internal/labels"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/routes"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

// Seeded fuzzing of everything a user (or a compose file from someone else) can put in front of om's generated
// configuration: names, hosts, route labels, `om.caddy` snippets, address rules, limits and settings. Each property
// holds for thousands of hostile inputs: nothing panics, and nothing a validator rejects reaches a config file.
//
// The seed is fixed, so a failure reproduces; change fuzzSeed (or fuzzRounds) to look further.
const (
	fuzzSeed   = 20261121
	fuzzRounds = 2500
)

var atoms = []string{"a", "b", "web", "0", "9", "-", "_", ".", "/", "//", "..", "*", "~", "%2f", "%00", "$", "{", "}", "{$", "{env.", "{file.",
	"{uri}", "\n", "\r", "\t", "\x00", "\x1b", "‮", "／", "∕", "é", "٣", "\"", "'", "`", "\\", ";", "#", " ", "  ",
	"@", "import ", "respond ", "reverse_proxy ", "}\n", "{\n", "https://", "http://127.0.0.1", "ntfy.sh/", "example.org",
	"10.0.0.1", "/24", "::1", "vpn", "256m", "200", "0.5", ",", "|", "<<", "remote_ip", "OM_POLICY=warn"}

var control = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func hostile(r *rand.Rand) string {
	if r.Float64() < 0.05 {
		return strings.Repeat(pick(r, atoms), 50+r.IntN(351))
	}
	var b strings.Builder
	for n := 1 + r.IntN(9); n > 0; n-- {
		b.WriteString(pick(r, atoms))
	}
	return b.String()
}

// mutate is a known-good value with one hostile atom spliced in.
func mutate(r *rand.Rand, good string) string {
	i := r.IntN(len(good) + 1)
	return good[:i] + pick(r, atoms) + good[i:]
}

func cases(good []string, rounds int, f func(string)) {
	r := rng(fuzzSeed)
	for n := 0; n < rounds; n++ {
		if n%2 == 1 {
			f(hostile(r))
		} else {
			f(mutate(r, pick(r, good)))
		}
	}
}

func TestASafeNameIsOnlyLowercaseLettersDigitsAndHyphens(t *testing.T) {
	strict := regexp.MustCompile(`\A[a-z0-9][a-z0-9-]{0,62}\z`)
	cases([]string{"web", "my-app", "a1"}, fuzzRounds, func(x string) {
		if workspace.SafeNameRE.MatchString(x) && !strict.MatchString(x) {
			t.Fatalf("%q accepted as a safe name", x)
		}
		if workspace.IsSafeName(x) != workspace.SafeNameRE.MatchString(x) {
			t.Fatalf("IsSafeName and the regex disagree on %q", x)
		}
	})
}

func TestASafeDomainIsOnlyLettersDigitsDotsAndHyphens(t *testing.T) {
	strict := regexp.MustCompile(`\A[a-z0-9.-]+\z`)
	cases([]string{"web.example.org", "a-b.localhost"}, fuzzRounds, func(x string) {
		if workspace.SafeDomainRE.MatchString(x) && !strict.MatchString(x) {
			t.Fatalf("%q accepted as a safe domain", x)
		}
	})
}

func TestAnAcceptedHostCannotCarryProxyConfig(t *testing.T) {
	strict := regexp.MustCompile(`\A(\*\.)?[a-z0-9.-]+\z`)
	cases([]string{"api.example.org", "*.example.org", "cdn.example.com"}, fuzzRounds, func(x string) {
		if egress.ValidHost(x) && !strict.MatchString(x) {
			t.Fatalf("%q accepted as an egress host", x)
		}
	})
}

func TestParsingTheEgressLabelNeverPanicsAndKeepsOnlyValidHosts(t *testing.T) {
	r := rng(fuzzSeed)
	for i := 0; i < fuzzRounds; i++ {
		var parts []string
		for n := 1 + r.IntN(4); n > 0; n-- {
			parts = append(parts, hostile(r))
		}
		value := strings.Join(parts, ",")
		if rule, ok := egress.ParseLabel(value); ok && rule.Mode == "" {
			for _, h := range rule.Hosts {
				if !egress.ValidHost(h) {
					t.Fatalf("%q from %q", h, value)
				}
			}
		}
	}
}

func TestLimitsAreNumbersOrRefused(t *testing.T) {
	mem, cpus := regexp.MustCompile(`\A"?\d+[kmg]"?\z`), regexp.MustCompile(`\A"?[0-9.]+"?\z`)
	pids := regexp.MustCompile(`\A"?\d+"?\z`)
	r := rng(fuzzSeed)
	for i := 0; i < fuzzRounds; i++ {
		lbl := map[string]any{"om.mem": hostile(r), "om.pids": hostile(r), "om.cpus": hostile(r)}
		out, _ := labels.ParseLimits(lbl)
		for _, l := range out {
			re := map[string]*regexp.Regexp{"mem_limit": mem, "pids_limit": pids, "cpus": cpus}[l.Key]
			if re == nil || !re.MatchString(l.Value) {
				t.Fatalf("limit %s=%q from %v", l.Key, l.Value, lbl)
			}
		}
	}
}

func TestOnlyAddressesRangesAndTheVPNWordSurviveIntoFirewallRules(t *testing.T) {
	d := state.NewDirs()
	t.Setenv("OM_STATE_DIR", t.TempDir())
	d = state.NewDirs()
	f := firewall.New(d, registry.New(d), "linux")
	f.VPNAllow = func() []string { return []string{"100.64.0.1/32"} }
	f.VPNIPs = func() []string { return []string{"100.64.0.1"} }
	item := regexp.MustCompile(`\A(vpn|[0-9a-f:.]+/\d+)\z`)
	bad := regexp.MustCompile("[;\\\\$`]")
	r := rng(fuzzSeed)
	for i := 0; i < fuzzRounds; i++ {
		lbl := map[string]string{"om.net.allow": hostile(r) + "," + hostile(r) + "," + hostile(r), "om.net.deny": hostile(r)}
		net, _ := routes.ParseNetPolicy(lbl, []string{"100.64.0.1"})
		if net == nil {
			continue
		}
		for _, it := range append(append([]string{}, net.Allow...), net.Deny...) {
			if !item.MatchString(it) {
				t.Fatalf("%q from %v", it, lbl)
			}
		}
		pol := firewall.Policy{"ports": []any{8080}, "allow": toAny(net.Allow), "deny": toAny(net.Deny)}
		for _, forward := range []bool{false, true} {
			for _, line := range f.NftNetRules("ws/svc", pol, forward) {
				if control.MatchString(line) || bad.MatchString(line) {
					t.Fatalf("rule %q from %v", line, lbl)
				}
			}
		}
	}
}

func toAny(l []string) any {
	if l == nil {
		return nil
	}
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

func TestARejectedPathNeverReachesTheGeneratedCaddyfile(t *testing.T) {
	r := rng(fuzzSeed)
	allowed := regexp.MustCompile(`^/[A-Za-z0-9._~/-]*\*?$`)
	quirk := regexp.MustCompile("[\"\\\\;\x00-\x1f]")
	for i := 0; i < fuzzRounds/2; i++ {
		alias, dpath := hostile(r), hostile(r)
		lbl := map[string]string{"om.route.aliases": alias, "om.route.dashboard_paths": dpath, "om.log": hostile(r)}
		opts, _ := routes.RouteOptions("", "svc", lbl, nil)
		for _, p := range append(append([]string{}, opts.Aliases...), opts.DashboardPaths...) {
			if !allowed.MatchString(p) {
				t.Fatalf("%q from %v", p, lbl)
			}
		}
		texts := []string{routes.RenderVhost("ws", "svc", 8080, opts, 3, true), routes.RenderAlias("ws", "svc", 20003, false, opts)}
		for _, out := range texts {
			if strings.Count(out, "{") != strings.Count(out, "}") {
				t.Fatalf("unbalanced braces for %v", lbl)
			}
			if strings.ContainsAny(out, "\x00\x1b‮") {
				t.Fatalf("control character in the output for %v", lbl)
			}
		}
		accepted := map[string]bool{}
		for _, p := range append(append([]string{}, opts.Aliases...), opts.DashboardPaths...) {
			accepted[p] = true
		}
		for _, raw := range regexp.MustCompile(`[,\s]+`).Split(alias+","+dpath, -1) {
			// text with a quote, backslash, `;` or control character that the validator refused must not appear at all
			if len(raw) >= 2 && !accepted[raw] && quirk.MatchString(raw) {
				for _, out := range texts {
					if strings.Contains(out, raw) {
						t.Fatalf("rejected %q was written to the config", raw)
					}
				}
			}
		}
	}
}

var snippetBase = []string{"header X-Frame-Options DENY\n", "respond /health 200\n", "redir /old /new 301\n", "@api path /api/*\nrespond @api 204\n"}

func TestSnippetValidationNeverPanicsOnAnything(t *testing.T) {
	r := rng(fuzzSeed)
	for i := 0; i < fuzzRounds; i++ {
		var lines []string
		for n := 1 + r.IntN(6); n > 0; n-- {
			lines = append(lines, hostile(r))
		}
		routes.ValidateSnippet(strings.Join(lines, "\n"))
	}
}

func TestAForbiddenTokenAnywhereMakesASnippetFail(t *testing.T) {
	r := rng(fuzzSeed)
	for _, base := range snippetBase {
		if p := routes.ValidateSnippet(base); len(p) != 0 {
			t.Fatalf("the base snippet %q must pass: %v", base, p)
		}
	}
	tokens := append(append([]string{}, routes.SnippetForbidden...), routes.SnippetClientAddress...)
	shapes := []string{"%s", "# %s", "  \t%s  ", `respond "%s"`, "header X %s", "respond \"\n# %s\""}
	for i := 0; i < fuzzRounds; i++ {
		base := pick(r, snippetBase)
		token := pick(r, tokens)
		line := strings.Replace(pick(r, shapes), "%s", token, 1)
		lines := strings.Split(strings.TrimSuffix(base, "\n"), "\n")
		at := r.IntN(len(lines) + 1)
		lines = append(lines[:at], append([]string{line}, lines[at:]...)...)
		text := strings.Join(lines, "\n") + "\n"
		if len(routes.ValidateSnippet(text)) == 0 {
			t.Fatalf("accepted a snippet with %q: %q", token, text)
		}
	}
}

func TestUnbalancedBracesFail(t *testing.T) {
	r := rng(fuzzSeed)
	for i := 0; i < fuzzRounds; i++ {
		base := pick(r, snippetBase)
		text := pick(r, []string{base + "}\n", "{\n" + base, base + "route {\n"})
		if len(routes.ValidateSnippet(text)) == 0 {
			t.Fatalf("accepted %q", text)
		}
	}
}

func TestAnIPv6ScopeIDIsNotAnAddressRule(t *testing.T) {
	net, problems := routes.ParseNetPolicy(map[string]string{"om.net.allow": "fe80::1%eth0"}, nil)
	if len(problems) == 0 { // the label is reported, and callers fail closed on it
		t.Error("not reported")
	}
	if net != nil && strings.Contains(strings.Join(net.Allow, ","), "%") {
		t.Errorf("kept the scope id: %v", net.Allow)
	}
	s := settings.Settings{"OM_VPN_ALLOW": "fe80::1%eth0,10.0.0.1"}
	if got := s.VPNAllow(); len(got) != 1 || got[0] != "10.0.0.1/32" {
		t.Errorf("VPN allow-list: %v", got)
	}
}
