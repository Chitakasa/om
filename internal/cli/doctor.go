package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/core"
	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/labels"
	"github.com/Chitakasa/om/internal/links"
	"github.com/Chitakasa/om/internal/migration"
	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/policy"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

// Port of lib/gitops/doctor.py. Each check returns (status, message, fix).
const (
	docPass = "PASS"
	docWarn = "WARN"
	docFail = "FAIL"
)

type docResult struct{ status, msg, fix string }

type docCheck struct {
	title string
	fn    func(rt string) docResult
}

func dr(s, m, f string) docResult { return docResult{s, m, f} }

// docHTTP is the HTTP status of a request with a given Host header; 0 if the connection failed.
func (a *App) docHTTP(host, path, addr string) int {
	if addr == "" {
		addr = "127.0.0.1"
	}
	port, _ := a.Settings().EdgePorts()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/%s", net.JoinHostPort(addr, strconv.Itoa(port)), strings.TrimPrefix(path, "/")), nil)
	if err != nil {
		return 0
	}
	req.Host = host
	req.Header.Set("User-Agent", "om-doctor")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (a *App) runtimeEnv() map[string]string {
	m, _ := state.ParseEnvFile(a.D.RuntimeEnv)
	if m == nil {
		m = map[string]string{}
	}
	return m
}

func (a *App) edgePortList() []int { h, s := a.Settings().EdgePorts(); return []int{h, s} }

func joinInts(v []int, sep string) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, sep)
}

func (a *App) docEngine(rt string) docResult {
	e := a.Eng.EngineInfo(rt)
	if !e.OK {
		return dr(docFail, rt+" not responding", "Start your container engine (`podman machine start`, Docker Desktop, or `systemctl start docker`).")
	}
	mode := "rootful"
	if e.Rootless {
		mode = "rootless"
	}
	if e.RemoteVM {
		mode += ", VM"
	}
	return dr(docPass, fmt.Sprintf("%s (%s), socket %s", rt, mode, e.Socket), "")
}

func (a *App) docCompose(rt string) docResult {
	if a.Eng.ComposeAvailable(rt) {
		return dr(docPass, fmt.Sprintf("`%s compose` available", rt), "")
	}
	return dr(docFail, fmt.Sprintf("`%s compose` missing", rt), "Install docker-compose v2 (or podman-compose).")
}

func (a *App) docPorts(rt string) docResult {
	e := a.Eng.EngineInfo(rt)
	ports := a.edgePortList()
	if state.IsLinux && e.Rootless && !e.RemoteVM {
		low := ports[0]
		if ports[1] < low {
			low = ports[1]
		}
		if start, ok := a.Eng.UnprivilegedPortStart(); ok && start > low {
			return dr(docFail, fmt.Sprintf("unprivileged ports start at %d", start),
				fmt.Sprintf("echo 'net.ipv4.ip_unprivileged_port_start=%d' | sudo tee /etc/sysctl.d/99-om.conf && sudo sysctl --system", low))
		}
	}
	return dr(docPass, "can bind "+joinInts(ports, "/"), "")
}

func (a *App) docCore(rt string) docResult {
	var down []string
	for _, c := range state.CoreContainers {
		if !a.Eng.ContainerRunning(rt, c) {
			down = append(down, c)
		}
	}
	if len(down) > 0 {
		return dr(docFail, "not running: "+strings.Join(down, ", "), "om core start")
	}
	var retired []string
	for _, c := range state.RetiredContainers {
		if a.Run([]string{rt, "container", "inspect", c}).Code == 0 {
			retired = append(retired, c)
		}
	}
	if len(retired) > 0 {
		return dr(docWarn, "removed parts still present: "+strings.Join(retired, ", "), "om core restart")
	}
	return dr(docPass, strings.Join(state.CoreContainers, ", ")+" running", "")
}

func (a *App) docHealthchecks(rt string) docResult {
	wanted := a.Reg.Read()
	r := a.Run([]string{rt, "ps", "--format", `{{.Names}}` + "\t" + `{{.Status}}` + "\t" + `{{index .Labels "com.docker.compose.project"}}`})
	var bare []string
	if r.Code == 0 {
		for _, line := range py.SplitLines(r.Stdout) {
			f := append(strings.Split(line, "\t"), "", "")
			if _, ok := wanted[f[2]]; ok && !strings.Contains(f[1], "(") {
				bare = append(bare, f[0])
			}
		}
	}
	if len(bare) > 0 {
		sort.Strings(bare)
		return dr(docWarn, "no healthcheck: "+strings.Join(bare, ", "), "add a healthcheck: to the service in its compose file")
	}
	return dr(docPass, "every running workspace container has a healthcheck", "")
}

func netKeys(out string) (map[string]bool, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(out), &m) != nil || m == nil {
		return nil, false
	}
	set := map[string]bool{}
	for k := range m {
		set[k] = true
	}
	return set, true
}

func (a *App) docRouterNetworks(rt string) docResult {
	want := map[string]bool{}
	for w := range a.Reg.Read() {
		want[w+"_net"] = true
		for _, n := range a.Eng.ProjectNetworks(rt, w) {
			want[n] = true
		}
	}
	r := a.Run([]string{rt, "inspect", state.Router, "--format", "{{json .NetworkSettings.Networks}}"})
	have, ok := netKeys(r.Stdout)
	if !ok {
		return dr(docWarn, "could not inspect router networks", "om core restart")
	}
	var missing []string
	for n := range want {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return dr(docFail, fmt.Sprintf("router not attached to %s (their services are unreachable)", strings.Join(missing, ", ")), "om core start")
	}
	return dr(docPass, fmt.Sprintf("router attached to %d workspace and project network(s)", len(want)), "")
}

func (a *App) docEdgeIsolated(rt string) docResult {
	r := a.Run([]string{rt, "inspect", state.Edge, "--format", "{{json .NetworkSettings.Networks}}"})
	nets, ok := netKeys(r.Stdout)
	if !ok {
		return dr(docWarn, "could not inspect edge networks", "")
	}
	var extra []string
	for n := range nets {
		if n != "om_core_net" {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		return dr(docFail, fmt.Sprintf("edge proxy is on workspace network(s) %s — containers there can reach the private tier", strings.Join(extra, ", ")),
			"om core restart   (and remove any `network connect ... om_caddy` from your scripts)")
	}
	return dr(docPass, "edge proxy reachable only from om_core_net", "")
}

func isCore(name string) bool {
	for _, c := range state.CoreContainers {
		if c == name {
			return true
		}
	}
	return false
}

func (a *App) docPublishedPorts(rt string) docResult {
	r := a.Run([]string{rt, "ps", "--format", "{{.Names}}\t{{.Ports}}"})
	var leaks []string
	for _, line := range py.SplitLines(r.Stdout) {
		name, ports, _ := strings.Cut(line, "\t")
		if isCore(name) || !strings.Contains(ports, "->") {
			continue
		}
		leaks = append(leaks, fmt.Sprintf("%s (%s)", name, ports))
	}
	if len(leaks) > 0 {
		return dr(docFail, "containers publish host ports, bypassing the proxy: "+strings.Join(leaks, "; "), "Replace `ports:` with `expose:` in their compose files, then `om start`.")
	}
	return dr(docPass, "no container publishes host ports except the edge", "")
}

func (a *App) docDrift(rt string) docResult {
	if d := a.Core.RuntimeDrift(); len(d) > 0 {
		return dr(docWarn, d[0], "om core restart")
	}
	return dr(docPass, "ingress addresses match this network", "")
}

func (a *App) docRebinding(string) docResult {
	code := a.docHTTP("attacker.example", "/api/workspaces", "")
	if code == 0 || code == 403 {
		return dr(docPass, "foreign Host on the private tier is refused (DNS-rebinding safe)", "")
	}
	return dr(docFail, fmt.Sprintf("foreign Host got HTTP %d", code), "Restore the explicit host list and `:80 { abort }` in core/caddy/Caddyfile.")
}

func (a *App) docPrivateReachable(string) docResult {
	code := a.docHTTP("localhost", "/healthz", "")
	base := a.BaseURL("")
	if code == 200 || code == 401 {
		return dr(docPass, fmt.Sprintf("private tier answers on %s/", base), "")
	}
	got := "no answer"
	if code != 0 {
		got = strconv.Itoa(code)
	}
	return dr(docFail, fmt.Sprintf("%s/ returned %s", base, got), "om core restart; then om doctor")
}

// probeImage is the pinned Alpine image the dashboard runs in (already pulled for the egress and tools builds).
func (a *App) probeImage() string {
	f := filepath.Join(a.D.Core, "compose.yml")
	if _, err := os.Stat(f); err != nil {
		f = filepath.Join(a.D.Core, "docker-compose.yml")
	}
	text, _ := py.ReadText(f)
	for _, line := range py.SplitLines(text) {
		if strings.Contains(line, "image:") && strings.Contains(line, "/alpine:") {
			return py.Strip(line[strings.Index(line, "image:")+len("image:"):])
		}
	}
	return ""
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// firstNonEmpty is Python's `a or b`.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (a *App) docRouterToken(rt string) docResult {
	l := a.Run([]string{rt, "exec", state.Router, "netstat", "-lnt"})
	if l.Code == 0 && strings.Contains(l.Stdout, "LISTEN") {
		return dr(docFail, "the router listens on the network: containers can connect to it", "om core restart (core/caddy/router/Caddyfile binds a unix socket only)")
	}
	r := a.Run([]string{rt, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"-v", "om_router_sock:/run/om-router:ro", "-v", a.probeMount(), a.probeImage(), probeBin, "probe", "router"})
	if py.Strip(r.Stdout) == "refused" {
		return dr(docPass, "router listens on no network; on its socket it refuses requests without the edge token", "")
	}
	return dr(docFail, fmt.Sprintf("router probe: %s (expected 'refused')", py.Repr(firstNonEmpty(py.Strip(r.Stdout), tail(py.Strip(r.Stderr), 160)))),
		"Check core/caddy/router/Caddyfile and data/edge_token in the om state dir; om core restart")
}

func (a *App) docEngineFilter(rt string) docResult {
	r := a.Run([]string{rt, "exec", "om_dashboard", probeBin, "probe", "sock"})
	if strings.Join(strings.Fields(r.Stdout), " ") == "0 200 403" {
		return dr(docPass, "dashboard has read-only engine access (writes → 403, no raw socket)", "")
	}
	return dr(docFail, fmt.Sprintf("engine filter probe returned %s (expected '0 200 403')", py.Repr(firstNonEmpty(py.Strip(r.Stdout), tail(py.Strip(r.Stderr), 200)))),
		"om core restart; check core/caddy/sockguard/Caddyfile")
}

// openEgressWithData: "writable volume" / "secrets" if a service combines open egress with data it could leak and
// does not waive the rule.
func (a *App) openEgressWithData(rt, wpath, svc string) string {
	var cfiles []string
	for _, pat := range []string{"", "*/", "*/*/"} {
		for _, n := range []string{"compose.yml", "docker-compose.yml"} {
			if pat == "" {
				cfiles = append(cfiles, filepath.Join(wpath, n))
				continue
			}
			m, _ := filepath.Glob(filepath.Join(wpath, pat+n))
			sort.Strings(m)
			cfiles = append(cfiles, m...)
		}
	}
	env := workspace.EnvList(a.runtimeEnv())
	for _, cf := range cfiles {
		if st, err := os.Stat(cf); err != nil || st.IsDir() {
			continue
		}
		cfg, _ := policy.ComposeConfig(a.RunIn, rt, cf, env)
		if len(cfg) == 0 {
			continue
		}
		services, _ := cfg["services"].(map[string]any)
		sv, _ := services[svc].(map[string]any)
		if len(sv) == 0 {
			continue
		}
		waived := false
		for _, w := range strings.Split(py.Str(labels.Service(sv)[policy.AllowLabel]), ",") {
			if py.Strip(w) == "egress" {
				waived = true
			}
		}
		hasWrites, hasSecrets := policy.Writes(sv), py.Truthy(sv["secrets"])
		if (hasWrites || hasSecrets) && !waived {
			if hasWrites {
				return "writable volume"
			}
			return "secrets"
		}
	}
	return ""
}

func probeTarget(members []string, rules map[string]egress.Rule) string {
	for _, m := range members {
		keys := make([]string, 0, len(rules))
		for k := range rules {
			keys = append(keys, k)
		}
		for _, k := range keys {
			if strings.Contains(m, k) {
				for _, h := range rules[k].Hosts {
					if !strings.HasPrefix(h, "*.") {
						return h
					}
				}
			}
		}
	}
	return "example.com"
}

var ipRE = regexp.MustCompile(`^[0-9.]+$`)

func (a *App) probeNetwork(rt, netName string, rules map[string]egress.Rule, hosts []string) (string, string) {
	members := strings.Fields(a.Run([]string{rt, "ps", "--filter", "network=" + netName, "--format", "{{.Names}}"}).Stdout)
	proxy := "error"
	for _, m := range members {
		if m == state.Egress {
			proxy = "refused"
		}
	}
	cmd := []string{rt, "run", "--rm", "--network", netName, "--read-only", "--cap-drop", "ALL", "-v", a.probeMount(), a.probeImage(), probeBin, "probe", "egress", probeTarget(members, rules)}
	r := a.Run(append(cmd, hosts...))
	want := "blocked blocked blocked " + proxy + " blocked"
	if strings.Join(strings.Fields(r.Stdout), " ") != want {
		return "bad", fmt.Sprintf("%s: %s (expected blocked ×3, proxy %s, raw_forge blocked)", netName, py.Repr(firstNonEmpty(py.Strip(r.Stdout), tail(py.Strip(r.Stderr), 120))), proxy)
	}
	if proxy == "error" {
		return "noproxy", netName
	}
	return "ok", netName
}

func (a *App) probeNetworks(rt string) (open, bad, noProxy []string) {
	hosts := []string{}
	for _, h := range append([]string{a.runtimeEnv()["LAN_IP"]}, a.vpnHosts()...) {
		if h != "" && !strings.HasSuffix(h, ".invalid") && ipRE.MatchString(h) {
			hosts = append(hosts, h)
		}
	}
	reg := a.Reg.Read()
	ids := make([]string, 0, len(reg))
	for w := range reg {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	for _, wid := range ids {
		rules := a.Egress.LoadRules(wid)
		for _, n := range append([]string{wid + "_net"}, a.Eng.ProjectNetworks(rt, wid)...) {
			if a.Run([]string{rt, "network", "inspect", n}).Code != 0 {
				continue
			}
			if !a.Eng.NetworkIsInternal(rt, n) {
				open = append(open, n)
				continue
			}
			switch out, detail := a.probeNetwork(rt, n, rules, hosts); out {
			case "bad":
				bad = append(bad, detail)
			case "noproxy":
				noProxy = append(noProxy, n)
			}
		}
	}
	return
}

func learnStatus(rem int64) string {
	if rem == -1 {
		return "permanent"
	}
	if rem > 0 {
		return fmt.Sprintf("%dh %dm left", rem/3600, (rem%3600)/60)
	}
	return "expired"
}

func (a *App) openEgressServices(rt string) (*docResult, []string, []string) {
	var learning, auditing []string
	reg := a.Reg.Read()
	ids := make([]string, 0, len(reg))
	for w := range reg {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	for _, wid := range ids {
		wpath := py.Str(reg[wid]["path"])
		if reg[wid]["path"] == nil {
			wpath = ""
		}
		rules := a.Egress.LoadRules(wid)
		svcs := make([]string, 0, len(rules))
		for s := range rules {
			svcs = append(svcs, s)
		}
		sort.Strings(svcs)
		for _, svc := range svcs {
			mode := rules[svc].Mode
			if (mode == egress.Learn || mode == egress.Internet || mode == egress.Audit) && isDir(wpath) {
				if problem := a.openEgressWithData(rt, wpath, svc); problem != "" {
					r := dr(docFail, fmt.Sprintf("service '%s/%s' has %s with om.egress=%s (refused by policy)", wid, svc, problem, mode),
						"list the hosts it needs or waive with om.policy.allow=egress")
					return &r, nil, nil
				}
			}
			switch mode {
			case egress.Learn:
				learning = append(learning, fmt.Sprintf("%s/%s (%s)", wid, svc, learnStatus(a.Egress.LearnRemaining(wid, svc))))
			case egress.Audit:
				auditing = append(auditing, wid+"/"+svc)
			}
		}
	}
	return nil, learning, auditing
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func (a *App) docEgress(rt string) docResult {
	open, bad, noProxy := a.probeNetworks(rt)
	if len(bad) > 0 {
		return dr(docFail, "egress probe failed (expected dns, direct, host addresses blocked; proxy refused without assigned IP; raw forging blocked): "+strings.Join(bad, "; "),
			"om core restart; check egress ACLs and container capabilities; om start")
	}
	refused, learning, auditing := a.openEgressServices(rt)
	if refused != nil {
		return *refused
	}
	var warns, fixes []string
	if len(open) > 0 {
		warns = append(warns, "open network(s) with internet access: "+strings.Join(open, ", "))
		fixes = append(fixes, "cd <workspace> && om network harden (project networks: om start recreates them internal)")
	}
	if len(learning) > 0 {
		warns = append(warns, "in learn mode (any public host allowed): "+strings.Join(learning, ", "))
		fixes = append(fixes, "om egress log <svc> --apply, then list the hosts")
	}
	if len(auditing) > 0 {
		warns = append(warns, "in audit mode (any public host allowed, permanently logged): "+strings.Join(auditing, ", "))
		fixes = append(fixes, "om egress log <svc> to inspect; use om.egress=<hosts> to enforce specific destinations")
	}
	if len(warns) > 0 {
		return dr(docWarn, strings.Join(warns, "; "), strings.Join(fixes, "; "))
	}
	msg := "workspace networks are internal; only om_egress leads out (source-IP ACL enforced)"
	if len(noProxy) > 0 {
		msg += fmt.Sprintf("; no proxy at all on %d network(s) without om.egress", len(noProxy))
	}
	return dr(docPass, msg, "")
}

func (a *App) docProjectIsolation(rt string) docResult {
	pairs := 0
	var bad []string
	reg := a.Reg.Read()
	ids := make([]string, 0, len(reg))
	for w := range reg {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	for _, wid := range ids {
		members := map[string]string{}
		for _, n := range a.Eng.ProjectNetworks(rt, wid) {
			r := a.Run([]string{rt, "ps", "--filter", "network=" + n, "--format", "{{.Names}}"})
			for _, m := range strings.Fields(r.Stdout) {
				if m != state.Router && m != state.Egress && m != state.StreamRouter {
					members[n] = m
					break
				}
			}
		}
		nets := make([]string, 0, len(members))
		for n := range members {
			nets = append(nets, n)
		}
		sort.Strings(nets)
		if len(nets) < 2 {
			continue
		}
		for i, an := range nets {
			bn := nets[(i+1)%len(nets)]
			target := members[bn]
			ip := py.Strip(a.Run([]string{rt, "inspect", "--format", fmt.Sprintf(`{{(index .NetworkSettings.Networks "%s").IPAddress}}`, bn), target}).Stdout)
			if ip == "" {
				continue
			}
			r := a.Run([]string{rt, "run", "--rm", "--network", an, "--read-only", "--cap-drop", "ALL", "-v", a.probeMount(), a.probeImage(), probeBin, "probe", "isolation", target, ip})
			pairs++
			if strings.Join(strings.Fields(r.Stdout), " ") != "blocked blocked" {
				bad = append(bad, fmt.Sprintf("%s → %s: %s", an, target, py.Repr(firstNonEmpty(py.Strip(r.Stdout), tail(py.Strip(r.Stderr), 120)))))
			}
		}
	}
	if len(bad) > 0 {
		return dr(docFail, "a folder's network reaches another folder's service: "+strings.Join(bad, "; "), "om core restart; om start in that workspace")
	}
	if pairs == 0 {
		return dr(docPass, "no workspace has two folders with running services to compare", "")
	}
	return dr(docPass, fmt.Sprintf("folders are isolated from each other (%d pair(s) probed: no name, no route)", pairs), "")
}

func (a *App) docGenerations(string) docResult {
	var bad, weak []string
	reg := a.Reg.Read()
	ids := make([]string, 0, len(reg))
	for w := range reg {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	for _, wid := range ids {
		p := ""
		if v, ok := reg[wid]["path"]; ok && v != nil {
			p = py.Str(v)
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if problems := a.Gen.VerifyChain(wid); len(problems) > 0 {
			bad = append(bad, wid+": "+problems[0])
			continue
		}
		cur := a.Gen.Current(wid)
		switch {
		case cur == nil:
			weak = append(weak, wid+": never deployed through om")
		case !py.Truthy(cur["commit"]):
			weak = append(weak, wid+": not a git repository")
		case py.Truthy(cur["dirty"]):
			weak = append(weak, fmt.Sprintf("%s: generation %s is dirty (uncommitted files)", wid, py.Str(cur["n"])))
		case !py.Truthy(cur["signer"]):
			weak = append(weak, fmt.Sprintf("%s: generation %s is unsigned", wid, py.Str(cur["n"])))
		}
	}
	if len(bad) > 0 {
		return dr(docFail, "generation log broken: "+strings.Join(bad, "; "), "om fsck in that workspace; the state dir may have been edited")
	}
	if len(weak) > 0 {
		return dr(docWarn, strings.Join(weak, "; "), "commit (signed) and `om start`; then OM_SIGNED=enforce in om.env")
	}
	return dr(docPass, "every workspace runs a clean, signed generation; logs chain", "")
}

// edgeListeners is what may listen in the edge container, and where. Anything else is a new door.
var edgeListeners = map[string]string{
	"tcp/80": "any", "tcp/443": "any", "udp/443": "any", "tcp/81": "any", "tcp/444": "any", "udp/444": "any",
	"tcp/8080": "any", "tcp/8443": "any", "udp/8443": "any", "tcp/2019": "loopback",
}

func (a *App) docAdminSurface(rt string) docResult {
	r := a.Run([]string{rt, "exec", state.Edge, "netstat", "-lntu"})
	if r.Code != 0 {
		return dr(docWarn, "could not list listeners in the edge container", "om core restart")
	}
	var bad []string
	for _, line := range py.SplitLines(r.Stdout) {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		switch parts[0] {
		case "tcp", "udp", "tcp6", "udp6":
		default:
			continue
		}
		proto, local := strings.TrimRight(parts[0], "6"), parts[3]
		i := strings.LastIndex(local, ":")
		addr, port := "", local
		if i >= 0 {
			addr, port = local[:i], local[i+1:]
		}
		where := edgeListeners[proto+"/"+port]
		if proto == "tcp" && state.IsNumber(port) {
			n, _ := strconv.Atoi(port)
			for _, base := range []int{state.PrivatePortBase, state.PublicPortBase} {
				if n >= base && n < base+state.PortSlots {
					where = "any"
				}
			}
		}
		if !(where == "any" || (where == "loopback" && (addr == "127.0.0.1" || addr == "::1"))) {
			bad = append(bad, proto+" "+local)
		}
	}
	if len(bad) > 0 {
		return dr(docFail, "unexpected listener(s) in the edge: "+strings.Join(bad, ", "), "find what opened it (podman exec om_caddy netstat -lntu); om core restart")
	}
	return dr(docPass, "edge listens only on its web ports and the services' own ports; Caddy admin on loopback only", "")
}

func (a *App) docWorkspacesFsck(string) docResult {
	exe, _ := os.Executable()
	var bad []string
	reg := a.Reg.Read()
	ids := make([]string, 0, len(reg))
	for w := range reg {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	for _, wid := range ids {
		p := py.Str(reg[wid]["path"])
		if reg[wid]["path"] == nil {
			p = ""
		}
		if _, err := os.Stat(filepath.Join(p, ".om", "config.json")); err != nil {
			continue
		}
		r := a.RunIn([]string{exe, "fsck"}, p, nil)
		if r.Code != 0 {
			first := "fsck failed"
			for _, ln := range py.SplitLines(r.Stdout) {
				if strings.Contains(ln, "✗") {
					first = py.Strip(ln)
					break
				}
			}
			first = strings.ReplaceAll(first, "\x1b", "")
			if rs := []rune(first); len(rs) > 120 {
				first = string(rs[:120])
			}
			bad = append(bad, wid+": "+first)
		}
	}
	if len(bad) > 0 {
		return dr(docFail, strings.Join(bad, "; "), "om fsck in that workspace")
	}
	return dr(docPass, "every workspace's running images match its lock; generation logs chain", "")
}

func (a *App) docCustomRoutes(string) docResult {
	files, _ := filepath.Glob(filepath.Join(a.D.Routes, "*.caddy"))
	var custom []string
	for _, f := range files {
		t, _ := py.ReadText(f)
		if rs := []rune(t); len(rs) > 400 {
			t = string(rs[:400])
		}
		if strings.Contains(t, "# custom:") {
			custom = append(custom, strings.TrimSuffix(filepath.Base(f), ".caddy"))
		}
	}
	sort.Strings(custom)
	if len(custom) > 0 {
		return dr(docPass, "own Caddy rules (om.caddy, checked against the allowed directives): "+strings.Join(custom, ", "), "")
	}
	return dr(docPass, "no service carries its own Caddy rules", "")
}

func (a *App) docLinks(rt string) docResult {
	found, problems := links.Describe(links.Runner(a.Run), rt)
	if len(problems) > 0 {
		return dr(docWarn, strings.Join(problems, "; "), "om links — fix the labels, then om start")
	}
	return dr(docPass, fmt.Sprintf("%d cross-workspace link(s), each a private network of exactly two services", len(found)), "")
}

func (a *App) docVPN(string) docResult {
	s := a.Settings()
	trusted := netdetect.VPNItems(s["OM_VPN"])
	tset := map[string]bool{}
	for _, t := range trusted {
		tset[t] = true
	}
	var untrusted []string
	for _, c := range a.Det.VPNCandidates() {
		if !tset[c.Name] && !tset[c.IP] {
			untrusted = append(untrusted, c.Name)
		}
	}
	note := ""
	if len(untrusted) > 0 {
		note = fmt.Sprintf("; not trusted: %s (`om vpn trust <iface>` if only your devices are on it)", strings.Join(untrusted, ", "))
	}
	hosts, allowed := a.vpnHosts(), s.VPNAllow()
	if len(allowed) > 0 && len(hosts) > 0 && !a.FW.VPNAllowEnforced() {
		return dr(docFail, fmt.Sprintf("OM_VPN_ALLOW (%s) is not in the host firewall: the VPN's private tier is closed", strings.Join(allowed, ", "))+note, "om firewall apply")
	}
	if len(allowed) > 0 && len(hosts) > 0 {
		msg := fmt.Sprintf("only %s reach the private tier over %s (enforced by the firewall); ", strings.Join(allowed, ", "), strings.Join(trusted, ", "))
		if a.FW.VPNFallbackApplied() {
			return dr(docPass, msg+"other VPN devices get the public tier, at the same address"+note, "")
		}
		if a.GOOS == "windows" {
			return dr(docPass, msg+"other VPN devices get the public tier on port 8080 (Windows Firewall cannot redirect)"+note, "")
		}
		return dr(docWarn, msg+"other VPN devices get no answer at the private address, the public tier only on port 8080"+note, "om firewall apply")
	}
	if len(hosts) == 0 {
		return dr(docPass, "no VPN trusted: the private tier is on this machine only"+note, "")
	}
	return dr(docPass, fmt.Sprintf("every device on %s reaches the private tier (%s) — keep joining it to devices you approve, or list yours with `om vpn allow <device>`",
		strings.Join(trusted, ", "), strings.Join(hosts, ", "))+note, "")
}

func (a *App) docNetPolicy(string) docResult {
	pols := a.Reg.NetPolicies()
	keys := make([]string, 0, len(pols))
	for k := range pols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	stale := a.FW.StaleNetRules()
	var missing []string
	for _, k := range keys {
		if !a.FW.NetPolicyEnforced(k, pols[k]) {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return dr(docFail, fmt.Sprintf("om.net rules not in the host firewall for %s (their own ports stay closed)", strings.Join(missing, ", ")), "om firewall apply")
	}
	if len(stale) > 0 {
		return dr(docWarn, fmt.Sprintf("the firewall still restricts %s by old om.net rules", strings.Join(stale, ", ")), "om firewall apply")
	}
	if len(pols) == 0 {
		return dr(docPass, "no service is restricted by address (om.net.allow / om.net.deny)", "")
	}
	return dr(docPass, fmt.Sprintf("%d service(s) restricted by address, enforced by the host firewall: %s", len(pols), strings.Join(keys, ", ")), "")
}

func (a *App) docVPNIsolation(string) docResult {
	var ips []string
	for _, h := range a.vpnHosts() {
		if ipRE.MatchString(h) {
			ips = append(ips, h)
		}
	}
	if len(ips) == 0 {
		return dr(docPass, "no VPN trusted", "")
	}
	code := a.docHTTP("om-doctor.dashboard.localhost", "/healthz", ips[0])
	if code == 0 {
		return dr(docPass, fmt.Sprintf("*.localhost sites answer this machine only (VPN %s with such a Host: refused)", ips[0]), "")
	}
	return dr(docFail, fmt.Sprintf("VPN address %s answers a *.localhost Host (HTTP %d)", ips[0], code), "om core restart (VPN must land on edge :81/:444)")
}

func (a *App) docLANTier(string) docResult {
	lan := a.runtimeEnv()["LAN_IP"]
	if lan == "" || strings.HasSuffix(lan, ".invalid") {
		return dr(docPass, "LAN tier disabled", "")
	}
	code := a.docHTTP(lan, "/api/system", lan)
	slots := a.Reg.ServiceSlots()
	keys := make([]string, 0, len(slots))
	for k := range slots {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var open []string
	for _, k := range keys {
		p := state.PrivatePortBase + slots[k]
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(lan, strconv.Itoa(p)), time.Second); err == nil {
			c.Close()
			open = append(open, fmt.Sprintf("%s (:%d)", k, p))
		}
	}
	switch {
	case len(open) > 0:
		return dr(docFail, "private service ports answer on the LAN address: "+strings.Join(open, ", "), "om core restart (ports.yml binds them to loopback and VPN only)")
	case code == 403:
		return dr(docPass, fmt.Sprintf("LAN tier (%s) is public-scoped (/api/system → 403); private service ports closed there", lan), "")
	case code == 0:
		return dr(docWarn, fmt.Sprintf("LAN tier (%s) not answering", lan), "om core restart (LAN address may have changed)")
	}
	return dr(docFail, fmt.Sprintf("LAN tier returned %d for /api/system (expected 403)", code), "Check the :8080 site in core/caddy/Caddyfile")
}

func (a *App) docLocalhostDNS(string) docResult {
	if addrs, err := net.LookupHost("om-doctor.dashboard.localhost"); err == nil && len(addrs) > 0 {
		return dr(docPass, "*.localhost resolves on this OS", "")
	}
	return dr(docWarn, "*.localhost names don't resolve for CLI tools on this OS (browsers still resolve them)", "Use browsers for <ws>.<svc>.localhost, or add entries to your hosts file.")
}

func (a *App) docFirewall(string) docResult {
	st := a.FW.Status()
	if applied, ok := a.FW.LoggingApplied(); st == "active" && ok && !applied {
		return dr(docWarn, "host firewall active, but applied before logging: refusals and connections are not logged", "om firewall apply")
	}
	switch st {
	case "active":
		return dr(docPass, "host firewall active; refusals and connections logged (`om firewall log`)", "")
	case "unknown":
		return dr(docWarn, "host firewall state unknown on this OS", "om firewall apply")
	}
	return dr(docWarn, "host firewall not active — any port a program opens is reachable from the LAN", "om firewall apply")
}

func (a *App) docBoot(rt string) docResult {
	st := a.Sched.BootStatus(rt)
	if strings.HasPrefix(st, "enabled") && !strings.Contains(st, "only after") {
		return dr(docPass, "containers restart at boot", "")
	}
	if strings.HasPrefix(st, "managed") {
		return dr(docWarn, st, "")
	}
	return dr(docWarn, "start at boot: "+st, "om boot enable")
}

func (a *App) docTokenNotLogged(rt string) docResult {
	tok, _ := settings.EdgeToken(a.D)
	var leaked []string
	for _, c := range []string{state.Edge, state.Router} {
		r := a.Run([]string{rt, "logs", c})
		if strings.Contains(r.Stdout+r.Stderr, tok) {
			leaked = append(leaked, c)
		}
	}
	if len(leaked) > 0 {
		return dr(docFail, fmt.Sprintf("the edge token appears in the logs of %s: treat it as known", strings.Join(leaked, ", ")),
			fmt.Sprintf("rm %s && om core restart   (a new token; the logged one becomes useless)", a.D.TokenFile))
	}
	return dr(docPass, "the edge token appears in no om log", "")
}

func (a *App) docSecretsTracked(string) docResult {
	if migration.LegacyStatePresent(a.D) {
		return dr(docWarn, "machine state still inside "+a.D.Home, "Run any `om` command (e.g. `om status`) to move it out once.")
	}
	if _, err := os.Stat(filepath.Join(a.D.Home, ".git")); err == nil {
		r := a.Run([]string{"git", "-C", a.D.Home, "ls-files", "core/data", "core/.env", "core/.runtime.env", "config"})
		if py.Strip(r.Stdout) != "" {
			return dr(docFail, "old state files are still tracked by git", "git -C ~/.om rm -r --cached core/data core/.env core/.runtime.env config")
		}
	}
	return dr(docPass, fmt.Sprintf("program in %s, state in %s", a.D.Home, a.D.State), "")
}

func (a *App) docSecretModes(string) docResult {
	if a.GOOS == "windows" {
		return dr(docPass, "Windows: secret files follow your profile's permissions", "")
	}
	files := []string{a.D.TokenFile, a.D.RuntimeEnv, a.D.UserEnv, a.Age.KeyFile()}
	for _, sub := range []string{"creds", "overrides"} {
		m, _ := filepath.Glob(filepath.Join(a.D.State, "egress", sub, "*"))
		sort.Strings(m)
		files = append(files, m...)
	}
	var loose, present []string
	for _, p := range files {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		present = append(present, p)
		if st.Mode().Perm()&0o077 != 0 {
			loose = append(loose, fmt.Sprintf("%s (%o)", filepath.Base(p), st.Mode().Perm()))
		}
	}
	if len(loose) > 0 {
		return dr(docWarn, "secret files readable by other users: "+strings.Join(loose, ", "), "chmod 600 "+strings.Join(present, " "))
	}
	return dr(docPass, "edge token, om.env, age key and egress credentials are readable by you only", "")
}

func (a *App) docOrphanRoutes(string) docResult {
	reg := a.Reg.Read()
	orphans := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(a.D.Routes, "*"))
	for _, f := range files {
		t, err := py.ReadText(f)
		if err != nil {
			continue
		}
		if rs := []rune(t); len(rs) > 400 {
			t = string(rs[:400])
		}
		m := migration.GeneratedRouteRE().FindStringSubmatch(t)
		if m == nil || m[1] == "core" {
			continue
		}
		p := ""
		if v, ok := reg[m[1]]["path"]; ok && v != nil {
			p = py.Str(v)
		}
		if st, err := os.Stat(filepath.Join(p, ".om", "config.json")); p == "" || err != nil || !st.Mode().IsRegular() {
			orphans[m[1]] = true
		}
	}
	if len(orphans) > 0 {
		var o []string
		for k := range orphans {
			o = append(o, k)
		}
		sort.Strings(o)
		return dr(docWarn, "routes left by missing workspace(s): "+strings.Join(o, ", "), "om core reload   (prunes them once their containers are stopped)")
	}
	return dr(docPass, "every route belongs to an existing workspace", "")
}

func (a *App) docRegistry(string) docResult {
	reg := a.Reg.Read()
	ids := make([]string, 0, len(reg))
	for w := range reg {
		ids = append(ids, w)
	}
	var missing []string
	for _, w := range ids {
		p := ""
		if v, ok := reg[w]["path"]; ok && v != nil {
			p = py.Str(v)
		}
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return dr(docWarn, "workspace folder(s) missing: "+strings.Join(missing, ", "), "Reconnect the drive, or `om list --prune`.")
	}
	return dr(docPass, fmt.Sprintf("%d workspace(s) registered", len(reg)), "")
}

func (a *App) docPrivateReach(string) docResult {
	t := a.tiers()
	vpn := t["vpn"].(map[string]any)
	trusted := anyStrings(vpn["trusted"])
	allow := anyStrings(vpn["allow_list"])
	login := anyStrings(t["login"])
	if len(trusted) > 0 && len(allow) == 0 && len(login) == 0 {
		return dr(docWarn, fmt.Sprintf("every device on %s reaches your private services (no device allow-list, no login)", strings.Join(trusted, "/")),
			"om vpn allow <a device of yours>, or om auth add <user>")
	}
	parts := []string{"this machine"}
	if len(trusted) > 0 {
		who := "every device"
		if len(allow) > 0 {
			who = strings.Join(allow, ", ")
		}
		s := "VPN: " + who
		if len(login) > 0 {
			s += ", behind a login"
		}
		parts = append(parts, s)
	}
	return dr(docPass, "private tier reached by "+strings.Join(parts, "; ")+" (om exposure shows each service)", "")
}

func (a *App) docAuth(string) docResult {
	if m, _ := filepath.Glob(filepath.Join(a.D.Auth, "*.conf")); len(m) > 0 {
		return dr(docPass, "private tier requires login", "")
	}
	trusted := a.trustedUsers()
	var others []string
	for _, u := range a.otherLoginUsers() {
		if !trusted[u] {
			others = append(others, u)
		}
	}
	if len(others) > 0 {
		return dr(docFail, fmt.Sprintf("private tier has no login and other people can log in here (%s): they can use your services", strings.Join(others, ", ")),
			"om auth add <user>  (or, if they are yours: OM_TRUSTED_USERS=<user> in om.env)")
	}
	return dr(docPass, "no login on the private tier: only you use this machine; your VPN decides who else reaches it", "")
}

// streamHostPorts lists the host ports in a `podman ps` Ports column ("0.0.0.0:22000-22199->..., ...").
func streamHostPorts(col string) []int {
	var out []int
	for _, part := range strings.Split(col, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "->") {
			continue
		}
		side := part[:strings.Index(part, "->")]
		side = side[strings.LastIndex(side, ":")+1:]
		if lo, hi, ok := strings.Cut(side, "-"); ok {
			if state.IsNumber(lo) && state.IsNumber(hi) {
				l, _ := strconv.Atoi(lo)
				h, _ := strconv.Atoi(hi)
				for p := l; p <= h; p++ {
					out = append(out, p)
				}
			}
		} else if state.IsNumber(side) {
			p, _ := strconv.Atoi(side)
			out = append(out, p)
		}
	}
	return out
}

func (a *App) docStreamPublished(rt string) docResult {
	declared := map[int]bool{}
	for i := 0; i < state.StreamPortSlots; i++ {
		declared[state.StreamPortBase+i] = true
	}
	for _, e := range a.Reg.StreamPorts() {
		if e.HostPort != 0 {
			declared[e.HostPort] = true
		}
	}
	r := a.Run([]string{rt, "ps", "--format", "{{.Names}}\t{{.Ports}}"})
	lines := py.SplitLines(r.Stdout)
	edgeCol := ""
	for _, line := range lines {
		name, ports, _ := strings.Cut(line, "\t")
		if name == state.StreamEdge {
			edgeCol = ports
			break
		}
	}
	pub := map[int]bool{}
	for _, p := range streamHostPorts(edgeCol) {
		pub[p] = true
	}
	var undeclared []int
	for p := range pub {
		if !declared[p] {
			undeclared = append(undeclared, p)
		}
	}
	sort.Ints(undeclared)
	if len(undeclared) > 0 {
		return dr(docFail, fmt.Sprintf("undeclared port(s) published on %s: %s", state.StreamEdge, joinInts(undeclared, ", ")), "om core restart (ports.yml binds only declared stream ports)")
	}
	var leaks []string
	for _, line := range lines {
		name, ports, _ := strings.Cut(line, "\t")
		if name == state.Edge || name == state.StreamEdge {
			continue
		}
		for _, part := range strings.Split(ports, ",") {
			if !strings.Contains(part, "->") {
				continue
			}
			side := part[:strings.Index(part, "->")]
			side = side[strings.LastIndex(side, ":")+1:]
			if state.IsNumber(side) {
				if p, _ := strconv.Atoi(side); p != 0 && declared[p] {
					leaks = append(leaks, fmt.Sprintf("%s (:%d)", name, p))
				}
			}
		}
	}
	if len(leaks) > 0 {
		return dr(docFail, "containers publish stream ports, bypassing stream proxy: "+strings.Join(leaks, "; "), "om core restart (ports.yml binds only declared stream ports)")
	}
	return dr(docPass, "only declared stream ports are bound/published", "")
}

func (a *App) docStreamFirewall(string) docResult {
	if a.FW.Status() != "active" {
		return dr(docWarn, "host firewall is not active (`om firewall apply` to enforce perimeter)", "om firewall apply")
	}
	priv, pub := a.FW.StreamFirewallPorts()
	var missing []string
	switch a.GOOS {
	case "linux":
		text, _ := py.ReadText(a.FW.NftInstalled)
		if text == "" {
			return dr(docFail, "applied host firewall (/etc/om-firewall.nft) is empty or missing", "om firewall apply")
		}
		for _, p := range pub {
			re := regexp.MustCompile(`tcp\s+dport\s+\{?[^}]*\b` + regexp.QuoteMeta(p) + `\b[^}]*\}?\s+accept`)
			if !re.MatchString(text) {
				missing = append(missing, p)
			}
		}
		if ips := a.FW.VPNIPs(); len(ips) > 0 && len(priv) > 0 {
			for _, p := range priv {
				re := regexp.MustCompile(`ip\s+daddr\s+\{?[^}]*\}\s+tcp\s+dport\s+\{?[^}]*\b` + regexp.QuoteMeta(p) + `\b[^}]*\}?\s+accept`)
				if !re.MatchString(text) {
					missing = append(missing, p)
				}
			}
		}
	case "darwin":
		text, _ := py.ReadText(a.FW.PfInstalled)
		if text == "" {
			return dr(docFail, "applied host firewall (/etc/pf.anchors/om) is empty or missing", "om firewall apply")
		}
		for _, p := range pub {
			if !strings.Contains(text, "port { "+p+" }") && !strings.Contains(text, "port "+p) {
				missing = append(missing, p)
			}
		}
	case "windows":
		r := a.Run([]string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetFirewallRule -Group om -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"})
		found := false
		if r.Code == 0 {
			for _, n := range py.SplitLines(r.Stdout) {
				if strings.Contains(n, "om public stream ports") {
					found = true
				}
			}
		}
		if len(pub) > 0 && !found {
			return dr(docFail, "firewall rule missing for public stream ports", "om firewall apply")
		}
	}
	if len(missing) > 0 {
		seen := map[string]bool{}
		var u []string
		for _, p := range missing {
			if !seen[p] {
				seen[p] = true
				u = append(u, p)
			}
		}
		sort.Strings(u)
		return dr(docFail, "firewall rule missing for stream port(s): "+strings.Join(u, ", "), "om firewall apply")
	}
	return dr(docPass, "a firewall rule exists for each stream port", "")
}

func (a *App) docStreamIsolation(rt string) docResult {
	stPorts := a.Reg.StreamPorts()
	reg := a.Reg.Read()
	ids := make([]string, 0, len(reg))
	for w := range reg {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	skeys := make([]string, 0, len(stPorts))
	for k := range stPorts {
		skeys = append(skeys, k)
	}
	checked := 0
	for _, wid := range ids {
		netName := wid + "_net"
		if a.Run([]string{rt, "network", "inspect", netName}).Code != 0 {
			continue
		}
		var others []string
		for _, k := range skeys {
			ows, osvc, _ := strings.Cut(k, "/")
			if ows != wid {
				cp := stPorts[k].ContainerPort
				if cp == 0 {
					cp = 25565
				}
				others = append(others, fmt.Sprintf("%s_%s:%d", ows, osvc, cp))
			}
		}
		args := []string{state.StreamEdge + ":22000", state.StreamRouter + ":1"}
		if len(others) > 0 {
			args = append(args, others[0])
		}
		cmd := []string{rt, "run", "--rm", "--network", netName, "--read-only", "--cap-drop", "ALL", "-v", a.probeMount(), a.probeImage(), probeBin, "probe", "stream"}
		st := strings.Fields(a.Run(append(cmd, args...)).Stdout)
		if len(st) == 0 {
			continue
		}
		checked++
		get := func(i int, def string) string {
			if i < len(st) {
				return st[i]
			}
			return def
		}
		const fix = "Ensure om_stream_edge is only on om_core_net and om_stream_router has no network listener"
		if get(0, "error") == "open" {
			return dr(docFail, fmt.Sprintf("from %s: %s is directly reachable over network", netName, state.StreamEdge), fix)
		}
		if get(1, "error") == "open" {
			return dr(docFail, fmt.Sprintf("from %s: %s has an open network port", netName, state.StreamRouter), fix)
		}
		if get(2, "unreachable") == "open" {
			return dr(docFail, fmt.Sprintf("from %s: cross-workspace stream target %s is reachable", netName, args[2]), fix)
		}
	}
	if checked == 0 {
		return dr(docPass, "no workspace networks available to probe stream isolation", "")
	}
	return dr(docPass, fmt.Sprintf("stream router and edge are isolated from workspace containers (%d network(s) probed)", checked), "")
}

func (a *App) docBasic() []docCheck {
	return []docCheck{
		{"Engine", a.docEngine}, {"Compose", a.docCompose}, {"Ports", a.docPorts}, {"Core", a.docCore},
	}
}

func (a *App) docPerimeter() []docCheck {
	return []docCheck{
		{"Router", a.docRouterNetworks}, {"Edge isolation", a.docEdgeIsolated},
		{"Published ports", a.docPublishedPorts}, {"Address drift", a.docDrift},
		{"Private tier", a.docPrivateReachable}, {"DNS rebinding", a.docRebinding},
		{"Router token", a.docRouterToken}, {"Token not logged", a.docTokenNotLogged},
		{"Engine filter", a.docEngineFilter}, {"Admin surface", a.docAdminSurface},
		{"Running = lock", a.docWorkspacesFsck}, {"Egress", a.docEgress},
		{"Project isolation", a.docProjectIsolation}, {"Generations", a.docGenerations},
		{"LAN tier", a.docLANTier}, {"VPN", a.docVPN}, {"VPN isolation", a.docVPNIsolation},
		{"Address rules", a.docNetPolicy}, {"Links", a.docLinks}, {"Custom routes", a.docCustomRoutes},
		{"Healthchecks", a.docHealthchecks}, {"Stream ports", a.docStreamPublished},
		{"Stream firewall", a.docStreamFirewall}, {"Stream isolation", a.docStreamIsolation},
	}
}

func (a *App) docHost() []docCheck {
	return []docCheck{
		{".localhost DNS", a.docLocalhostDNS}, {"Firewall", a.docFirewall}, {"Boot", a.docBoot},
		{"Login", a.docAuth}, {"Private reach", a.docPrivateReach}, {"Secret files", a.docSecretModes}, {"State", a.docSecretsTracked},
		{"Registry", a.docRegistry}, {"Orphan routes", a.docOrphanRoutes},
	}
}

type docRow struct {
	title string
	docResult
}

func runDocChecks(cs []docCheck, rt string) []docRow {
	out := make([]docRow, 0, len(cs))
	for _, c := range cs {
		out = append(out, docRow{c.title, c.fn(rt)})
	}
	return out
}

// cmdDoctor verifies the installation and the perimeter and prints a fix for every problem.
func (a *App) cmdDoctor(ns Namespace) error {
	rt := a.Runtime()
	var rows []docRow
	basic := runDocChecks(a.docBasic(), rt)
	rows = append(rows, basic...)
	// the core runs on a working engine
	if basic[len(basic)-1].status == docPass && basic[0].status == docPass {
		rows = append(rows, runDocChecks(a.docPerimeter(), rt)...)
	}
	rows = append(rows, runDocChecks(a.docHost(), rt)...)
	fails, warns := 0, 0
	for _, r := range rows {
		switch r.status {
		case docFail:
			fails++
		case docWarn:
			warns++
		}
	}
	code := 0
	if fails > 0 {
		code = 1
	}
	if ns.Bool("json") {
		checks := []any{}
		for _, r := range rows {
			o := py.NewObject()
			o.Set("check", r.title)
			o.Set("status", r.status)
			o.Set("detail", r.msg)
			o.Set("fix", r.fix)
			checks = append(checks, o)
		}
		o := py.NewObject()
		o.Set("version", a.Version)
		o.Set("runtime", rt)
		o.Set("failures", fails)
		o.Set("warnings", warns)
		o.Set("checks", checks)
		io.WriteString(a.Out, py.Dumps(o)+"\n")
		if code != 0 {
			return Exit(code)
		}
		return nil
	}
	colors := map[string]string{docPass: "\033[32m", docWarn: "\033[33m", docFail: "\033[31m"}
	a.p("\n\033[1mom doctor\033[0m  (om %s, %s)", a.Version, rt)
	a.p("%s", strings.Repeat("═", 78))
	for _, r := range rows {
		a.p("  %s%s\033[0m  %s %s", colors[r.status], r.status, ljust(r.title, 16), r.msg)
		if r.fix != "" && r.status != docPass {
			a.p("        ↳ %s", r.fix)
		}
	}
	a.p("%s", strings.Repeat("─", 78))
	a.p("  %d failure(s), %d warning(s)\n", fails, warns)
	if code != 0 {
		return Exit(code)
	}
	return nil
}

// probeBin is the om binary inside the probe containers (see Core.installDashboardBinary).
const probeBin = "/om/" + core.DashboardBinName

// probeMount mounts the directory holding that binary, read-only.
func (a *App) probeMount() string { return filepath.Join(a.D.State, "bin") + ":/om:ro,z" }
