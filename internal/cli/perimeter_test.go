package cli

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/routes"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

// The perimeter is built by several generators (Caddy routes, the port registries, the edge's published ports, the
// host firewall, om exposure). A bug in one that the others do not notice quietly weakens the whole. This test builds
// random workspaces (seeded) with random labels, runs the real route sync, renders everything, and checks what must
// hold across the outputs, whatever the labels were:
//
//  1. a service whose address rules the firewall does not carry has no port of its own and no redirects
//  2. a service whose labels or `om.caddy` are refused has no route at all
//  3. own ports are unique, inside their ranges, and each belongs to a registered slot
//  4. an address policy only names ports of its own service
//  5. a stream port with an address rule is published only when that rule is in the firewall
//  6. the firewall has a drop rule for every port of every enforced address rule, and opens the public range only
//  7. om exposure lists every routed service, and flags the rules that are not in the firewall

var (
	pcNames      = []string{"web", "api", "db", "x-1", "a-b", "cache", "docs", "app"}
	pcGood       = "header X-Frame-Options DENY\nhandle /health {\n    respond \"ok\" 200\n}\n"
	pcBad        = []string{"reverse_proxy evil:80\n", "respond \"\n# {$OM_EDGE_TOKEN}\"\n", "import /etc/caddy/*\n", "@m remote_ip 1.2.3.4\nrespond @m x\n"}
	pcNetAllow   = []string{"", "", "100.64.0.9", "100.64.0.0/24, 192.168.1.0/24", "vpn", "garbage", "127.0.0.1/32", "10.0.0.0/8,notanip"}
	pcNetDeny    = []string{"", "", "", "100.64.0.66", "bad", "fe80::/10"}
	pcTCP        = [][2]string{{}, {}, {}, {"25565", ""}, {"25565", "25570"}, {"80", "443"}, {"25565", "22005"}, {"²", ""}, {"25565", "99999"}}
	pcOwnPortRE  = regexp.MustCompile(`(?m)^http://:(\d+) \{`)
	pcPrivate    = func(p int) bool { return p >= state.PrivatePortBase && p < state.PrivatePortBase+state.PortSlots }
	pcPublic     = func(p int) bool { return p >= state.PublicPortBase && p < state.PublicPortBase+state.PortSlots }
	pcNameOfFile = func(ws, f string) string { return strings.SplitN(f[len(ws)+1:], ".", 2)[0] }
)

type pcService struct {
	labels     []string
	snippet    string
	badSnippet bool
}

func pcWorkspace(r *rand.Rand, tmp, ws string) (string, map[string]pcService) {
	root := filepath.Join(tmp, ws)
	os.MkdirAll(filepath.Join(root, ".om"), 0o755)
	os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(fmt.Sprintf(`{"workspace_id": %q}`, ws)), 0o644)
	spec := map[string]pcService{}
	names := append([]string(nil), pcNames...)
	r.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	for _, name := range names[:2+r.IntN(4)] {
		labels := []string{fmt.Sprintf("dashboard.port=%d", []int{80, 8080, 3000}[r.IntN(3)])}
		if r.Float64() < 0.5 {
			labels = append(labels, "dashboard.scope="+[]string{"public", "private"}[r.IntN(2)])
		}
		if v := pcNetAllow[r.IntN(len(pcNetAllow))]; v != "" {
			labels = append(labels, "om.net.allow="+v)
		}
		if v := pcNetDeny[r.IntN(len(pcNetDeny))]; v != "" {
			labels = append(labels, "om.net.deny="+v)
		}
		if r.Float64() < 0.25 {
			labels = append(labels, "om.log=off")
		}
		if tcp := pcTCP[r.IntN(len(pcTCP))]; tcp[0] != "" {
			labels = append(labels, "om.tcp="+tcp[0])
			if tcp[1] != "" {
				labels = append(labels, "om.tcp.port="+tcp[1])
			}
		}
		snippet := []string{"", "", pcGood, pcBad[r.IntN(len(pcBad))]}[r.IntN(4)]
		d := filepath.Join(root, "services", name)
		os.MkdirAll(d, 0o755)
		var body strings.Builder
		for _, l := range labels {
			body.WriteString(fmt.Sprintf("      - %q\n", l))
		}
		os.WriteFile(filepath.Join(d, "compose.yml"), []byte(fmt.Sprintf("services:\n  %s:\n    image: x\n    labels:\n%s", name, body.String())), 0o644)
		if snippet != "" {
			os.WriteFile(filepath.Join(d, "om.caddy"), []byte(snippet), 0o644)
		}
		bad := false
		for _, b := range pcBad {
			bad = bad || snippet == b
		}
		spec[name] = pcService{labels, snippet, bad}
	}
	return root, spec
}

func ownPorts(text string) []int {
	var out []int
	for _, m := range pcOwnPortRE.FindAllStringSubmatch(text, -1) {
		n, _ := strconv.Atoi(m[1])
		out = append(out, n)
	}
	return out
}

func perimeterSeed(t *testing.T, seed uint64) (int, int) {
	r := rand.New(rand.NewPCG(seed, 99))
	a := sandboxApp(t)
	ws := fmt.Sprintf("pc%d", seed)
	root, spec := pcWorkspace(r, t.TempDir(), ws)
	if err := a.Reg.Update(func(w registry.Workspaces) error { w[ws] = map[string]any{"id": ws, "path": root}; return nil }); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(a.D.Routes, 0o755)
	vpnAllow := []string{"100.64.0.9/32", "100.64.0.20/32"}
	enforced := map[string]bool{}
	a.Syncer.NetPolicyEnforced = func(key string, _ map[string]any) bool {
		v, ok := enforced[key]
		if !ok {
			v = r.Float64() < 0.6
			enforced[key] = v
		}
		return v
	}
	a.Syncer.VPNAllow = func() []string { return vpnAllow }
	a.FW.VPNAllow = func() []string { return vpnAllow }
	a.FW.VPNIPs = func() []string { return []string{"100.64.0.1"} }
	if _, err := a.Syncer.SyncCaddyRoutes(root, "none", false, nil); err != nil {
		t.Fatalf("seed %d: %v", seed, err)
	}

	files := map[string]string{}
	entries, _ := os.ReadDir(a.D.Routes)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ws+"-") {
			b, _ := os.ReadFile(filepath.Join(a.D.Routes, e.Name()))
			files[e.Name()] = string(b)
		}
	}
	forWS := func(prefix string) map[string]int {
		out := map[string]int{}
		for k, v := range a.Reg.ServiceSlots() {
			if rest, ok := strings.CutPrefix(k, prefix); ok {
				out[rest] = v
			}
		}
		return out
	}
	slots := forWS(ws + "/")
	policies := map[string]map[string]any{}
	for k, v := range a.Reg.NetPolicies() {
		if rest, ok := strings.CutPrefix(k, ws+"/"); ok {
			policies[rest] = v
		}
	}
	streams := map[string]registry.StreamEntry{}
	for k, v := range a.Reg.StreamPorts() {
		if rest, ok := strings.CutPrefix(k, ws+"/"); ok {
			streams[rest] = v
		}
	}
	ctx := fmt.Sprintf("workspace %s, services %v", ws, sortedKeys(spec))

	// 2. refused labels or snippets: no route at all, web or TCP, and no port slot
	for name, s := range spec {
		labels := map[string]string{}
		for _, l := range s.labels {
			k, v, _ := strings.Cut(l, "=")
			labels[k] = v
		}
		_, problems := routes.ParseNetPolicy(labels, vpnAllow)
		if s.badSnippet || len(problems) > 0 {
			for f := range files {
				if strings.HasPrefix(f, ws+"-"+name+".") {
					t.Errorf("%s has a refused om.caddy or unreadable address rules but a route %s; %s", name, f, ctx)
				}
			}
			if _, ok := streams[name]; ok {
				t.Errorf("%s is refused but its TCP port is published; %s", name, ctx)
			}
			if _, ok := slots[name]; ok {
				t.Errorf("%s is refused but has a port slot; %s", name, ctx)
			}
		}
	}
	// 1. address rules the firewall does not carry: no own port, no redirects
	for name := range policies {
		if enforced[ws+"/"+name] {
			continue
		}
		if text, ok := files[ws+"-"+name+".caddy"]; ok {
			if p := ownPorts(text); len(p) > 0 {
				t.Errorf("%s: rules not in the firewall but its own port is open (%v); %s", name, p, ctx)
			}
			if _, ok := files[ws+"-"+name+".private_alias"]; ok {
				t.Errorf("%s: redirect to a closed port; %s", name, ctx)
			}
		}
	}
	// 3. own ports: unique, in range, each a registered slot's port
	seen := map[int]string{}
	for fname, text := range files {
		for _, port := range ownPorts(text) {
			if !pcPrivate(port) && !pcPublic(port) {
				t.Errorf("%s: port %d outside the ranges; %s", fname, port, ctx)
			}
			slot, ok := slots[pcNameOfFile(ws, fname)]
			if !ok {
				t.Errorf("%s: own port without a slot; %s", fname, ctx)
				continue
			}
			if port != state.PrivatePortBase+slot && port != state.PublicPortBase+slot {
				t.Errorf("%s: port %d is not its slot's; %s", fname, port, ctx)
			}
			if prev, dup := seen[port]; dup {
				t.Errorf("port %d used by %s and %s; %s", port, prev, fname, ctx)
			}
			seen[port] = fname
		}
	}
	uniq := map[int]bool{}
	for _, s := range slots {
		uniq[s] = true
	}
	if len(uniq) != len(slots) {
		t.Errorf("two services share a slot; %s", ctx)
	}
	// 4. address policies name only their own service's ports
	for name, pol := range policies {
		allowed := map[int]bool{}
		if s, ok := slots[name]; ok {
			allowed[state.PrivatePortBase+s], allowed[state.PublicPortBase+s] = true, true
		}
		if st, ok := streams[name]; ok {
			allowed[st.HostPort] = true
		}
		ports, _ := pol["ports"].([]any)
		for _, p := range ports {
			n, _ := strconv.Atoi(fmt.Sprint(p))
			if !allowed[n] {
				t.Errorf("%s: policy names port %d, not one of its own; %s", name, n, ctx)
			}
		}
	}

	// Make the firewall real: the installed ruleset carries the drops of the policies that are enforced.
	var installed strings.Builder
	for _, key := range sortedKeys(a.Reg.NetPolicies()) {
		if enforced[key] {
			for _, fwd := range []bool{false, true} {
				for _, ln := range a.FW.NftNetRules(key, a.Reg.NetPolicies()[key], fwd) {
					installed.WriteString(ln + "\n")
				}
			}
		}
	}
	a.FW.ReadFile = func(p string) (string, error) { return installed.String(), nil }
	a.FW.Run = func(c []string) state.Result {
		if strings.Join(c, " ") == "systemctl is-active om-firewall" {
			return state.Result{Stdout: "active\n"}
		}
		return state.Result{Code: 1}
	}
	a.FW.OS = "linux"

	// 5. a stream port with an address rule is published only when the rule is in the firewall
	resolved := settings.Resolved{HTTPPort: 80, HTTPSPort: 443, VPNIPs: []string{"100.64.0.1"}, LANIP: "192.168.1.5", VPNPrivate: true}
	hooks := settings.Hooks{IsLocal: func(string) bool { return false },
		StreamPorts: func() map[string]settings.StreamPort {
			out := map[string]settings.StreamPort{}
			for k, v := range a.Reg.StreamPorts() {
				out[k] = settings.StreamPort{HostPort: v.HostPort, Scope: v.Scope}
			}
			return out
		},
		NetPolicies:       a.Reg.NetPolicies,
		NetPolicyEnforced: func(key string, pol map[string]any) bool { return a.FW.NetPolicyEnforced(key, pol) }}
	rendered := settings.RenderPorts(a.D, resolved, hooks)
	published := rendered
	if i := strings.Index(rendered, "stream_edge:"); i >= 0 {
		published = rendered[i:]
	}
	for name, info := range streams {
		inDefault := info.HostPort >= state.StreamPortBase && info.HostPort < state.StreamPortBase+state.StreamPortSlots
		if _, hasPolicy := policies[name]; hasPolicy && !inDefault && !enforced[ws+"/"+name] {
			if strings.Contains(published, fmt.Sprintf(":%d:%d", info.HostPort, info.HostPort)) {
				t.Errorf("%s: stream port %d published without its address rule in the firewall; %s", name, info.HostPort, ctx)
			}
		}
	}
	// 6. the firewall drops for every enforced rule's ports, and opens only the public range to everyone
	nft := a.FW.RenderNft(nil, nil)
	for name, pol := range policies {
		if !enforced[ws+"/"+name] {
			continue
		}
		text := strings.Join(a.FW.NftNetRules(ws+"/"+name, pol, false), "\n")
		ports, _ := pol["ports"].([]any)
		for _, p := range ports {
			if !regexp.MustCompile(`dport \{[^}]*\b` + fmt.Sprint(p) + `\b[^}]*\} .*drop`).MatchString(text) {
				t.Errorf("%s: no drop rule for port %v; %s", name, p, ctx)
			}
		}
	}
	if want := fmt.Sprintf("tcp dport %d-%d accept", state.PublicPortBase, state.PublicPortBase+state.PortSlots-1); !strings.Contains(nft, want) {
		t.Errorf("the public range is not opened: want %q", want)
	}
	for _, line := range strings.Split(nft, "\n") {
		if strings.Contains(line, fmt.Sprintf("%d-", state.PrivatePortBase)) && strings.Contains(line, "accept") && !strings.Contains(line, "ip daddr") {
			t.Errorf("the private range is open to everyone: %s", strings.TrimSpace(line))
		}
	}
	// 7. om exposure lists every routed service and flags rules that are not in the firewall
	data := a.exposureData()
	listed := map[string][]string{}
	for _, x := range data["services"].([]any) {
		s := x.(map[string]any)
		if s["workspace"] == ws {
			listed[fmt.Sprint(s["service"])] = anyStrings(s["reachable_by"])
		}
	}
	routed := map[string]bool{}
	for f := range files {
		if strings.HasSuffix(f, ".caddy") {
			routed[pcNameOfFile(ws, f)] = true
		}
	}
	for n := range streams {
		routed[n] = true
	}
	var missing []string
	for n := range routed {
		if _, ok := listed[n]; !ok {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("exposure misses %v; %s", missing, ctx)
	}
	for name, lines := range listed {
		if _, ok := policies[name]; !ok || enforced[ws+"/"+name] {
			continue
		}
		flagged := false
		for _, l := range lines {
			flagged = flagged || strings.Contains(l, "NOT in the host firewall")
		}
		if !flagged {
			t.Errorf("%s: unenforced rule not flagged; %s", name, ctx)
		}
	}
	nStreams := 0
	for _, s := range spec {
		for _, l := range s.labels {
			if strings.HasPrefix(l, "om.tcp=") {
				nStreams++
				break
			}
		}
	}
	return len(enforced), nStreams
}

func TestRandomWorkspacesKeepEveryGeneratorInAgreement(t *testing.T) {
	rules, streams := 0, 0
	for seed := uint64(0); seed < 60; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r, s := perimeterSeed(t, seed)
			rules += r
			streams += s
		})
	}
	if rules <= 20 || streams <= 10 {
		t.Errorf("the random workspaces tried %d address rules and %d stream ports: too few for the checks above to mean anything", rules, streams)
	}
}
