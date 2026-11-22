package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/gitsync"
	"github.com/Chitakasa/om/internal/labels"
	"github.com/Chitakasa/om/internal/links"
	"github.com/Chitakasa/om/internal/lock"
	"github.com/Chitakasa/om/internal/network"
	"github.com/Chitakasa/om/internal/policy"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/workspace"
)

type composeResult struct {
	cfg map[string]any
	err string
}

func (a *App) composeConfig(rt, file string, env []string) composeResult {
	cfg, msg := policy.ComposeConfig(a.RunIn, rt, file, env)
	return composeResult{cfg, msg}
}

func (a *App) wsID(root string) (string, error) {
	id, err := workspace.WorkspaceID(root)
	if err != nil {
		return "", Die("%s", err)
	}
	return id, nil
}

func (a *App) trustFirstSigners(wsID string, signers []signerFP, kind string) bool {
	a.p("  \033[1mFirst deploy of %s: these keys will be trusted to sign it from now on\033[0m", wsID)
	for _, s := range signers {
		a.p("    %s  %s", s.principal, s.fingerprint)
	}
	if a.Gen.Mode(a.Settings()) != "enforce" || kind == "dev" {
		return true
	}
	if a.Confirm(fmt.Sprintf("Trust these %d signer(s) for %s?", len(signers), wsID)) {
		return true
	}
	a.p("  \033[31m✗ Not deployed: the signers were not confirmed (OM_SIGNED=enforce). Run `om start` in a terminal to confirm them.\033[0m")
	return false
}

type signerFP struct{ principal, fingerprint string }

// checkSignature returns (may deploy, signer, dirty). A dirty tree runs as a dev generation (unsigned, marked dirty);
// a clean HEAD must be signed by a trusted key, or OM_SIGNED=enforce refuses it.
func (a *App) checkSignature(root, wsID, kind string) (bool, string, bool) {
	snap := a.Gen.Snapshot(root)
	if snap["commit"] == nil {
		a.p("  \033[33m⚠ not a git repository: this deploy cannot be signed or rolled back (git init).\033[0m")
		return true, "", true
	}
	if snap["dirty"] == true {
		a.p("  \033[33m⚠ uncommitted changes: running the working tree unsigned, generation marked dirty.\033[0m")
		return true, "", true
	}
	commit := snap["commit"].(string)
	var first []signerFP
	for _, f := range a.Gen.IsFirstUse(wsID, root) {
		first = append(first, signerFP{f.Principal, f.Fingerprint})
	}
	trusted, who := a.Gen.Verify(wsID, root, "HEAD")
	if trusted && len(first) > 0 && !a.trustFirstSigners(wsID, first, kind) {
		return false, "", false
	}
	short := commit
	if len(short) > 8 {
		short = short[:8]
	}
	if trusted {
		a.p("  \033[32m✓ commit %s signed by %s\033[0m", short, who)
		return true, strings.SplitN(who, " (", 2)[0], false
	}
	if a.Gen.Mode(a.Settings()) == "enforce" && kind != "dev" {
		a.p("  \033[31m✗ commit %s: %s. Not deployed (OM_SIGNED=enforce).\033[0m", short, who)
		return false, "", false
	}
	a.p("  \033[33m⚠ commit %s: %s (OM_SIGNED=warn: deploying anyway).\033[0m", short, who)
	return true, "", false
}

type isolation struct {
	overrides   map[string]string
	failed      map[string]bool
	needsEgress map[string]bool
	subnets     map[string]string
}

// isolateProjects puts each folder on its own internal network; the router and om_egress join them before anything
// starts.
func (a *App) isolateProjects(rt, wsID, root string, targets []workspace.Project, configs map[string]composeResult) isolation {
	iso := isolation{map[string]string{}, map[string]bool{}, map[string]bool{}, map[string]string{}}
	for _, t := range targets {
		d := t.Dir
		net, path, err := a.Net.ProjectNetwork(rt, wsID, workspace.ProjectRel(root, d), d, configs[d].cfg)
		if err != nil {
			iso.failed[d] = true
			a.p("    \033[31m✗ %s: %s — not started (it would share the workspace network)\033[0m", filepath.Base(d), err)
			continue
		}
		iso.overrides[d] = path
		if net != "" {
			iso.subnets[d] = a.Eng.NetworkSubnet(rt, net)
		}
		if len(policy.EgressServices(configs[d].cfg)) > 0 {
			n := net
			if n == "" {
				n = wsID + "_net"
			}
			iso.needsEgress[n] = true
		}
	}
	return iso
}

// renderEgress writes the proxy rules of every service with om.egress.
func (a *App) renderEgress(rt, wsID string, targets []workspace.Project, configs map[string]composeResult, subnets map[string]string, target string) (map[string]egress.Rule, map[string]string, error) {
	wanted, svcSubnets := map[string]egress.Rule{}, map[string]string{}
	for _, t := range targets {
		cfg := configs[t.Dir].cfg
		if len(cfg) > 0 {
			svcs := policy.EgressServices(cfg)
			for s, r := range svcs {
				wanted[s] = r
				svcSubnets[s] = subnets[t.Dir]
			}
		}
	}
	urls, err := a.Egress.RenderWorkspace(rt, wsID, wanted, target == "", svcSubnets)
	return wanted, urls, err
}

// attachNetworks puts om_egress only on networks with a service that may go out (elsewhere it is not even
// reachable), the router on all of them; networks of folders that are gone are removed on a full start.
func (a *App) attachNetworks(rt, wsID, root string, targets []workspace.Project, configs map[string]composeResult, target string, needs map[string]bool) {
	known, ok := a.Reg.EgressNetworks(wsID)
	set := needs
	if target != "" && ok {
		set = setOf(known)
		for n := range needs {
			set[n] = true
		}
	}
	a.Reg.SetEgressNetworks(wsID, sortedSet(set))
	for _, net := range a.Eng.ConnectRouter(rt, []string{wsID}) {
		a.p("    \033[33m⚠ could not attach the router/egress to %s: its routes return 502\033[0m", net)
	}
	if target == "" {
		keep := map[string]bool{}
		for _, t := range targets {
			cfg := configs[t.Dir].cfg
			if !(len(cfg) > 0 && network.SharesWorkspaceNetwork(cfg)) {
				keep[network.ProjectNetworkName(wsID, workspace.ProjectRel(root, t.Dir))] = true
			}
		}
		for _, net := range a.Net.PruneProjectNetworks(rt, wsID, keep) {
			a.p("  \033[36m- Removed network %s (its folder is gone)\033[0m", net)
		}
	}
}

func (a *App) announceOpenEgress(wanted map[string]egress.Rule) {
	var learning, auditing []string
	for _, s := range sortedKeys(wanted) {
		switch wanted[s].Mode {
		case egress.Learn:
			learning = append(learning, s)
		case egress.Audit:
			auditing = append(auditing, s)
		}
	}
	if len(learning) > 0 {
		a.p("  \033[33m⚠ learning (any public host allowed, recorded): %s — `om egress log`, then list the hosts\033[0m", strings.Join(learning, ", "))
	}
	if len(auditing) > 0 {
		a.p("  \033[36mℹ audit mode (all public egress logged permanently): %s — see `om egress log`\033[0m", strings.Join(auditing, ", "))
	}
}

// policyAllows runs the deploy gate on one compose file and says what it found. False: refused (OM_POLICY=enforce).
func (a *App) policyAllows(wsID, composeFile string, c composeResult) bool {
	cfg := c.cfg
	if len(cfg) > 0 && network.SharesWorkspaceNetwork(cfg) {
		joins := false
		nets, _ := cfg["networks"].(map[string]any)
		for _, v := range nets {
			if n, _ := v.(map[string]any); n != nil && n["name"] == wsID+"_net" {
				joins = true
			}
		}
		if !joins {
			a.p("    \033[33m⚠ %s has om.network=shared but doesn't join %s_net: its routes return 502.\033[0m\n      Add: networks: {default: {name: ${WORKSPACE_NET}, external: true}}", filepath.Base(composeFile), wsID)
		}
	}
	violations, waived := policy.EvaluateCompose(cfg, c.err, wsID+"_net")
	if len(waived) > 0 {
		a.p("    \033[36mℹ policy: %d exception(s) allowed by %s (see `om policy check`)\033[0m", len(waived), policy.AllowLabel)
	}
	if len(violations) == 0 {
		return true
	}
	enforce := policy.Mode(a.Settings()) == "enforce"
	mark := "33m⚠"
	if enforce {
		mark = "31m✗"
	}
	a.p("    \033[%s policy: %d violation(s) in %s\033[0m", mark, len(violations), filepath.Base(composeFile))
	for _, v := range violations {
		a.p("      - %s", v)
	}
	if enforce {
		a.p("      Not started (OM_POLICY=enforce). Fix the lines above; `om policy check` re-checks.")
		return false
	}
	a.p("      Started anyway (OM_POLICY=warn); this will be refused once OM_POLICY=enforce.")
	return true
}

// nologOverride writes the compose override discarding the own output (stdout/stderr) of services labelled
// om.log=off, or returns "": no trace in the engine's log either (a search engine logs failed upstream URLs, query
// included).
func (a *App) nologOverride(ws, projectDir string, cfg map[string]any) (string, error) {
	var quiet []string
	services, _ := cfg["services"].(map[string]any)
	for _, name := range sortedKeys(services) {
		svc, _ := services[name].(map[string]any)
		if strings.ToLower(py.Strip(py.Str(orEmptyAny(labels.Service(svc), "om.log")))) == "off" {
			quiet = append(quiet, name)
		}
	}
	sum := sha256.Sum256([]byte(projectDir))
	path := filepath.Join(a.D.State, "nolog", "overrides", ws+"-"+hex.EncodeToString(sum[:])[:12]+".yml")
	if len(quiet) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "", nil
	}
	lines := []string{"# Generated by om — om.log=off: the engine keeps none of these services' output. Do not edit.", "services:"}
	for _, n := range quiet {
		lines = append(lines, "  "+py.JSONString(n)+":", "    logging:", `      driver: "none"`)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func orEmptyAny(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return ""
}

// startProject runs `compose up` for one folder with every override om adds (egress, lock, secrets, network, logging,
// limits).
func (a *App) startProject(rt, wsID string, env []string, dir string, cfg map[string]any, build bool, proxyURLs map[string]string, pinned map[string]string, netOverride, subnet string) bool {
	composeFile, _ := workspace.FindComposeFile(dir)
	up := []string{"up", "-d"}
	if hb, _ := workspace.HasBuild(composeFile); build && hb {
		up = append(up, "--build")
	}
	secretOverride, err := a.Age.WriteOverride(rt, wsID, dir, cfg, filepath.Join(a.D.State, "secrets", "overrides"))
	if err != nil {
		a.p("    \033[31m✗ secrets: %s — not started (the host key is in %s)\033[0m", err, a.Age.KeyFile())
		return false
	}
	limitsOverride, problems, _ := labels.WriteOverride(a.D, wsID, dir, cfg)
	for _, pr := range problems {
		a.p("    \033[33m⚠ %s — ignored, no such limit\033[0m", pr)
	}
	egressOverride, _ := a.Egress.WriteOverride(wsID, dir, cfg, proxyURLs, subnet, nil)
	lockOverride, _ := a.Lock.WriteOverride(wsID, dir, cfg, pinned)
	nolog, _ := a.nologOverride(wsID, dir, cfg)
	var extra []string
	for _, o := range []string{egressOverride, lockOverride, secretOverride, netOverride, nolog, limitsOverride} {
		if o != "" {
			extra = append(extra, "-f", o)
		}
	}
	cmd := append(workspace.Compose(rt, composeFile, extra...), up...)
	res := a.RunIn(cmd, dir, env)
	if res.Code != 0 {
		a.p("    \033[31m❌ Failed to start %s:\033[0m\n%s", filepath.Base(dir), lastRunes(py.Strip(res.Stderr), 1500))
		return false
	}
	a.p("    \033[32m✓ %s running\033[0m", filepath.Base(dir))
	return true
}

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

func (a *App) warnExposedPorts(rt, wsID string) {
	r := a.Run([]string{rt, "ps", "--format", "{{.Names}}\t{{.Ports}}"})
	for _, line := range py.SplitLines(r.Stdout) {
		name, ports, _ := strings.Cut(line, "\t")
		if strings.HasPrefix(name, wsID+"_") && strings.Contains(ports, "->") {
			a.p("  \033[31m⚠ %s publishes host ports (%s).\033[0m", name, ports)
			a.p("    These bypass the proxy and may be reachable from the LAN. Use 'expose:' instead of 'ports:'.")
		}
	}
}

// startWorkspace starts services; build also rebuilds images of services that have a `build:` section. Every call is
// recorded as a generation.
func (a *App) startWorkspace(root, target string, build bool, kind string) (bool, error) {
	wsID, err := a.wsID(root)
	if err != nil {
		return false, err
	}
	rt := a.Runtime()
	allowed, signer, dirty := a.checkSignature(root, wsID, kind)
	if !allowed {
		a.Gen.Record(wsID, root, kind, "refused", "")
		return false, nil
	}
	if err := workspace.Register(a.Reg, root, wsID); err != nil {
		return false, Die("%s", err)
	}
	workspace.HideLocalFiles(root)
	a.ensureNet(wsID, rt)
	if err := a.ensureCoreRunning(rt, wsID); err != nil {
		return false, err
	}
	targets := workspace.DiscoverComposeDirs(root, target)
	if len(targets) == 0 {
		a.p("\n  \033[33mNo services or projects found.\033[0m Run '\033[1mom add <name>\033[0m' to scaffold one.\n")
		return true, nil
	}
	a.p("\n\033[1m🚀 Starting User Workloads [%s]\033[0m", strings.ToUpper(wsID))
	a.p("%s", strings.Repeat("─", 78))
	env := a.wsEnv(root, wsID, rt)
	// Read every project once: routes, the policy gate and the egress proxy all work on `compose config`.
	configs := map[string]composeResult{}
	cfgOnly := map[string]map[string]any{}
	for _, t := range targets {
		cf, _ := workspace.FindComposeFile(t.Dir)
		configs[t.Dir] = a.composeConfig(rt, cf, env)
		cfgOnly[t.Dir] = configs[t.Dir].cfg
	}
	if _, err := a.Syncer.SyncCaddyRoutes(root, rt, false, cfgOnly); err != nil {
		return false, Die("%s", err)
	}
	iso := a.isolateProjects(rt, wsID, root, targets, configs)
	wanted, proxyURLs, err := a.renderEgress(rt, wsID, targets, configs, iso.subnets, target)
	if err != nil {
		return false, Die("%s", err)
	}
	pinned := lock.Read(root)
	refSet := map[string]bool{}
	for _, c := range configs {
		for _, ref := range lock.Images(c.cfg) {
			if _, ok := pinned[ref]; !ok {
				refSet[ref] = true
			}
		}
	}
	if len(refSet) > 0 {
		a.p("  \033[33m⚠ not in .om/lock.json (tag can change under you): %s — run `om lock`\033[0m", strings.Join(sortedSet(refSet), ", "))
	}
	a.attachNetworks(rt, wsID, root, targets, configs, target, iso.needsEgress)
	a.announceOpenEgress(wanted)

	ok := true
	for _, t := range targets {
		dir := t.Dir
		a.p("  ▶ [Priority %02d] Starting \033[1m%s\033[0m...", t.Priority, filepath.Base(dir))
		c := configs[dir]
		cf, _ := workspace.FindComposeFile(dir)
		// in this order, and each step only if the one before allowed it: gate, network, start
		if !a.policyAllows(wsID, cf, c) || iso.failed[dir] ||
			!a.startProject(rt, wsID, env, dir, c.cfg, build, proxyURLs, pinned, iso.overrides[dir], iso.subnets[dir]) {
			ok = false
		}
	}
	a.Core.ReloadCaddy(rt, wsID, false)
	a.warnExposedPorts(rt, wsID)
	for _, problem := range links.Sync(links.Runner(a.Run), rt) {
		if strings.HasPrefix(problem, wsID+"/") || strings.Contains(problem, "="+wsID+"/") {
			a.p("    \033[33m⚠ link %s\033[0m", problem)
		}
	}
	genKind := kind
	if dirty && kind == "start" {
		genKind = "dev"
	}
	if target != "" {
		genKind += ":" + target
	}
	result := "failed"
	if ok {
		result = "running"
	}
	gen, err := a.Gen.Record(wsID, root, genKind, result, signer)
	if err != nil {
		return false, Die("%s", err)
	}
	if ok && signer != "" {
		if warn, err := a.Gen.RememberSigners(wsID, root, "HEAD"); err == nil && warn != "" {
			a.p("%s", warn)
		}
	}
	a.p("\n\033[32m✓ User workloads live (generation %d). Access via: %s\033[0m\n", genNumber(gen), a.BaseURL(wsID+".<service>.localhost"))
	return ok, nil
}

func genNumber(g map[string]any) int {
	switch n := g["n"].(type) {
	case int:
		return n
	}
	return 0
}

func (a *App) cmdStart(root string, ns Namespace) error {
	ok, err := a.startWorkspace(root, ns.Str("target"), ns.Bool("build"), "start")
	if err != nil {
		return err
	}
	if !ok {
		return Exit(1)
	}
	return nil
}

func (a *App) cmdRestart(root string, ns Namespace) error { return a.cmdStart(root, ns) }

func (a *App) cmdDev(root string, ns Namespace) error {
	rt := a.Runtime()
	proj, err := workspace.ResolveTarget(root, ns.Str("project"))
	if err != nil {
		return Die("%s", err)
	}
	a.p("\033[1m🛠️  Launching dev container for %s...\033[0m", ns.Str("project"))
	a.startWorkspace(root, ns.Str("project"), true, "dev")
	names, err := workspace.ServiceContainers(rt, root, proj)
	if err != nil {
		return Die("%s", err)
	}
	a.p("\n\033[36mStreaming live logs for %s (Ctrl+C to detach; the container keeps running)...\033[0m", names[0])
	a.Passthrough([]string{rt, "logs", "-f", "--tail", "50", names[0]}, "", nil)
	return nil
}

func (a *App) cmdStop(root string, ns Namespace, stopAll bool) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	rt := a.Runtime()
	env := a.wsEnv(root, wsID, rt)
	all := workspace.DiscoverComposeDirs(root, ns.Str("target"))
	targets := make([]workspace.Project, len(all))
	for i, t := range all {
		targets[len(all)-1-i] = t
	}
	if len(targets) == 0 && !stopAll {
		a.p("\033[33mNo matching services or projects found to stop.\033[0m")
		return nil
	}
	a.p("\n\033[1m🛑 Stopping User Workloads [%s]...\033[0m", strings.ToUpper(wsID))
	for _, t := range targets {
		a.p("  ■ Stopping %s...", filepath.Base(t.Dir))
		cf, _ := workspace.FindComposeFile(t.Dir)
		a.RunIn(workspace.Compose(rt, cf, "down"), t.Dir, env)
	}
	if ns.Str("target") == "" {
		a.Age.Wipe(wsID) // decrypted copies live only while the workspace runs
		a.Egress.RenderWorkspace(rt, wsID, map[string]egress.Rule{}, true, nil)
	}
	if stopAll {
		a.Core.Down(rt)
		a.p("\033[32m✓ Workspace and Global Core stopped.\033[0m\n")
	} else {
		a.p("\033[32m✓ User workloads stopped. Dashboard remains live at %s/\033[0m\n", a.BaseURL(""))
	}
	return nil
}

func (a *App) cmdDown(root string, ns Namespace) error {
	return a.cmdStop(root, Namespace{"target": nil}, true)
}

// workspaceImages returns {image ref: [services using it]}, the held refs and the auto refs. A ref is held when any
// service using it has om.update=hold, and auto only when every service using it has om.update=auto.
func (a *App) workspaceImages(root, target string, report bool) (map[string][]string, map[string]bool, map[string]bool, []string) {
	rt := a.Runtime()
	wsID, _ := workspace.WorkspaceID(root)
	env := a.wsEnv(root, wsID, rt)
	users, held := map[string][]string{}, map[string]bool{}
	seen := map[string]map[string]bool{}
	var order []string
	for _, t := range workspace.DiscoverComposeDirs(root, target) {
		cf, _ := workspace.FindComposeFile(t.Dir)
		c := a.composeConfig(rt, cf, env)
		if c.err != "" && report {
			a.p("  \033[31m✗ %s\033[0m", c.err)
		}
		modes, bad := lock.UpdateModes(c.cfg)
		if report {
			for _, line := range bad {
				a.p("  \033[33m⚠ %s is not one of %s; treated as manual\033[0m", line, strings.Join(lock.Modes, ", "))
			}
		}
		imgs := lock.Images(c.cfg)
		for _, svc := range sortedKeys(imgs) {
			ref := imgs[svc]
			if _, ok := users[ref]; !ok {
				order = append(order, ref)
			}
			users[ref] = append(users[ref], svc)
			if seen[ref] == nil {
				seen[ref] = map[string]bool{}
			}
			seen[ref][modes[svc]] = true
			if modes[svc] == "hold" {
				held[ref] = true
			}
		}
	}
	auto := map[string]bool{}
	for ref, m := range seen {
		if len(m) == 1 && m["auto"] {
			auto[ref] = true
		}
	}
	return users, held, auto, order
}

// lockWorkspace resolves digests for this workspace's pulled images into .om/lock.json and returns (old, new). With
// refresh, only limits which refs move (nil: all) and held refs never do.
func (a *App) lockWorkspace(root, target string, refresh bool, only map[string]bool) (map[string]string, map[string]string, error) {
	rt := a.Runtime()
	users, held, _, _ := a.workspaceImages(root, target, true)
	refs := map[string]bool{}
	for r := range users {
		refs[r] = true
	}
	old := lock.Read(root)
	move := map[string]bool{}
	if refresh {
		for r := range refs {
			if (only == nil || only[r]) && !held[r] {
				move[r] = true
			}
		}
	} else {
		move = refs
	}
	rest := []string{}
	for r := range refs {
		if !move[r] {
			rest = append(rest, r)
		}
	}
	newPins, missing := a.Lock.Resolve(rt, rest, old, false)
	moved, missingMoved := a.Lock.Resolve(rt, sortedSet(move), old, refresh)
	for k, v := range moved {
		newPins[k] = v
	}
	missing = append(missing, missingMoved...)
	if refresh {
		for _, ref := range sortedSet(intersect(held, refs)) {
			a.p("  ⏸ %s is held (om.update=hold), pin unchanged", ref)
		}
	}
	if target != "" { // keep the other projects' pins
		merged := map[string]string{}
		for k, v := range old {
			merged[k] = v
		}
		for k, v := range newPins {
			merged[k] = v
		}
		newPins = merged
	}
	for _, ref := range missing {
		a.p("  \033[33m⚠ no digest for %s (registry needs a login? pull it once, then `om lock`)\033[0m", ref)
	}
	if err := lock.Write(root, newPins); err != nil {
		return nil, nil, Die("%s", err)
	}
	all := map[string]bool{}
	for k := range old {
		all[k] = true
	}
	for k := range newPins {
		all[k] = true
	}
	for _, ref := range sortedSet(all) {
		if old[ref] != newPins[ref] {
			from, to := "unpinned", "removed"
			if v, ok := old[ref]; ok {
				from = v[7:19]
			}
			if v, ok := newPins[ref]; ok {
				to = v[7:19]
			}
			a.p("  %s  %s → %s", ref, from, to)
		}
	}
	return old, newPins, nil
}

func intersect(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

// commitLock commits only .om/lock.json (signed if git is configured to sign).
func (a *App) commitLock(root, message string) {
	if c, _, _ := gitsync.RunGit([]string{"rev-parse", "--is-inside-work-tree"}, root); c != 0 {
		return
	}
	d, _, _ := gitsync.RunGit([]string{"diff", "--quiet", "--", lock.Name}, root)
	l, _, _ := gitsync.RunGit([]string{"ls-files", "--error-unmatch", lock.Name}, root)
	if d == 0 && l == 0 {
		return
	}
	gitsync.RunGit([]string{"add", lock.Name}, root)
	code, _, err := gitsync.RunGit([]string{"commit", "-m", message, "--", lock.Name}, root)
	if code == 0 {
		a.p("  \033[32m✓ committed .om/lock.json\033[0m")
	} else {
		a.p("  \033[33m⚠ could not commit the lock: %s\033[0m", lastRunes(py.Strip(err), 300))
	}
}

func (a *App) cmdLock(root string, ns Namespace) error {
	old, newPins, err := a.lockWorkspace(root, "", false, nil)
	if err != nil {
		return err
	}
	changed := !samePins(old, newPins)
	suffix := ""
	if !changed {
		suffix = " (no change)"
	}
	a.p("\033[32m✓ %d image(s) pinned in %s.\033[0m%s", len(newPins), lock.Name, suffix)
	if changed {
		a.p("  Commit it to make it part of what runs: git commit .om/lock.json")
	}
	return nil
}

func samePins(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (a *App) updatesFile(ws string) string {
	return filepath.Join(a.D.State, "registry", "updates", ws+".json")
}

// availableUpdates returns {ref: (pinned, newest)} for images whose tag now points at another digest, and writes the
// cache.
func (a *App) availableUpdates(root, target string) map[string][2]string {
	wsID, _ := workspace.WorkspaceID(root)
	pinned := lock.Read(root)
	users, held, _, _ := a.workspaceImages(root, target, false)
	out := map[string][2]string{}
	refs := make([]string, 0, len(users))
	for r := range users {
		if !held[r] {
			refs = append(refs, r)
		}
	}
	sort.Strings(refs)
	for _, ref := range refs {
		newest := a.Lock.RegistryDigest(ref)
		if newest != "" && pinned[ref] != "" && newest != pinned[ref] {
			out[ref] = [2]string{pinned[ref], newest}
		}
	}
	if target == "" {
		os.MkdirAll(filepath.Dir(a.updatesFile(wsID)), 0o755)
		var svcs []string
		for _, ref := range sortedKeys(out) {
			svcs = append(svcs, users[ref]...)
		}
		sort.Strings(svcs)
		body := py.NewObject()
		body.Set("checked", a.Now().Unix())
		body.Set("updates", sortedKeys(out))
		body.Set("services", svcs)
		os.WriteFile(a.updatesFile(wsID), []byte(py.DumpsCompact(body)+"\n"), 0o644)
	}
	return out
}

func (a *App) cachedUpdates(wsID string) ([]string, float64) {
	b, err := os.ReadFile(a.updatesFile(wsID))
	if err != nil {
		return nil, 0
	}
	v, err := py.LoadJSON(b)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, 0
	}
	var ups []string
	if l, ok := m["updates"].([]any); ok {
		for _, x := range l {
			ups = append(ups, py.Str(x))
		}
	}
	var checked float64
	if n, ok := m["checked"].(interface{ Float64() (float64, error) }); ok {
		checked, _ = n.Float64()
	}
	return ups, checked
}

func (a *App) describeChange(ref, old, new string) string {
	x, okx := a.Lock.Describe(ref, old)
	y, oky := a.Lock.Describe(ref, new)
	if !okx {
		x = lock.Description{}
	}
	if !oky {
		y = lock.Description{}
	}
	var bits []string
	if x.Created != "" || y.Created != "" {
		c1, c2 := x.Created, y.Created
		if c1 == "" {
			c1 = "?"
		}
		if c2 == "" {
			c2 = "?"
		}
		bits = append(bits, fmt.Sprintf("built %s → %s", c1, c2))
	}
	if x.Size != 0 && y.Size != 0 {
		bits = append(bits, fmt.Sprintf("%.1f → %.1f MB", float64(x.Size)/1048576, float64(y.Size)/1048576))
	}
	if len(bits) == 0 {
		return ""
	}
	return "  (" + strings.Join(bits, ", ") + ")"
}

func (a *App) cmdUpdate(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	rt := a.Runtime()
	target := ns.Str("target")
	users, _, _, _ := a.workspaceImages(root, target, false)
	if ns.Bool("dry_run") {
		ups := a.availableUpdates(root, target)
		for _, ref := range sortedKeys(ups) {
			p := ups[ref]
			a.p("  %s  %s → %s  [%s]%s", ref, p[0][7:19], p[1][7:19], strings.Join(users[ref], ", "), a.describeChange(ref, p[0], p[1]))
		}
		msg := fmt.Sprintf("  %d update(s) available.", len(ups))
		if len(ups) > 0 {
			msg += "  Apply: om update"
			if target != "" {
				msg += " " + target
			}
			msg += " (--image REF to pick, -i to choose)"
		}
		a.p("%s", msg)
		return nil
	}
	env := a.wsEnv(root, wsID, rt)
	targets := workspace.DiscoverComposeDirs(root, target)
	if len(targets) == 0 {
		return Die("Nothing to update.")
	}
	var only map[string]bool
	if imgs := ns.List("image"); len(imgs) > 0 {
		only = setOf(imgs)
	}
	for _, ref := range sortedSet(only) {
		if _, ok := users[ref]; !ok {
			return Die("%s is not an image of this workspace (`om update --dry-run` lists them).", ref)
		}
	}
	if ns.Bool("choose") {
		if !a.Interactive {
			return Die("--choose needs a terminal.")
		}
		ups := a.availableUpdates(root, target)
		chosen := map[string]bool{}
		for _, ref := range sortedKeys(ups) {
			if only != nil && !only[ref] {
				continue
			}
			p := ups[ref]
			fmt.Fprintf(a.Out, "  Update %s [%s] %s → %s? [y/N] ", ref, strings.Join(users[ref], ", "), p[0][7:19], p[1][7:19])
			line, _ := a.In.ReadString('\n')
			if l := strings.ToLower(py.Strip(line)); l == "y" || l == "yes" {
				chosen[ref] = true
			}
		}
		only = chosen
		if len(only) == 0 {
			a.p("  Nothing selected.")
			return nil
		}
	}
	a.p("  ⬇ Checking registries for newer digests...")
	old, newPins, err := a.lockWorkspace(root, target, true, only)
	if err != nil {
		return err
	}
	if !samePins(old, newPins) {
		var changed []string
		for _, r := range sortedKeys(newPins) {
			if old[r] != newPins[r] {
				changed = append(changed, r)
			}
		}
		a.commitLock(root, "om update: "+strings.Join(changed, ", "))
	}
	a.availableUpdates(root, "") // the pins just moved: refresh what `om status` lists (whole workspace)
	for _, t := range targets {
		cf, _ := workspace.FindComposeFile(t.Dir)
		if hb, _ := workspace.HasBuild(cf); hb {
			a.p("  🔨 Rebuilding %s...", filepath.Base(t.Dir))
			r := a.RunIn(workspace.Compose(rt, cf, "build", "--pull"), t.Dir, env)
			if r.Code != 0 {
				out := r.Stderr
				if out == "" {
					out = r.Stdout
				}
				a.p("    \033[31m❌ build failed: %s\033[0m", lastRunes(py.Strip(out), 500))
			}
		}
	}
	// Same path as `om start`: policy gate, egress and lock overrides, routes.
	ok, err := a.startWorkspace(root, target, false, "update")
	if err != nil {
		return err
	}
	if !ok {
		return Exit(1)
	}
	a.p("  Health check...")
	if a.gitSync().SyntheticHealthCheck(a.gitSync().WorkspaceVhosts(wsID), 60*time.Second) {
		a.p("\033[32m✓ All services healthy.\033[0m")
		return nil
	}
	return Exit(1)
}

// gitSync builds the GitOps engine with the private ingress and the generated routes.
func (a *App) gitSync() *gitsync.Sync { return gitsync.New(a.Out, a.BaseURL("127.0.0.1"), a.D.Routes) }

// serviceDir finds a service folder by name, including ones disabled with .omignore (which discovery skips).
func (a *App) serviceDir(root, name string) (string, error) {
	bases := []string{root}
	if es, err := os.ReadDir(root); err == nil {
		for _, e := range es {
			p := filepath.Join(root, e.Name())
			if st, err := os.Stat(p); err == nil && st.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				bases = append(bases, p)
			}
		}
	}
	for _, b := range bases {
		d := filepath.Join(b, name)
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			if _, ok := workspace.FindComposeFile(d); ok {
				return d, nil
			}
		}
	}
	return "", Die("No service or project named '%s' in this workspace. See `om status`.", name)
}

func (a *App) cmdDisable(root string, ns Namespace) error {
	rt := a.Runtime()
	dir, err := a.serviceDir(root, ns.Str("service"))
	if err != nil {
		return err
	}
	if dir == root {
		return Die("Refusing to disable the workspace root compose project.")
	}
	if _, err := os.Stat(filepath.Join(dir, ".omignore")); err == nil {
		return Die("%s is already disabled.", filepath.Base(dir))
	}
	wsID, _ := workspace.WorkspaceID(root)
	env := a.wsEnv(root, wsID, rt)
	cf, _ := workspace.FindComposeFile(dir)
	a.RunIn(workspace.Compose(rt, cf, "down"), dir, env)
	os.WriteFile(filepath.Join(dir, ".omignore"), []byte("disabled by `om disable`; remove with `om enable`\n"), 0o644)
	a.Syncer.SyncCaddyRoutes(root, rt, true, nil)
	active := map[string]egress.Rule{}
	for _, t := range workspace.DiscoverComposeDirs(root, "") {
		if f, ok := workspace.FindComposeFile(t.Dir); ok {
			if c := a.composeConfig(rt, f, env); len(c.cfg) > 0 {
				for k, v := range policy.EgressServices(c.cfg) {
					active[k] = v
				}
			}
		}
	}
	a.Egress.RenderWorkspace(rt, wsID, active, true, nil)
	a.p("\033[32m✓ Disabled %s.\033[0m Re-enable with `om enable %s`", filepath.Base(dir), filepath.Base(dir))
	return nil
}

func (a *App) cmdEnable(root string, ns Namespace) error {
	dir, err := a.serviceDir(root, ns.Str("service"))
	if err != nil {
		return err
	}
	marker := filepath.Join(dir, ".omignore")
	if _, err := os.Stat(marker); err != nil {
		return Die("%s is not disabled.", filepath.Base(dir))
	}
	os.Remove(marker)
	a.p("\033[32m✓ Enabled %s.\033[0m Start it with `om start %s`", filepath.Base(dir), filepath.Base(dir))
	return nil
}

func (a *App) cmdRemove(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	rt := a.Runtime()
	dir, err := workspace.ResolveTarget(root, ns.Str("service"))
	if err != nil {
		return Die("%s", err)
	}
	if dir == root {
		return Die("Refusing to remove the workspace root compose project.")
	}
	dataDir := filepath.Join(root, "data", filepath.Base(dir))
	rel, _ := filepath.Rel(root, dir)
	what := rel
	dataExists := false
	if _, err := os.Stat(dataDir); err == nil {
		dataExists = true
		if ns.Bool("data") {
			r, _ := filepath.Rel(root, dataDir)
			what += " and " + r
		}
	}
	if !ns.Bool("yes") && !a.Confirm(fmt.Sprintf("Remove %s? (moved to .om/trash, recoverable)", what)) {
		return Die("Aborted.")
	}
	env := a.wsEnv(root, wsID, rt)
	cf, _ := workspace.FindComposeFile(dir)
	a.RunIn(workspace.Compose(rt, cf, "down"), dir, env)
	workspace.HideLocalFiles(root)
	trash := filepath.Join(root, ".om", "trash", a.Now().Format("20060102-150405"))
	os.MkdirAll(trash, 0o755)
	if err := os.Rename(dir, filepath.Join(trash, filepath.Base(dir))); err != nil {
		return Die("%s", err)
	}
	if ns.Bool("data") && dataExists {
		os.Rename(dataDir, filepath.Join(trash, "data-"+filepath.Base(dir)))
	}
	a.Syncer.SyncCaddyRoutes(root, rt, true, nil)
	a.p("\033[32m✓ Removed %s.\033[0m Restore from %s", filepath.Base(dir), trash)
	return nil
}

func (a *App) cmdLogs(root string, ns Namespace) error {
	rt := a.Runtime()
	dir, err := workspace.ResolveTarget(root, ns.Str("service"))
	if err != nil {
		return Die("%s", err)
	}
	names, err := workspace.ServiceContainers(rt, root, dir)
	if err != nil {
		return Die("%s", err)
	}
	cmd := []string{rt, "logs", "--tail", strconv.Itoa(ns.Int("tail"))}
	if ns.Bool("follow") {
		cmd = append(cmd, "-f")
	}
	if ns.Bool("follow") || len(names) == 1 {
		a.Passthrough(append(cmd, names[0]), "", nil)
		return nil
	}
	for _, n := range names {
		a.p("\033[1m── %s ──\033[0m", n)
		a.Passthrough(append(append([]string{}, cmd...), n), "", nil)
	}
	return nil
}

func (a *App) cmdShell(root string, ns Namespace) error {
	rt := a.Runtime()
	dir, err := workspace.ResolveTarget(root, ns.Str("service"))
	if err != nil {
		return Die("%s", err)
	}
	names, err := workspace.ServiceContainers(rt, root, dir)
	if err != nil {
		return Die("%s", err)
	}
	inner := ns.List("cmd")
	if len(inner) == 0 {
		inner = []string{"sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"}
	}
	tty := "-i"
	if a.Interactive {
		tty = "-it"
	}
	return Exit(a.Passthrough(append([]string{rt, "exec", tty, names[0]}, inner...), "", nil))
}
