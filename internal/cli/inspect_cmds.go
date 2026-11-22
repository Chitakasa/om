package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/gitsync"
	"github.com/Chitakasa/om/internal/lock"
	"github.com/Chitakasa/om/internal/prune"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/scan"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

var coreRoles = [][2]string{{"om_caddy", "edge proxy"}, {"om_router", "internal router"}, {"om_egress", "outbound allow-list proxy"},
	{"om_sockguard", "read-only engine filter"}, {"om_stream_edge", "raw TCP edge"}, {"om_stream_router", "raw TCP router"},
	{"om_dashboard", "dashboard  http://localhost/"}}

var stateBadges = map[string]string{"absent": "\033[90m⚪ Offline\033[0m", "running": "\033[32m🟢 Running\033[0m",
	"crashed": "\033[31m❌ Crashed\033[0m", "stopped": "\033[33m⏹ Stopped\033[0m"}

func ljust(s string, w int) string {
	if n := runeLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func rjust(s string, w int) string {
	if n := runeLen(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

type containerState struct{ status, state string }

// containerStates returns {container: (status text, state)} for every container the engine knows, running or not.
func (a *App) containerStates(rt string) map[string]containerState {
	r := a.Run([]string{rt, "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.State}}"})
	out := map[string]containerState{}
	for _, line := range py.SplitLines(py.Strip(r.Stdout)) {
		p := strings.Split(line, "\t")
		if len(p) >= 3 {
			out[p[0]] = containerState{strings.ToLower(p[1]), strings.ToLower(p[2])}
		}
	}
	return out
}

// stateOf is absent, running, crashed (exited with an error) or stopped.
func stateOf(states map[string]containerState, name string) string {
	s, ok := states[name]
	if !ok {
		return "absent"
	}
	if strings.Contains(s.status, "up") || s.state == "running" {
		return "running"
	}
	if strings.Contains(s.status, "exited") && !strings.Contains(s.status, "exited (0)") {
		return "crashed"
	}
	return "stopped"
}

// serviceTier is public or private: a stream service's own scope, else whether it has a public alias route.
func (a *App) serviceTier(wsID, service, streamScope string) string {
	if streamScope != "" {
		return streamScope
	}
	if _, err := os.Stat(filepath.Join(a.D.Routes, wsID+"-"+service+".public_alias")); err == nil {
		return "public"
	}
	return "private"
}

func (a *App) statusData(root, rt string, states map[string]containerState) map[string]any {
	core := map[string]any{}
	for _, c := range state.CoreContainers {
		core[c] = stateOf(states, c)
	}
	out := map[string]any{"version": state.Version, "runtime": rt, "core": core}
	if root != "" {
		wsID, _ := workspace.WorkspaceID(root)
		updates, checked := a.cachedUpdates(wsID)
		streamPorts := a.Reg.StreamPorts()
		var services []any
		for _, t := range workspace.DiscoverComposeDirs(root, "") {
			conts := map[string]any{}
			names, _ := workspace.ServiceContainers(rt, root, t.Dir)
			for _, n := range names {
				conts[n] = stateOf(states, n)
			}
			scope := ""
			if sp, ok := streamPorts[wsID+"/"+filepath.Base(t.Dir)]; ok {
				scope = sp.Scope
			}
			services = append(services, map[string]any{"service": filepath.Base(t.Dir), "containers": conts, "scope": a.serviceTier(wsID, filepath.Base(t.Dir), scope)})
		}
		var cur any
		if g := a.Gen.Current(wsID); g != nil {
			cur = g
		}
		ups := []any{}
		for _, u := range updates {
			ups = append(ups, u)
		}
		ws := map[string]any{"id": wsID, "path": root, "generation": cur, "updates": ups, "updates_checked": int64(checked), "services": services}
		if ign := workspace.IgnoredComposeDirs(root); len(ign) > 0 {
			var names []any
			for _, d := range ign {
				names = append(names, filepath.Base(d))
			}
			ws["ignored"] = names
		}
		out["workspace"] = ws
	}
	return out
}

func (a *App) serviceURL(wsID, service string, stream *streamInfo, lan string) string {
	if _, err := os.Stat(filepath.Join(a.D.Routes, wsID+"-"+service+".caddy")); err == nil {
		return a.BaseURL(wsID + "." + service + ".localhost")
	}
	if stream != nil {
		host := "localhost"
		if stream.scope == "public" && lan != "" {
			host = lan
		}
		return fmt.Sprintf("tcp://%s:%d", host, stream.hostPort)
	}
	return "—"
}

type streamInfo struct {
	scope    string
	hostPort int
}

func (a *App) generationSummary(wsID, root string) string {
	gen, now := a.Gen.Current(wsID), a.Gen.Snapshot(root)
	if gen == nil {
		return "generation —  (nothing deployed through om yet: om start)"
	}
	st := "\033[32mclean\033[0m"
	if py.Truthy(gen["dirty"]) {
		st = "\033[33mdirty\033[0m"
	}
	who := "\033[33munsigned\033[0m"
	if s := gen["signer"]; py.Truthy(s) {
		who = "signed by " + py.Str(s)
	}
	commit := "—"
	if c := gen["commit"]; py.Truthy(c) {
		commit = py.Str(c)
		if len(commit) > 8 {
			commit = commit[:8]
		}
	}
	line := fmt.Sprintf("generation %s  %s  %s  %s  (%s, %s)", py.Str(gen["n"]), st, commit, who, py.Str(gen["kind"]), py.Str(gen["time"]))
	if now["commit"] != gen["commit"] && !(now["commit"] == nil && gen["commit"] == nil) ||
		now["dirty"] != gen["dirty"] && !(py.Str(now["dirty"]) == py.Str(gen["dirty"])) || now["lock"] != gen["lock"] && !(now["lock"] == nil && gen["lock"] == nil) {
		line += "\n  \033[33m⚠ the workspace changed since this generation (commit, lock or files): om start\033[0m"
	}
	return line
}

func (a *App) printWorkspaceStatus(root, rt string, states map[string]containerState) {
	wsID, _ := workspace.WorkspaceID(root)
	a.p("\n\033[1mWORKSPACE: %s\033[0m  (%s)", wsID, root)
	a.p("%s", strings.Repeat("─", 78))
	a.p("  %s", a.generationSummary(wsID, root))
	if updates, _ := a.cachedUpdates(wsID); len(updates) > 0 {
		var short []string
		for _, u := range updates {
			short = append(short, u[strings.LastIndex(u, "/")+1:])
		}
		a.p("  \033[36mupdates  %d available (%s) — om update --dry-run\033[0m", len(updates), strings.Join(short, ", "))
	}
	targets := workspace.DiscoverComposeDirs(root, "")
	if len(targets) == 0 {
		a.p("  (no services yet — `om add <name>`)")
	}
	streams := map[string]*streamInfo{}
	for k, v := range a.Reg.StreamPorts() {
		streams[k] = &streamInfo{v.Scope, v.HostPort}
	}
	env, _ := state.ParseEnvFile(a.D.RuntimeEnv)
	lan := env["LAN_IP"]
	if strings.HasSuffix(lan, ".invalid") {
		lan = ""
	}
	unknown := false
	for _, t := range targets {
		name := filepath.Base(t.Dir)
		st := streams[wsID+"/"+name]
		kind := "service"
		if filepath.Base(filepath.Dir(t.Dir)) == "projects" {
			kind = "project"
		}
		names, _ := workspace.ServiceContainers(rt, root, t.Dir)
		badge := stateBadges[stateOf(states, names[0])]
		scope := ""
		if st != nil {
			scope = st.scope
		}
		url := a.serviceURL(wsID, name, st, lan)
		unknown = unknown || url == "—"
		a.p("  %s %s %s %s %s", ljust(name, 20), ljust(kind, 8), ljust(badge, 22), ljust(a.serviceTier(wsID, name, scope), 8), url)
	}
	if unknown {
		a.p("  \033[90m— = no web address (a background service)\033[0m")
	}
	if ign := workspace.IgnoredComposeDirs(root); len(ign) > 0 {
		var names []string
		for _, d := range ign {
			names = append(names, filepath.Base(d))
		}
		a.p("  \033[90mnot managed by om (has .omignore): %s\033[0m", strings.Join(names, ", "))
	}
	a.p("")
}

func (a *App) cmdStatus(root string, ns Namespace) error {
	rt := a.Runtime()
	states := a.containerStates(rt)
	if ns.Bool("json") {
		a.EmitJSON(a.statusData(root, rt, states))
		return nil
	}
	a.p("\n\033[1mOM PLATFORM\033[0m  (om %s)", state.Version)
	a.p("%s", strings.Repeat("═", 78))
	for _, r := range coreRoles {
		a.p("  %s %s %s", ljust(r[0], 16), ljust(stateBadges[stateOf(states, r[0])], 22), r[1])
	}
	if root != "" {
		a.printWorkspaceStatus(root, rt, states)
	} else {
		a.cmdList(ns)
	}
	var steps [][2]string
	if stateOf(states, "om_caddy") != "running" {
		steps = append(steps, [2]string{"om core start", "the edge proxy and dashboard are not running"})
	}
	if root == "" {
		steps = append(steps, [2]string{"cd <folder>; om init", "make a folder a workspace, then `om add web` and `om start`"})
	}
	if len(steps) > 0 {
		a.p("  \033[1mNext\033[0m")
		for _, s := range steps {
			a.p("    %s %s", ljust(s[0], 22), s[1])
		}
		a.p("")
	}
	return nil
}

func (a *App) cmdList(ns Namespace) error {
	reg := a.Reg.Read()
	if ns.Bool("json") {
		var out []any
		for _, w := range sortedKeys(reg) {
			p, _ := reg[w]["path"].(string)
			_, err := os.Stat(filepath.Join(p, ".om", "config.json"))
			item := map[string]any{"id": w, "path": nilIfEmpty(reg[w]["path"]), "exists": err == nil, "last_active": reg[w]["last_active"]}
			out = append(out, item)
		}
		if out == nil {
			out = []any{}
		}
		a.EmitJSON(out)
		return nil
	}
	a.p("\n\033[1mREGISTERED WORKSPACES\033[0m")
	a.p("%s", strings.Repeat("═", 78))
	if len(reg) == 0 {
		a.p("  None yet. Run 'om init' in a directory to create one.\n")
		return nil
	}
	var missing []string
	for _, id := range sortedKeys(reg) {
		p, _ := reg[id]["path"].(string)
		_, err := os.Stat(p)
		exists := err == nil
		if !exists {
			missing = append(missing, id)
		}
		st := "\033[31mMISSING\033[0m"
		if exists {
			st = "\033[32mACTIVE\033[0m "
		}
		a.p("  %s %s  %s", ljust(id, 20), st, p)
	}
	if len(missing) > 0 && ns.Bool("prune") {
		a.Reg.Update(func(w registry_Workspaces) error {
			for _, m := range missing {
				delete(w, m)
			}
			return nil
		})
		removed, _ := a.Syncer.PruneOrphanRoutes(a.Runtime(), true, true, true)
		a.p("\n  \033[36mPruned: %s (%d route file(s) removed)\033[0m", strings.Join(missing, ", "), len(removed))
	} else if len(missing) > 0 {
		a.p("\n  Missing folders (e.g. unplugged drive) are kept; `om list --prune` removes them.")
	}
	a.p("")
	return nil
}

func nilIfEmpty(v any) any {
	if s, ok := v.(string); ok && s == "" {
		return nil
	}
	return v
}

func (a *App) cmdLog(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	es := a.Gen.Entries(wsID)
	n := ns.Int("n")
	pick := es
	if n > 0 && len(es) > n {
		pick = es[len(es)-n:]
	}
	rev := make([]any, 0, len(pick))
	for i := len(pick) - 1; i >= 0; i-- {
		rev = append(rev, pick[i])
	}
	if ns.Bool("json") {
		probs := []any{}
		for _, p := range a.Gen.VerifyChain(wsID) {
			probs = append(probs, p)
		}
		a.EmitJSON(map[string]any{"workspace": wsID, "generations": rev, "problems": probs})
		return nil
	}
	if len(es) == 0 {
		a.p("  No generations yet: om start")
		return nil
	}
	a.p("\n\033[1mGENERATIONS: %s\033[0m", wsID)
	a.p("%s", strings.Repeat("─", 78))
	for _, x := range rev {
		e := x.(map[string]any)
		res := py.Str(e["result"])
		switch res {
		case "running":
			res = "\033[32mrunning\033[0m"
		case "failed":
			res = "\033[31mfailed\033[0m"
		case "refused":
			res = "\033[31mrefused\033[0m"
		}
		flags := ""
		if py.Truthy(e["dirty"]) {
			flags = " dirty"
		}
		signer := "unsigned"
		if s := e["signer"]; py.Truthy(s) {
			signer = py.Str(s)
		}
		commit := "—"
		if c := e["commit"]; py.Truthy(c) {
			commit = py.Str(c)
			if len(commit) > 8 {
				commit = commit[:8]
			}
		}
		kind, tm := "", ""
		if v, ok := e["kind"]; ok {
			kind = py.Str(v)
		}
		if v, ok := e["time"]; ok {
			tm = py.Str(v)
		}
		a.p("  %s  %s  %s %s %s  %s%s", rjust(py.Str(e["n"]), 4), commit, ljust(res, 18), ljust(kind, 14), tm, signer, flags)
	}
	for _, p := range a.Gen.VerifyChain(wsID) {
		a.p("  \033[31m✗ %s\033[0m", p)
	}
	a.p("")
	return nil
}

var branchRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,100}$`)

func (a *App) trackedBranch(root string) string {
	b := "main"
	if v, ok := workspace.ReadConfig(root).Get("tracked_branch"); ok {
		b = py.Str(v)
	}
	if branchRE.MatchString(b) && !strings.HasPrefix(b, "-") {
		return b
	}
	return "main"
}

func (a *App) cmdRollback(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	var es []map[string]any
	for _, e := range a.Gen.Entries(wsID) {
		if e["result"] == "running" && py.Truthy(e["commit"]) && !py.Truthy(e["dirty"]) {
			es = append(es, e)
		}
	}
	cur := a.Gen.Current(wsID)
	var target map[string]any
	if g := ns.Int("generation"); g != 0 {
		for _, e := range es {
			if py.Str(e["n"]) == strconv.Itoa(g) {
				target = e
			}
		}
		if target == nil {
			return Die("Generation %d is not a clean, successfully started generation (see `om log`).", g)
		}
	} else {
		for i := len(es) - 1; i >= 0; i-- {
			if cur == nil || es[i]["commit"] != cur["commit"] {
				target = es[i]
				break
			}
		}
		if target == nil {
			return Die("No earlier clean generation with a different commit to roll back to (see `om log`).")
		}
	}
	if a.Gen.Snapshot(root)["dirty"] == true {
		return Die("Uncommitted changes: commit or stash them first (rollback checks out another commit).")
	}
	commit := py.Str(target["commit"])
	a.p("\033[33m⏪ Rolling back to generation %s (%s)\033[0m — volumes and data are not rolled back.", py.Str(target["n"]), commit[:8])
	code, _, errText := gitsync.RunGit([]string{"checkout", "--detach", commit}, root)
	if code != 0 {
		return Die("git checkout failed: %s", errText)
	}
	ok, err := a.startWorkspace(root, "", false, "rollback")
	if err != nil {
		return err
	}
	a.p("  HEAD is detached at %s. To continue on your branch: git checkout %s", commit[:8], a.trackedBranch(root))
	if ok {
		return Exit(0)
	}
	return Exit(1)
}

// runningDigests returns {service: RepoDigests} for this workspace's running containers.
func (a *App) runningDigests(rt, wsID string) map[string]map[string]bool {
	r := a.Run([]string{rt, "ps", "--filter", "label=com.docker.compose.project=" + wsID, "--format", `{{.Image}}` + "\t" + `{{index .Labels "com.docker.compose.service"}}`})
	out := map[string]map[string]bool{}
	for _, line := range py.SplitLines(r.Stdout) {
		img, svc, _ := strings.Cut(line, "\t")
		info := a.Run([]string{rt, "image", "inspect", "--format", "{{json .RepoDigests}}", img})
		set := map[string]bool{}
		text := info.Stdout
		if text == "" {
			text = "[]"
		}
		var l []string
		if json.Unmarshal([]byte(text), &l) == nil {
			for _, d := range l {
				set[d[strings.LastIndex(d, "@")+1:]] = true
			}
		}
		out[svc] = set
	}
	return out
}

func (a *App) cmdFsck(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	rt := a.Runtime()
	env := a.wsEnv(root, wsID, rt)
	problems := append([]string(nil), a.Gen.VerifyChain(wsID)...)
	if cur := a.Gen.Current(wsID); cur != nil && py.Truthy(cur["commit"]) && !py.Truthy(cur["dirty"]) {
		commit := py.Str(cur["commit"])
		if trusted, who := a.Gen.Verify(wsID, root, commit); !trusted {
			problems = append(problems, fmt.Sprintf("generation %s commit %s: %s", py.Str(cur["n"]), commit[:8], who))
		}
	}
	pinned := lock.Read(root)
	running := a.runningDigests(rt, wsID)
	for _, t := range workspace.DiscoverComposeDirs(root, "") {
		cf, _ := workspace.FindComposeFile(t.Dir)
		c := a.composeConfig(rt, cf, env)
		imgs := lock.Images(c.cfg)
		for _, svc := range sortedKeys(imgs) {
			ref := imgs[svc]
			if _, ok := pinned[ref]; !ok {
				problems = append(problems, fmt.Sprintf("%s: %s is not in .om/lock.json (om lock)", svc, ref))
			} else if r, ok := running[svc]; ok && !r[pinned[ref]] {
				problems = append(problems, fmt.Sprintf("%s: running image is not the locked %s… (om start)", svc, pinned[ref][:19]))
			}
		}
	}
	for _, p := range problems {
		a.p("  \033[31m✗ %s\033[0m", p)
	}
	if len(problems) == 0 {
		a.p("\033[32m✓ generations chain, signature and running images match the lock.\033[0m")
		return Exit(0)
	}
	a.p("\n  %d problem(s).", len(problems))
	return Exit(1)
}

func (a *App) hardenNetwork(root, wsID, rt string) bool {
	net := wsID + "_net"
	if a.Eng.NetworkIsInternal(rt, net) {
		a.p("\033[32m✓ %s is already internal.\033[0m", net)
		return true
	}
	a.p("\033[1m🔒 Hardening %s\033[0m: services will reach only the hosts in their om.egress label.", net)
	a.cmdStop(root, Namespace{"target": nil}, false)
	for _, c := range []string{state.Router, state.Egress} {
		a.Run([]string{rt, "network", "disconnect", "-f", net, c})
	}
	if r := a.Run([]string{rt, "network", "rm", net}); r.Code != 0 {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		a.p("\033[31m✗ Could not remove %s:\033[0m %s\n  Something outside this workspace still uses it (`%s network inspect %s`). Restarting as it was.", net, lastRunes(py.Strip(out), 400), rt, net)
		a.Eng.ConnectRouter(rt, []string{wsID})
		a.startWorkspace(root, "", false, "start")
		return false
	}
	ok := a.Eng.EnsureNetwork(rt, net, true) && a.Eng.NetworkIsInternal(rt, net)
	a.Eng.ConnectRouter(rt, []string{wsID})
	started, _ := a.startWorkspace(root, "", false, "start")
	ok = started && ok
	if ok {
		a.p("\033[32m✓ %s is internal.\033[0m Blocked calls: `om egress log`.", net)
	} else {
		a.p("\033[31m✗ Hardening %s did not complete — see above.\033[0m", net)
	}
	return ok
}

func (a *App) cmdNetwork(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	rt := a.Runtime()
	if ns.Str("action") == "harden" {
		if a.hardenNetwork(root, wsID, rt) {
			return Exit(0)
		}
		return Exit(1)
	}
	a.p("\n  internet/LAN ─► om_caddy (edge, om_core_net only) ─[token]─► om_router ─► services")
	a.p("  Each folder has its own network: services in different folders cannot reach each other (om.link joins two).")
	proj := a.Eng.ProjectNetworks(rt, wsID)
	for _, net := range append([]string{wsID + "_net"}, proj...) {
		r := a.Run([]string{rt, "ps", "-a", "--filter", "network=" + net, "--format", "{{.Names}}"})
		members := strings.Fields(r.Stdout)
		sort.Strings(members)
		var services []string
		for _, m := range members {
			if m != state.Router && m != state.Egress {
				services = append(services, m)
			}
		}
		if net == wsID+"_net" && len(services) == 0 && len(a.Eng.ProjectNetworks(rt, wsID)) > 0 {
			continue // every folder has its own network; the shared one is empty
		}
		title := "\n\033[1mNETWORK " + net + "\033[0m"
		if net == wsID+"_net" {
			title += "  (shared: om.network=shared)"
		}
		a.p("%s", title)
		a.p("%s", strings.Repeat("═", 78))
		has := setOf(members)
		for _, m := range members {
			role := "service"
			switch m {
			case "om_router":
				role = "router (accepts only edge-signed requests)"
			case "om_egress":
				role = "egress proxy (only listed hosts, per service)"
			}
			a.p("  • %s %s", ljust(m, 28), role)
		}
		if !has["om_router"] {
			a.p("  \033[31m⚠ om_router is not attached — run `om start` or `om core start`.\033[0m")
		}
		if a.Eng.NetworkIsInternal(rt, net) {
			a.p("  \033[32m✓ internal: no way out except om_egress, for services with om.egress\033[0m")
		} else {
			a.p("  \033[33m⚠ open: containers can reach the internet and the LAN — `om network harden`\033[0m")
		}
		if has["om_caddy"] {
			a.p("  \033[31m⚠ om_caddy (edge) is attached to this network — containers can reach the private tier. Run `om core restart`.\033[0m")
		}
	}
	a.p("")
	return nil
}

func (a *App) syncAllowed(root, rev string) bool {
	wsID, _ := workspace.WorkspaceID(root)
	trusted, who := a.Gen.Verify(wsID, root, rev)
	if trusted {
		a.p("  \033[32m✓ incoming %s signed by %s\033[0m", rev, who)
		return true
	}
	if a.Gen.Mode(a.Settings()) == "enforce" {
		a.p("  \033[31m✗ incoming %s: %s. Not pulled (OM_SIGNED=enforce).\033[0m", rev, who)
		return false
	}
	a.p("  \033[33m⚠ incoming %s: %s (OM_SIGNED=warn: syncing anyway).\033[0m", rev, who)
	return true
}

func (a *App) cmdScan(root string) error {
	tool := scan.Scanner(a.LookPath)
	if tool == "" {
		return Die("No scanner found. Install trivy or grype; om ships none (the vulnerability database is theirs).")
	}
	pinned := lock.Read(root)
	if len(pinned) == 0 {
		return Die("Nothing pinned yet: run `om lock` first.")
	}
	for _, ref := range sortedKeys(pinned) {
		fmt.Fprintf(a.Out, "  %s ... ", ref)
		r := a.Run(scan.Command(tool, lock.PinnedRef(ref, pinned[ref])))
		counts, err := scan.Count(tool, r.Stdout)
		if err != nil {
			out := r.Stderr
			if out == "" {
				out = r.Stdout
			}
			a.p("\033[33m⚠ %s failed: %s\033[0m", tool, lastRunes(py.Strip(out), 200))
			continue
		}
		bad := false
		var parts []string
		for _, s := range scan.Severities {
			bad = bad || counts[s] > 0
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], strings.ToLower(s)))
		}
		col := "\033[32m"
		if bad {
			col = "\033[31m"
		}
		a.p("%s%s\033[0m", col, strings.Join(parts, ", "))
	}
	a.p("  (%s; a pin with findings may have a fix: om update --dry-run)", tool)
	return nil
}

func (a *App) cmdPrune(ns Namespace) error {
	rt := a.Runtime()
	locked := map[string]bool{}
	reg := a.Reg.Read()
	for _, d := range reg {
		p, _ := d["path"].(string)
		for _, v := range lock.Read(p) {
			locked[v] = true
		}
	}
	pr := prune.Pruner{Run: a.Run}
	found := pr.Candidates(rt, locked)
	if len(found) == 0 {
		a.p("  No unused images.")
		return nil
	}
	var total float64
	for _, e := range found {
		names := strings.Join(e.Names, ", ")
		if names == "" {
			names = "<untagged>"
		}
		a.p("  %s %s  %s MB", ljust(names, 56), e.ID, rjust(fmt.Sprintf("%.1f", float64(e.Size)/1e6), 8))
		total += float64(e.Size) / 1e6
	}
	if !ns.Bool("yes") {
		a.p("  %d unused image(s), at most %.0f MB (layers shared between images are counted once each). Remove them: om prune --yes   (images of any project on this engine, not only om's)", len(found), total)
		return nil
	}
	var kept []string
	for _, e := range found {
		if !pr.Remove(rt, e) {
			kept = append(kept, e.ID)
		}
	}
	line := fmt.Sprintf("\033[32m✓ Removed %d image(s).\033[0m", len(found)-len(kept))
	if len(kept) > 0 {
		line += fmt.Sprintf(" \033[33mkept (engine refused): %s\033[0m", strings.Join(kept, ", "))
	}
	a.p("%s", line)
	return nil
}

func (a *App) cmdNotify() error {
	chans := a.Notify.ChannelList()
	list := strings.Join(chans, ", ")
	if list == "" {
		list = "none"
	}
	a.p("  Channels (OM_NOTIFY): %s; every message is also appended to %s", list, filepath.Join(a.D.Logs, "notify.log"))
	for _, r := range a.Notify.Notify("om: test", "If you can read this, notifications work.", "") {
		mark := "\033[31m✗\033[0m"
		if r.OK {
			mark = "\033[32m✓\033[0m"
		}
		a.p("  %s %s: %s", mark, r.Channel, r.Detail)
	}
	if len(chans) == 0 {
		a.p("  Notifications are off (OM_NOTIFY=off). Set OM_NOTIFY=auto, or add webhook with OM_NOTIFY_URL=https://ntfy.sh/<topic>, in %s", a.D.UserEnv)
	}
	return nil
}
