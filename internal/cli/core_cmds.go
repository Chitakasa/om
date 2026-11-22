package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

func (a *App) wsEnv(root, wsID, runtime string) []string {
	return workspace.EnvList(workspace.Env(root, wsID, a.Eng.Info(runtime).Socket))
}

// ensureCoreRunning makes sure the core is up and the router can reach every workspace network.
func (a *App) ensureCoreRunning(runtime, wsID string) error {
	set := map[string]bool{}
	for _, w := range workspace.KnownWorkspaces(a.Reg) {
		set[w] = true
	}
	if wsID != "" {
		set[wsID] = true
	}
	if !a.Core.Running(runtime) {
		a.p("\033[1m🌐 Starting Global Core (edge proxy, router, dashboard)...\033[0m")
		ok, err := a.Core.Up(runtime, false, false)
		if err != nil {
			return Die("%s", err)
		}
		if !ok {
			return Die("Global Core failed to start — run `om doctor` for a diagnosis.")
		}
		a.p("  \033[32m✓ Dashboard online at %s/\033[0m", a.BaseURL(""))
	}
	for _, net := range a.Eng.ConnectRouter(runtime, sortedKeys(set)) {
		a.p("\033[33m⚠ Could not attach to %s\033[0m", net)
	}
	for _, d := range a.Core.RuntimeDrift() {
		a.p("\033[33m⚠ %s\033[0m", d)
	}
	return nil
}

func (a *App) cmdCore(ns Namespace) error {
	rt := a.Runtime()
	switch ns.Str("action") {
	case "start":
		a.p("\033[1m🚀 Starting Global Core...\033[0m")
		ok, err := a.Core.Up(rt, false, false)
		if err != nil {
			return Die("%s", err)
		}
		if !ok {
			return Exit(1)
		}
		if _, err := a.Syncer.PruneOrphanRoutes(rt, true, false, false); err != nil {
			return Die("%s", err)
		}
		a.p("\033[32m✓ Global Core is live: %s/\033[0m", a.BaseURL(""))
	case "stop":
		a.p("\033[1m🛑 Stopping Global Core...\033[0m")
		if _, err := a.Core.Down(rt); err != nil {
			return Die("%s", err)
		}
		a.p("\033[32m✓ Global Core stopped.\033[0m")
	case "restart":
		if len(ns.List("services")) > 0 {
			return a.coreRestartContainers(rt, ns.List("services"))
		}
		a.p("\033[1m🔄 Restarting Global Core...\033[0m")
		ok, err := a.Core.Up(rt, true, false)
		if err != nil {
			return Die("%s", err)
		}
		if !ok {
			return Exit(1)
		}
		a.Syncer.PruneOrphanRoutes(rt, true, false, false)
		a.p("\033[32m✓ Global Core restarted.\033[0m")
	case "update":
		a.p("\033[1m⬇ Pulling Global Core images...\033[0m")
		if _, err := a.Core.WriteRuntimeFiles(rt); err != nil {
			return Die("%s", err)
		}
		if cmd, err := a.Core.CoreCompose(rt, "pull", "caddy", "router", "sockguard", "dashboard"); err == nil { // om_egress is built locally
			a.Passthrough(cmd, a.D.Core, nil)
		}
		ok, err := a.Core.Up(rt, false, false)
		if err != nil {
			return Die("%s", err)
		}
		if !ok {
			return Exit(1)
		}
		a.p("\033[32m✓ Global Core updated.\033[0m")
	case "reload":
		removed, err := a.Syncer.PruneOrphanRoutes(rt, true, false, false)
		if err != nil {
			return Die("%s", err)
		}
		if len(removed) == 0 {
			a.Core.ReloadCaddy(rt, "", false)
		}
	case "watch":
		return Exit(a.Core.Watch(rt, -1))
	case "heal":
		return a.coreHeal(rt)
	default:
		a.coreStatus(rt)
	}
	return nil
}

func (a *App) coreRestartContainers(rt string, names []string) error {
	var full []string
	for _, n := range names {
		full = append(full, "om_"+strings.TrimPrefix(n, "om_"))
	}
	var bad []string
	for _, n := range full {
		found := false
		for _, c := range state.CoreContainers {
			found = found || c == n
		}
		if !found {
			bad = append(bad, n)
		}
	}
	if len(bad) > 0 {
		var known []string
		for _, k := range state.CoreContainers {
			known = append(known, k[3:])
		}
		return Die("Unknown core container(s): %s (known: %s)", strings.Join(bad, ", "), strings.Join(known, ", "))
	}
	// Lifecycle: on local Podman om first matches the healthcheck timers' oom_score_adj
	a.Passthrough(a.Eng.Lifecycle(rt, append([]string{"restart"}, full...)...), "", nil)
	var down []string
	for _, n := range full {
		if !a.Eng.ContainerRunning(rt, n) {
			down = append(down, n)
		}
	}
	if len(down) > 0 { // a runtime hiccup (e.g. conmon killed) can leave it exited: start it once
		a.Passthrough(a.Eng.Lifecycle(rt, append([]string{"start"}, down...)...), "", nil)
		var still []string
		for _, n := range down {
			if !a.Eng.ContainerRunning(rt, n) {
				still = append(still, n)
			}
		}
		down = still
	}
	if len(down) > 0 {
		return Die("Could not bring up %s — see `%s logs %s`.", strings.Join(down, ", "), rt, down[0])
	}
	a.p("\033[32m✓ Restarted %s.\033[0m", strings.Join(full, ", "))
	return nil
}

func (a *App) coreHeal(rt string) error {
	done, err := a.Core.Heal(rt)
	if err != nil {
		return Die("%s", err)
	}
	// What heal had to fix (not the one-run wait before an address change): at most once an hour per message
	var fixed []string
	for _, n := range strings.Split(done, "; ") {
		if n != "" && !strings.Contains(n, "waiting one more run") {
			fixed = append(fixed, n)
		}
	}
	if len(fixed) > 0 {
		joined := strings.Join(fixed, "; ")
		a.Notify.Notify("om core", joined, fmt.Sprintf("heal:%s:%d", joined, a.Now().Unix()/3600))
	}
	done = a.announceImageUpdates(done)
	if done != "" {
		os.MkdirAll(a.D.Logs, 0o755)
		if f, err := os.OpenFile(filepath.Join(a.D.Logs, "heal.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(f, "[%s] %s\n", a.Now().Format("2006-01-02 15:04:05"), done)
			f.Close()
		}
		a.p("%s", done)
	}
	return nil
}

// announceImageUpdates looks for newer images at most every 6 hours (`om status` shows the result), notifies, and
// extends done.
func (a *App) announceImageUpdates(done string) string {
	reg := a.Reg.Read()
	for _, wid := range sortedKeys(reg) {
		p, _ := reg[wid]["path"].(string)
		ws := p
		if st, err := os.Stat(filepath.Join(ws, ".om", "config.json")); err != nil || st.IsDir() {
			continue
		}
		_, checked := a.cachedUpdates(wid)
		if float64(a.Now().Unix())-checked > 6*3600 {
			ups := a.availableUpdates(ws, "")
			if n := len(ups); n > 0 {
				if done != "" {
					done += "; "
				}
				done += fmt.Sprintf("%s: %d image update(s) available", wid, n)
				refs := sortedKeys(ups)
				var keyParts []string
				for _, r := range refs {
					keyParts = append(keyParts, r+"="+ups[r][1])
				}
				a.Notify.Notify("om: "+wid, fmt.Sprintf("%d image update(s) available: %s. Run: om update --dry-run", n, strings.Join(refs, ", ")),
					"updates:"+wid+":"+strings.Join(keyParts, ","))
			}
		}
	}
	return done
}

func (a *App) coreStatus(rt string) {
	a.p("\n\033[1mGLOBAL CORE\033[0m  (om %s, %s)", state.Version, rt)
	a.p("%s", strings.Repeat("═", 78))
	roles := [][2]string{{"om_caddy", "Edge proxy (front door)"}, {"om_router", "Internal router"}, {"om_egress", "Outbound allow-list proxy"},
		{"om_sockguard", "Read-only engine filter"}, {"om_stream_edge", "Raw TCP edge"}, {"om_stream_router", "Raw TCP router"},
		{"om_dashboard", "Universal dashboard"}}
	for _, r := range roles {
		st := "\033[31m⏹ Stopped\033[0m"
		if a.Eng.ContainerRunning(rt, r[0]) {
			st = "\033[32m🟢 Running\033[0m"
		}
		a.p("  %-16s %-26s %s", r[0], r[1], st)
	}
	env, _ := state.ParseEnvFile(a.D.RuntimeEnv)
	vpn := a.vpnHosts()
	line := "\n  Private tier: " + a.BaseURL("") + "/"
	if len(vpn) > 0 {
		line += "  ·  VPN " + a.BaseURL(vpn[len(vpn)-1]) + "/"
	}
	a.p("%s", line)
	if lan := env["LAN_IP"]; lan != "" && !strings.HasSuffix(lan, ".invalid") {
		line = "  Public tier:  " + a.BaseURL(lan) + "/"
		if len(vpn) > 0 {
			line += "  ·  VPN http://" + vpn[len(vpn)-1] + ":8080/"
		}
		a.p("%s", line)
	}
	for _, d := range a.Core.RuntimeDrift() {
		a.p("  \033[33m⚠ %s\033[0m", d)
	}
	a.p("")
}

func (a *App) vpnHosts() []string { return settingsVPNHosts(a.D) }

// stringSet helpers shared by the command files.
func setOf(l []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range l {
		m[x] = true
	}
	return m
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
