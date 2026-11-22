package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/policy"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

func (a *App) readEgressLog(rt, since string) (map[string]map[string]bool, map[string]map[string]bool, error) {
	r := a.Run([]string{rt, "logs", "--since", since, state.Egress})
	if r.Code != 0 {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		return nil, nil, Die("Cannot read %s logs: %s", state.Egress, lastRunes(py.Strip(out), 300))
	}
	log := r.Stdout + "\n" + r.Stderr
	denied, err := a.Egress.DeniedHosts(log, nil)
	if err != nil {
		return nil, nil, Die("%s", err)
	}
	used, err := a.Egress.UsedHosts(log, nil)
	if err != nil {
		return nil, nil, Die("%s", err)
	}
	return denied, used, nil
}

func learningStatus(current string, remaining int64) string {
	switch {
	case current == egress.Audit:
		return "(audit mode — permanent, no expiry)"
	case remaining == -1:
		return "(learning — permanent, no expiry)"
	case remaining > 0:
		return fmt.Sprintf("(learning, %dh %dm left)", remaining/3600, (remaining%3600)/60)
	}
	return "(learning expired — fell back to deny-all)"
}

func (a *App) printEgressNextSteps(root, ws, svc, suggestion string, apply bool, hint string) {
	if apply {
		a.applySuggestionToRoot(root, ws, svc, suggestion)
		return
	}
	a.p("    %s: \033[36mom egress log %s --apply\033[0m", hint, svc)
	a.p("    or set in compose: \033[36mom.egress=%s\033[0m", suggestion)
}

func (a *App) cmdEgress(root string, ns Namespace) error {
	rt := a.Runtime()
	since := ns.Str("since")
	denied, used, err := a.readEgressLog(rt, since)
	if err != nil {
		return err
	}
	onlyWS := ""
	if root != "" && !ns.Bool("all") {
		onlyWS, _ = workspace.WorkspaceID(root)
	}
	target := ""
	for _, t := range ns.List("target") {
		if t != "log" {
			target = t
			break
		}
	}
	apply := ns.Bool("apply")
	users := map[string]bool{}
	for u := range denied {
		users[u] = true
	}
	for u := range used {
		users[u] = true
	}
	shown := 0
	for _, user := range sortedSet(users) {
		ws, svc, _ := strings.Cut(user, ".")
		if (target != "" && !strings.HasSuffix(user, "."+target)) || (onlyWS != "" && ws != onlyWS) {
			continue
		}
		cur, has := a.Egress.LoadRules(ws)[svc]
		learning := has && (cur.Mode == egress.Learn || cur.Mode == egress.Audit)
		hosts := map[string]bool{}
		for h := range used[user] {
			hosts[h] = true
		}
		for h := range denied[user] {
			hosts[h] = true
		}
		sugg := egress.Suggestion(cur, has && !learning, sortedSet(hosts))
		switch {
		case learning:
			status := learningStatus(cur.Mode, a.Egress.LearnRemaining(ws, svc))
			a.p("\n  \033[1m%s/%s\033[0m \033[33m%s\033[0m", ws, svc, status)
			info, _ := a.Egress.LoadLearn(ws, svc)["hosts"].(map[string]any)
			if len(info) > 0 {
				for _, h := range sortedKeys(info) {
					count := 1
					if m, ok := info[h].(map[string]any); ok {
						if c, ok := m["count"]; ok {
							count = int(num(c))
						}
					}
					a.p("    - %s (%d requests)", h, count)
				}
			} else if len(used[user]) > 0 {
				a.p("    used: %s", strings.Join(sortedSet(used[user]), ", "))
			}
			a.printEgressNextSteps(root, ws, svc, sugg, apply, "when done, run")
		case len(denied[user]) > 0:
			a.p("\n  \033[1m%s/%s\033[0m was refused: %s", ws, svc, strings.Join(sortedSet(denied[user]), ", "))
			a.printEgressNextSteps(root, ws, svc, sugg, apply, "to allow, run")
		default:
			continue
		}
		shown++
	}
	if shown == 0 {
		msg := fmt.Sprintf("  Nothing refused or learned in the last %s", since)
		if onlyWS != "" {
			msg += " for workspace " + onlyWS
		}
		a.p("%s.\n  A service without om.egress never reaches the proxy; set `om.egress=learn` (discovery) or `om.egress=audit` (permanent) to record and allow what it uses.", msg)
	}
	a.p("")
	return nil
}

func (a *App) applySuggestionToRoot(root, ws, svc, sugg string) {
	target := ""
	if root != "" {
		if id, err := workspace.WorkspaceID(root); err == nil && id == ws {
			target = root
		}
	}
	if target == "" {
		reg := a.Reg.Read()
		if p, _ := reg[ws]["path"].(string); p != "" {
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				target = p
			}
		}
		if target == "" {
			target = root
		}
	}
	if target == "" {
		a.p("    \033[31m✗ Could not find workspace directory for '%s'\033[0m", ws)
		return
	}
	for _, t := range workspace.DiscoverComposeDirs(target, "") {
		cf, ok := workspace.FindComposeFile(t.Dir)
		if ok && egress.ApplyEgressLabel(cf, svc, strings.Split(sugg, ",")) {
			rel, err := filepath.Rel(target, cf)
			if err != nil || strings.HasPrefix(rel, "..") {
				rel = cf
			}
			a.p("    \033[32m✓ Updated %s:\033[0m om.egress=%s", rel, sugg)
			a.p("      Run 'git diff' to review and 'om start' to apply.")
			return
		}
	}
	a.p("    \033[31m✗ Could not find compose file defining service '%s' in %s\033[0m", svc, target)
}

func (a *App) cmdPolicy(root string, ns Namespace) error {
	rt := a.Runtime()
	type ws struct{ id, root string }
	var roots []ws
	switch {
	case ns.Bool("all"):
		reg := a.Reg.Read()
		for _, id := range sortedKeys(reg) {
			p, _ := reg[id]["path"].(string)
			if _, err := os.Stat(p); err == nil && p != "" {
				roots = append(roots, ws{id, p})
			}
		}
	case root != "":
		id, err := a.wsID(root)
		if err != nil {
			return err
		}
		roots = []ws{{id, root}}
	default:
		return Die("fatal: not an om workspace. Use `om policy check --all` to check every registered workspace.")
	}
	total := 0
	for _, w := range roots {
		env := a.wsEnv(w.root, w.id, rt)
		for _, t := range workspace.DiscoverComposeDirs(w.root, "") {
			cf, _ := workspace.FindComposeFile(t.Dir)
			c := a.composeConfig(rt, cf, env)
			found, waived := policy.EvaluateCompose(c.cfg, c.err, w.id+"_net")
			total += len(found)
			mark := "\033[32m✓\033[0m"
			if len(found) > 0 {
				mark = "\033[31m✗\033[0m"
			}
			rel, err := filepath.Rel(w.root, cf)
			if err != nil {
				rel = cf
			}
			a.p("  %s %s: %s", mark, w.id, rel)
			for _, v := range found {
				a.p("      - %s", v)
			}
			for _, x := range waived {
				a.p("      \033[36m~ allowed by %s: %s\033[0m", policy.AllowLabel, x)
			}
		}
	}
	a.p("\n  %d violation(s); mode: %s (OM_POLICY in %s)", total, policy.Mode(a.Settings()), a.D.UserEnv)
	if total > 0 {
		return Exit(1)
	}
	return Exit(0)
}
