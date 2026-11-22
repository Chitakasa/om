package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/gitsync"
	"github.com/Chitakasa/om/internal/links"
	"github.com/Chitakasa/om/internal/previews"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/routesync"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

func (a *App) previewsDir() string { return filepath.Join(a.D.State, "previews") }

func (a *App) gitOK(args ...string) (int, string, string) { return gitsync.RunGit(args, "") }

func (a *App) listPreviews(base string) {
	reg := a.Reg.Read()
	var ids []string
	for w := range reg {
		if strings.HasPrefix(w, base+"--") {
			ids = append(ids, w)
		}
	}
	sort.Strings(ids)
	a.p("\n\033[1mPREVIEWS of %s\033[0m", base)
	if len(ids) == 0 {
		a.p("  None. `om preview <branch>` runs a branch next to this workspace.\n")
		return
	}
	for _, w := range ids {
		p, _ := reg[w]["path"].(string)
		r := a.Run([]string{"git", "-C", p, "branch", "--show-current"})
		branch := py.Strip(r.Stdout)
		if branch == "" {
			branch = "?"
		}
		a.p("  %s branch %s %s", ljust(w, 36), ljust(branch, 24), p)
	}
	a.p("")
}

// removePreview throws a preview away: containers and their data, routes, ports, networks, generations and the
// worktree.
func (a *App) removePreview(origin, pid, path, branch, rt string) error {
	_, inReg := a.Reg.Read()[pid]
	_, statErr := os.Stat(path)
	exists := statErr == nil
	if !exists && !inReg {
		return Die("No preview %s.", pid)
	}
	if exists {
		env := a.wsEnv(path, pid, rt)
		ts := workspace.DiscoverComposeDirs(path, "")
		for i := len(ts) - 1; i >= 0; i-- {
			cf, _ := workspace.FindComposeFile(ts[i].Dir)
			a.RunIn(workspace.Compose(rt, cf, "down", "-v"), ts[i].Dir, env)
		}
	}
	a.Age.Wipe(pid)
	a.Egress.RenderWorkspace(rt, pid, nil, true, nil)
	a.Reg.Update(func(w registry_Workspaces) error { delete(w, pid); return nil })
	files, _ := filepath.Glob(filepath.Join(a.D.Routes, pid+"-*"))
	for _, f := range files {
		if routesync.RouteOwner(f) == pid {
			os.Remove(f)
		}
	}
	a.Reg.ReleaseSlots(pid)
	a.Core.ReloadCaddy(rt, "", true)
	for _, c := range []string{state.Router, state.Egress} { // attached to every workspace network
		a.Run([]string{rt, "network", "disconnect", pid + "_net", c})
	}
	a.Run([]string{rt, "network", "rm", pid + "_net"})
	a.Net.PruneProjectNetworks(rt, pid, map[string]bool{})
	a.Reg.SetEgressNetworks(pid, nil)
	os.RemoveAll(filepath.Join(a.D.State, "generations", pid))
	if r := a.Run([]string{"git", "-C", origin, "worktree", "remove", "--force", path}); r.Code != 0 {
		os.RemoveAll(path)
		a.Run([]string{"git", "-C", origin, "worktree", "prune"})
	}
	links.Sync(links.Runner(a.Run), rt)
	a.p("\033[32m✓ Preview %s removed\033[0m: containers, data, routes, ports and worktree. The branch %s is kept (git branch -D %s to delete it).", pid, branch, branch)
	return nil
}

func (a *App) createPreviewWorktree(origin, path, pid, base, branch string) error {
	if r := a.Run([]string{"git", "-C", origin, "rev-parse", "--is-inside-work-tree"}); r.Code != 0 {
		return Die("Previews need the workspace to be a git repository (git init).")
	}
	cur := py.Strip(a.Run([]string{"git", "-C", origin, "branch", "--show-current"}).Stdout)
	if cur == branch {
		return Die("%s is checked out here already — `om start` runs it.", branch)
	}
	exists := a.Run([]string{"git", "-C", origin, "rev-parse", "--verify", "--quiet", "refs/heads/" + branch}).Code == 0
	os.MkdirAll(a.previewsDir(), 0o755)
	cmd := []string{"git", "-C", origin}
	if exists {
		cmd = append(cmd, "worktree", "add", path, branch)
	} else {
		cmd = append(cmd, "worktree", "add", "-b", branch, path)
	}
	if r := a.Run(cmd); r.Code != 0 {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		return Die("git worktree failed: %s", lastRunes(py.Strip(out), 300))
	}
	local := py.NewObject()
	local.Set("workspace_id", pid)
	local.Set("preview_of", base)
	workspace.WriteLocal(path, local)
	tail := ""
	if !exists {
		from := cur
		if from == "" {
			from = "HEAD"
		}
		tail = " (new branch from " + from + ")"
	}
	a.p("\033[32m✓ %s checked out as preview %s\033[0m%s", branch, pid, tail)
	return nil
}

func (a *App) startPreview(origin, path, pid, base string, ns Namespace) error {
	branch := ns.Str("branch")
	if _, err := os.Stat(path); err != nil {
		if err := a.createPreviewWorktree(origin, path, pid, base, branch); err != nil {
			return err
		}
	}
	if bad := previews.PreviewPortable(path); len(bad) > 0 {
		return Die("These names would collide with the original workspace; use the variables om sets:\n  %s", strings.Join(bad, "\n  "))
	}
	workspace.Register(a.Reg, path, pid)
	ok, err := a.startWorkspace(path, "", false, "preview")
	if err != nil {
		return err
	}
	if !ok {
		return Die("The preview did not start cleanly; `om preview rm %s` throws it away.", branch)
	}
	a.cmdRoutes(path, ns)
	a.p("  Throw it away: om preview rm %s\n", branch)
	return nil
}

// cmdPreview is `om preview <branch>` (= `start <branch>`); with no branch it lists.
func (a *App) cmdPreview(root string, ns Namespace) error {
	n := Namespace{}
	for k, v := range ns {
		n[k] = v
	}
	if act := n.Str("action"); act != "start" && act != "rm" && act != "list" {
		n["branch"], n["action"] = act, "start"
	}
	if n.Str("action") == "start" && n.Str("branch") == "" {
		n["action"] = "list"
	}
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	base := wsID
	if v, ok := workspace.ReadLocal(root).Get("preview_of"); ok && py.Truthy(v) {
		base = py.Str(v)
	}
	origin := root
	if p, _ := a.Reg.Read()[base]["path"].(string); p != "" {
		origin = p
	}
	branch := n.Str("branch")
	if n.Str("action") == "list" || branch == "" {
		a.listPreviews(base)
		return nil
	}
	if !previews.ValidBranch(branch) {
		return Die("'%s' is not a branch name om will pass to git (letters, digits, . _ / -; no leading -, no ..).", branch)
	}
	pid, err := previews.PreviewID(base, branch)
	if err != nil {
		return Die("%s", err)
	}
	path := filepath.Join(a.previewsDir(), pid)
	if n.Str("action") == "rm" {
		return a.removePreview(origin, pid, path, branch, a.Runtime())
	}
	return a.startPreview(origin, path, pid, base, n)
}

func (a *App) cmdUninstall(ns Namespace) error {
	rt := a.Runtime()
	if !ns.Bool("yes") && !a.Confirm("Stop the Global Core and uninstall om? (workspaces are not touched)") {
		return Die("Aborted.")
	}
	a.Core.Down(rt)
	a.Sched.AutosyncDisable()
	a.Sched.BootDisable()
	home, _ := os.UserHomeDir()
	exe, _ := os.Executable()
	exeReal, _ := filepath.EvalSymlinks(exe)
	for _, name := range []string{"om", "om.cmd", "om.exe"} {
		link := filepath.Join(home, ".local", "bin", name)
		fi, err := os.Lstat(link)
		if err != nil {
			continue
		}
		remove := false
		if fi.Mode()&os.ModeSymlink != 0 {
			if t, err := filepath.EvalSymlinks(link); err == nil && t == exeReal {
				remove = true
			}
		} else if b, err := os.ReadFile(link); err == nil && strings.Contains(string(b), "om-wrapper") {
			remove = true
		}
		if remove {
			if err := os.Remove(link); err != nil {
				a.p("  ⚠ left %s in place: %s", link, err)
			}
		}
	}
	a.p("\033[32m✓ om stopped and unlinked.\033[0m")
	a.p("  Host firewall (if applied) stays active: `om firewall remove` before uninstalling to drop it.")
	if ns.Bool("purge") {
		var targets []string
		for _, p := range []string{a.D.Home, a.D.State} {
			if _, err := os.Stat(p); err == nil {
				targets = append(targets, p)
			}
		}
		shown := strings.Join(append(append([]string{}, targets...), a.D.UserEnv), ", ")
		fmt.Fprintf(a.Out, "Type 'delete' to permanently delete %s (program, local CA, routes, settings): ", shown)
		line, _ := a.In.ReadString('\n')
		if py.Strip(line) == "delete" {
			for _, p := range targets {
				os.RemoveAll(p)
			}
			os.Remove(a.D.UserEnv)
			os.Remove(a.D.Config) // only if empty: the folder may be shared with other tools
			a.p("\033[32m✓ Deleted %s\033[0m", shown)
		}
	}
	return nil
}
