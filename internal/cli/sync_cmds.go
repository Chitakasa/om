package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/gitsync"
	"github.com/Chitakasa/om/internal/lock"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/workspace"
)

const autoUpdateEvery = 6 * 3600

func (a *App) cmdSync(root string, ns Namespace) error {
	if ns.Bool("scheduled") {
		return Exit(a.scheduledSync())
	}
	if root == "" {
		return Die("fatal: not an om workspace. cd into one, or use `om sync --scheduled`.")
	}
	ok := a.syncWorkspaceAt(root, a.trackedBranch(root), ns.Bool("force"), ns.Bool("rebase"))
	if ok {
		return Exit(0)
	}
	return Exit(1)
}

func (a *App) syncWorkspaceAt(root, branch string, force, rebase bool) bool {
	return a.gitSync().SyncWorkspace(root, branch, force, rebase,
		func(kind string) { a.startWorkspace(root, "", true, kind) },
		func(rev string) bool { return a.syncAllowed(root, rev) })
}

// autoUpdate moves the images only om.update=auto services use to their newest digests, redeploys, and undoes it if
// the health check fails. A digest that failed is not retried. Returns log lines.
func (a *App) autoUpdate(root string, st map[string]any) []string {
	wsID, _ := workspace.WorkspaceID(root)
	_, _, auto, _ := a.workspaceImages(root, "", false)
	failed, _ := st["auto_failed"].(map[string]any)
	if failed == nil {
		failed = map[string]any{}
		st["auto_failed"] = failed
	}
	ups := map[string][2]string{}
	for ref, d := range a.availableUpdates(root, "") {
		if auto[ref] && py.Str(failed[ref]) != d[1] {
			ups[ref] = d
		}
	}
	if len(ups) == 0 {
		return nil
	}
	oldLock := lock.Read(root)
	only := map[string]bool{}
	for r := range ups {
		only[r] = true
	}
	old, new, err := a.lockWorkspace(root, "", true, only)
	if err != nil {
		return []string{"auto-update aborted: " + err.Error()}
	}
	var moved []string
	for _, r := range sortedKeys(ups) {
		if old[r] != new[r] {
			moved = append(moved, r)
		}
	}
	if len(moved) == 0 {
		return nil
	}
	a.commitLock(root, "om update (auto): "+strings.Join(moved, ", "))
	if _, out, _ := gitsync.RunGit([]string{"status", "--porcelain", "--", lock.Name}, root); py.Strip(out) != "" {
		lock.Write(root, oldLock)
		return []string{"auto-update aborted: could not commit .om/lock.json, pins restored"}
	}
	var parts []string
	for _, r := range moved {
		from := "unpinned"
		if v, ok := old[r]; ok {
			from = v[7:19]
		}
		parts = append(parts, fmt.Sprintf("%s %s → %s", r, from, new[r][7:19]))
	}
	names := strings.Join(parts, ", ")
	if ok, _ := a.startWorkspace(root, "", false, "update"); ok && a.gitSync().SyntheticHealthCheck(a.gitSync().WorkspaceVhosts(wsID), 60*time.Second) {
		for _, r := range moved {
			delete(failed, r)
		}
		return []string{"auto-updated " + names}
	}
	for _, r := range moved {
		failed[r] = new[r]
	}
	if c, _, _ := gitsync.RunGit([]string{"revert", "--no-edit", "HEAD"}, root); c != 0 {
		lock.Write(root, oldLock)
		return []string{fmt.Sprintf("auto-update of %s FAILED its health check; could not revert the lock commit, pins restored in the working tree", names)}
	}
	redeployed, _ := a.startWorkspace(root, "", false, "rollback")
	tail := ""
	if !redeployed {
		tail = ", redeploy of the previous images FAILED too"
	}
	return []string{fmt.Sprintf("auto-update of %s FAILED its health check; lock reverted%s", names, tail)}
}

func readSyncState(root string) map[string]any {
	b, err := os.ReadFile(filepath.Join(root, ".om", "state.json"))
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&m) != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func writeSyncState(root string, st map[string]any) {
	b, _ := json.Marshal(st)
	os.WriteFile(filepath.Join(root, ".om", "state.json"), b, 0o644)
}

func num(v any) float64 {
	switch n := v.(type) {
	case json.Number:
		f, _ := n.Float64()
		return f
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case float64:
		return n
	}
	return 0
}

func gitOut(root string, args ...string) string {
	_, out, _ := gitsync.RunGit(args, root)
	return py.Strip(out)
}

var ansiLineRE = regexp.MustCompile("\033\\[[0-9;]*m")

func (a *App) syncAndLog(wsID, root, branch string, emit func(string)) bool {
	emit(wsID + ": syncing")
	var buf bytes.Buffer
	saved := a.Out
	a.Out = &buf
	gs := a.gitSync()
	gs.Out = &buf
	ok := gs.SyncWorkspace(root, branch, false, false,
		func(kind string) { a.startWorkspace(root, "", true, kind) },
		func(rev string) bool { return a.syncAllowed(root, rev) })
	a.Out = saved
	for _, line := range py.SplitLines(buf.String()) {
		emit(wsID + ": " + ansiLineRE.ReplaceAllString(line, ""))
	}
	return ok
}

func (a *App) recordSyncResult(wsID, root, branch, remote string, ok bool, st map[string]any, emit func(string)) {
	if ok {
		delete(st, "quarantined")
	} else if remote != "" && gitOut(root, "rev-parse", "HEAD") != remote {
		st["quarantined"] = remote
		emit(fmt.Sprintf("%s: remote %s quarantined until a new commit is pushed", wsID, remote[:8]))
	}
	if !ok {
		q := ""
		if remote != "" && st["quarantined"] == remote {
			q = fmt.Sprintf("; remote %s is quarantined until a new commit is pushed", remote[:8])
		}
		key := remote
		if key == "" {
			key = "local"
		}
		a.Notify.Notify("om: "+wsID, fmt.Sprintf("sync of %s failed%s (see %s)", branch, q, filepath.Join(a.D.Logs, "autosync.log")), "sync:"+wsID+":"+key)
	}
	if ok {
		st["last_result"] = "ok"
	} else {
		st["last_result"] = "failed"
	}
}

func (a *App) scheduledAutoUpdate(wsID, root string, st map[string]any, emit func(string)) {
	st["last_auto_update"] = a.Now().Unix()
	saved := a.Out
	a.Out = io.Discard
	lines := a.autoUpdate(root, st)
	a.Out = saved
	for _, l := range lines {
		emit(wsID + ": " + l)
		a.Notify.Notify("om: "+wsID, l, "auto:"+wsID+":"+l)
	}
	for _, l := range lines {
		if strings.Contains(l, "FAILED") || strings.Contains(l, "aborted") {
			st["last_result"] = "auto-update failed"
		}
	}
}

type gitopsSettings struct {
	autoSync bool
	interval int
}

func gitopsOf(root string) gitopsSettings {
	g := gitopsSettings{interval: 300}
	if m, ok := workspace.ReadLocal(root).Get("gitops"); ok {
		if mm, ok := m.(map[string]any); ok {
			g.autoSync = py.Truthy(mm["auto_sync"])
			if v, ok := mm["interval_seconds"]; ok && num(v) > 0 {
				g.interval = int(num(v))
			}
		}
	}
	return g
}

// syncOneWorkspace returns nil when the workspace is not due (or skipped), else whether it succeeded.
func (a *App) syncOneWorkspace(wsID, root string, g gitopsSettings, emit func(string)) *bool {
	workspace.HideLocalFiles(root)
	st := readSyncState(root)
	every := g.interval
	if every < 60 {
		every = 60
	}
	if float64(a.Now().Unix())-num(st["last_sync"]) < float64(every) {
		return nil
	}
	st["last_sync"] = a.Now().Unix()
	branch := a.trackedBranch(root)
	if gitOut(root, "status", "--porcelain") != "" {
		emit(fmt.Sprintf("%s: skipped — uncommitted changes in %s", wsID, root))
		st["last_result"] = "skipped (dirty)"
		writeSyncState(root, st)
		return nil
	}
	gitOut(root, "fetch", "-q", "origin", branch)
	remote := gitOut(root, "rev-parse", "--verify", "-q", "origin/"+branch)
	if remote != "" && remote == st["quarantined"] {
		st["last_result"] = fmt.Sprintf("skipped (remote %s quarantined)", remote[:8])
		writeSyncState(root, st)
		return nil
	}
	ok := a.syncAndLog(wsID, root, branch, emit)
	a.recordSyncResult(wsID, root, branch, remote, ok, st, emit)
	if ok && float64(a.Now().Unix())-num(st["last_auto_update"]) >= autoUpdateEvery {
		a.scheduledAutoUpdate(wsID, root, st, emit)
	}
	writeSyncState(root, st)
	return &ok
}

func (a *App) scheduledSync() int {
	os.MkdirAll(a.D.Logs, 0o755)
	f, err := os.OpenFile(filepath.Join(a.D.Logs, "autosync.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 1
	}
	defer f.Close()
	emit := func(msg string) { fmt.Fprintf(f, "[%s] %s\n", a.Now().Format("2006-01-02 15:04:05"), msg) }
	rc := 0
	reg := a.Reg.Read()
	for _, id := range sortedKeys(reg) {
		root, _ := reg[id]["path"].(string)
		var g gitopsSettings
		if _, err := os.Stat(root); err == nil && root != "" {
			g = gitopsOf(root)
		}
		if !g.autoSync {
			continue
		}
		if r := a.syncOneWorkspace(id, root, g, emit); r != nil && !*r {
			rc = 1
		}
	}
	return rc
}

func (a *App) cmdAutosync(root string, ns Namespace) error {
	action := ns.Str("action")
	if action == "status" {
		a.p("  Scheduler: %s", a.Sched.AutosyncStatus())
		reg := a.Reg.Read()
		for _, id := range sortedKeys(reg) {
			r, _ := reg[id]["path"].(string)
			g := gopsDefault()
			if _, err := os.Stat(r); err == nil && r != "" {
				g = gitopsOf(r)
			}
			last := "never"
			st := readSyncState(r)
			if _, ok := st["last_sync"]; ok {
				last = time.Unix(int64(num(st["last_sync"])), 0).Format("2006-01-02 15:04") + fmt.Sprintf(" (%s)", py.Str(st["last_result"]))
			}
			on := "off"
			if g.autoSync {
				on = "on "
			}
			a.p("  %s auto_sync=%s every %ds  last: %s", ljust(id, 20), on, g.interval, last)
		}
		a.p("  Log: %s", filepath.Join(a.D.Logs, "autosync.log"))
		return nil
	}
	if root == "" {
		return Die("Run inside a workspace: `om autosync on|off` applies to the current workspace.")
	}
	local := workspace.ReadLocal(root)
	g, _ := func() (map[string]any, bool) {
		v, ok := local.Get("gitops")
		m, ok2 := v.(map[string]any)
		return m, ok && ok2
	}()
	if g == nil {
		g = map[string]any{}
	}
	wsID, _ := workspace.WorkspaceID(root)
	if action == "on" {
		if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
			return Die("This workspace is not a git repository (git init && git remote add origin <url>).")
		}
		g["auto_sync"] = true
		if e := ns.Int("every"); e != 0 {
			m := e * 60
			if m < 60 {
				m = 60
			}
			g["interval_seconds"] = m
		}
		local.Set("gitops", g)
		workspace.WriteLocal(root, local)
		if a.Sched.AutosyncStatus() != "active" {
			a.Sched.AutosyncEnable(1)
		}
		a.p("\033[32m✓ Auto-sync on for %s on this machine (every %ds).\033[0m", wsID, gitopsOf(root).interval)
		return nil
	}
	g["auto_sync"] = false
	local.Set("gitops", g)
	workspace.WriteLocal(root, local)
	still := false
	for _, d := range a.Reg.Read() {
		p, _ := d["path"].(string)
		if _, err := os.Stat(p); err == nil && gitopsOf(p).autoSync {
			still = true
		}
	}
	if !still {
		a.Sched.AutosyncDisable()
	}
	a.p("\033[32m✓ Auto-sync off for %s.\033[0m", wsID)
	return nil
}

func gopsDefault() gitopsSettings { return gitopsSettings{interval: 300} }

func (a *App) cmdReload(root string, ns Namespace) error {
	rt := a.Runtime()
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	a.Syncer.SyncCaddyRoutes(root, rt, false, nil)
	a.Core.ReloadCaddy(rt, wsID, false)
	return nil
}

func (a *App) cmdDrift(root string, ns Namespace) error {
	a.gitSync().PrintDriftReport(root, a.trackedBranch(root))
	return nil
}
