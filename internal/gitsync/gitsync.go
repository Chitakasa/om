// Package gitsync is the GitOps and drift reconciliation engine: Git drift detection, pull reconciliation,
// synthetic health checks and automated rollbacks. Port of lib/gitops/engine.py. Everything Python prints goes
// to Out.
package gitsync

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/py"
)

// Sync carries what the engine needs. Use New for the real thing.
type Sync struct {
	Out io.Writer
	// Ingress is the private ingress URL the health probe asks (settings.BaseURL("127.0.0.1")).
	Ingress string
	// RoutesDir holds the generated route files (the vhosts to probe).
	RoutesDir string
	// Health probes hosts until none is unhealthy or the timeout passes; it replaces the HTTP probe in tests.
	Health func(hosts []string) bool
	// Now and Sleep drive the health probe's deadline.
	Now   func() time.Time
	Sleep func(time.Duration)
}

// New returns a Sync that prints to out.
func New(out io.Writer, ingress, routesDir string) *Sync {
	s := &Sync{Out: out, Ingress: ingress, RoutesDir: routesDir, Now: time.Now, Sleep: time.Sleep}
	s.Health = func(hosts []string) bool { return s.SyntheticHealthCheck(hosts, 60*time.Second) }
	return s
}

func (s *Sync) p(format string, a ...any) { fmt.Fprintf(s.Out, format+"\n", a...) }

// RunGit runs git in cwd and returns (code, stdout, stderr), both stripped.
func RunGit(args []string, cwd string) (int, string, string) {
	c := exec.Command("git", args...)
	c.Dir = cwd
	var o, e bytes.Buffer
	c.Stdout, c.Stderr = &o, &e
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), clean(o.String()), clean(e.String())
		}
		return 1, "", err.Error()
	}
	return 0, clean(o.String()), clean(e.String())
}

func clean(s string) string { return py.Strip(py.UniversalNewlines(strings.ToValidUTF8(s, "\uFFFD"))) }

// Drift is a workspace compared with its remote branch.
type Drift struct {
	Status     string // NO_GIT, NO_REMOTE, UP-TO-DATE, AHEAD, BEHIND, DIVERGED
	Message    string
	Branch     string
	LocalHash  string
	LocalMsg   string
	RemoteHash string
	RemoteMsg  string
	Ahead      int
	Behind     int
	Dirty      bool
}

func short(h, empty string) string {
	if h == "" {
		return empty
	}
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// InspectDrift analyzes Git drift against the remote branch.
func InspectDrift(root, branch string) Drift {
	if code, _, _ := RunGit([]string{"rev-parse", "--is-inside-work-tree"}, root); code != 0 {
		return Drift{Status: "NO_GIT", Message: "Workspace is not a Git repository."}
	}
	RunGit([]string{"fetch", "origin", branch}, root) // silently
	_, localHash, _ := RunGit([]string{"rev-parse", "HEAD"}, root)
	_, localMsg, _ := RunGit([]string{"log", "-1", "--format=%s", "HEAD"}, root)
	codeR, remoteHash, _ := RunGit([]string{"rev-parse", "origin/" + branch}, root)
	_, remoteMsg, _ := RunGit([]string{"log", "-1", "--format=%s", "origin/" + branch}, root)
	if codeR != 0 {
		return Drift{Status: "NO_REMOTE", LocalHash: short(localHash, "none"), Message: "No remote branch 'origin/" + branch + "' found."}
	}
	_, counts, _ := RunGit([]string{"rev-list", "--left-right", "--count", "HEAD...origin/" + branch}, root)
	ahead, behind := 0, 0
	if f := py.Fields(counts); len(f) == 2 {
		ahead, _ = strconv.Atoi(f[0])
		behind, _ = strconv.Atoi(f[1])
	}
	_, status, _ := RunGit([]string{"status", "--porcelain"}, root)
	st := "UP-TO-DATE"
	switch {
	case ahead > 0 && behind > 0:
		st = "DIVERGED"
	case ahead > 0:
		st = "AHEAD"
	case behind > 0:
		st = "BEHIND"
	}
	if localMsg == "" {
		localMsg = "No commit"
	}
	if remoteMsg == "" {
		remoteMsg = "No commit"
	}
	return Drift{Status: st, Branch: branch, LocalHash: short(localHash, "unknown"), LocalMsg: localMsg,
		RemoteHash: short(remoteHash, "unknown"), RemoteMsg: remoteMsg, Ahead: ahead, Behind: behind, Dirty: py.Strip(status) != ""}
}

func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// PrintDriftReport prints a clear, actionable drift report for devs and non-devs.
func (s *Sync) PrintDriftReport(root, branch string) {
	info := InspectDrift(root, branch)
	s.p("\n\033[1mREMOTE GITOPS STATE (Branch: %s)\033[0m", branch)
	s.p("%s", strings.Repeat("═", 78))
	switch info.Status {
	case "NO_GIT":
		s.p("  \033[33mℹ Workspace is local-only (not a Git repository).\033[0m")
		s.p("  To connect to GitOps: git init && git remote add origin <url>\n")
		return
	case "NO_REMOTE":
		s.p("  Local Commit:   %s", info.LocalHash)
		s.p("  \033[33mℹ No remote branch origin/%s tracked yet.\033[0m\n", branch)
		return
	}
	s.p("  Local Commit:   %s (\"%s\")", info.LocalHash, firstRunes(info.LocalMsg, 45))
	s.p("  Remote Commit:  %s (\"%s\")", info.RemoteHash, firstRunes(info.RemoteMsg, 45))
	if info.Dirty {
		s.p("  Working Tree:   \033[33m⚠ Uncommitted local changes detected\033[0m")
	} else {
		s.p("  Working Tree:   \033[32mClean\033[0m")
	}
	fmt.Fprint(s.Out, "\n  STATUS: ")
	switch info.Status {
	case "UP-TO-DATE":
		s.p("\033[32m✓ UP-TO-DATE (Local system matches remote truth)\033[0m\n")
	case "BEHIND":
		s.p("\033[33m⬇ BEHIND by %d commit(s) (New updates available on remote)\033[0m", info.Behind)
		s.p("\n  HOW TO RESOLVE:")
		s.p("  • Run: \033[1mom sync\033[0m")
		s.p("    Pulls new updates and gracefully reconciles services with health verification.\n")
	case "AHEAD":
		s.p("\033[36m⬆ AHEAD by %d commit(s) (Local commits ready to publish)\033[0m", info.Ahead)
		s.p("\n  HOW TO RESOLVE:")
		s.p("  • Run: \033[1mgit push origin %s\033[0m", branch)
		s.p("    Publishes your changes so teammates or backups stay synchronized.\n")
	case "DIVERGED":
		s.p("\033[31m⚠ DIVERGED (History Mismatch: %d ahead, %d behind)\033[0m", info.Ahead, info.Behind)
		s.p("\n  HOW TO RESOLVE:")
		s.p("  • Option 1 (Recommended - Rebase Local on Remote):")
		s.p("      Run: \033[1mom sync --rebase\033[0m (Applies remote updates, replays local work)")
		s.p("  • Option 2 (Discard Local & Align with Remote Truth):")
		s.p("      Run: \033[1mom sync --force\033[0m (Resets local state strictly to remote commit)\n")
	}
}

// WorkspaceVhosts returns the hostnames of this workspace's generated Caddy vhosts (plus its dashboard).
func (s *Sync) WorkspaceVhosts(ws string) []string {
	hosts := []string{ws + ".dashboard.localhost"}
	files, _ := filepath.Glob(filepath.Join(s.RoutesDir, ws+"-*.caddy"))
	sort.Strings(files)
	for _, f := range files {
		text, err := py.ReadText(f)
		if err != nil {
			continue
		}
		for _, line := range py.SplitLines(text) {
			line = py.Strip(line)
			if strings.HasPrefix(line, "http://"+ws+".") && strings.HasSuffix(line, "{") {
				hosts = append(hosts, py.Strip(line[len("http://"):len(line)-1]))
				break
			}
		}
	}
	return hosts
}

// SyntheticHealthCheck probes each vhost through the private ingress until none returns a 5xx (or the timeout
// expires). A 401 (private-tier login enabled) counts as healthy: the proxy and upstream answered.
func (s *Sync) SyntheticHealthCheck(hosts []string, timeout time.Duration) bool {
	deadline := s.Now().Add(timeout)
	pending := append([]string(nil), hosts...)
	client := &http.Client{Timeout: 3 * time.Second}
	for len(pending) > 0 && s.Now().Before(deadline) {
		var failing []string
		for _, host := range pending {
			req, err := http.NewRequest("GET", s.Ingress+"/", nil)
			if err != nil {
				failing = append(failing, host)
				continue
			}
			req.Host = host
			req.Header.Set("User-Agent", "om-healthcheck/1.0")
			resp, err := client.Do(req)
			if err != nil {
				failing = append(failing, host)
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				failing = append(failing, host)
			}
		}
		pending = failing
		if len(pending) > 0 {
			wait := deadline.Sub(s.Now())
			if wait > 2*time.Second {
				wait = 2 * time.Second
			}
			if wait < 0 {
				wait = 0
			}
			s.Sleep(wait)
		}
	}
	for _, host := range pending {
		s.p("  \033[31m✗ %s unhealthy\033[0m", host)
	}
	return len(pending) == 0
}

// pull brings the working tree to origin/<branch> (reset, rebase or fast-forward); false, with the reason shown,
// if it fails.
func (s *Sync) pull(root, branch string, force, rebase bool) bool {
	if force {
		s.p("  Forcing alignment to remote truth...")
		code, _, err := RunGit([]string{"reset", "--hard", "origin/" + branch}, root)
		if code != 0 {
			s.p("\033[31m❌ Reset failed:\033[0m %s", err)
		}
		return code == 0
	}
	if rebase {
		code, _, err := RunGit([]string{"rebase", "origin/" + branch}, root)
		if code != 0 {
			s.p("\033[31m❌ Rebase conflict! Run 'git rebase --abort':\033[0m %s", err)
		}
		return code == 0
	}
	code, _, err := RunGit([]string{"pull", "--ff-only", "origin", branch}, root)
	if code != 0 {
		s.p("\033[31m❌ Fast-forward pull failed:\033[0m %s", err)
		s.p("  Run 'om drift' to inspect history mismatch.")
	}
	return code == 0
}

// workspaceID is the workspace id; a preview's own id lives in its machine-local .om/local.json.
func workspaceID(root string, cfg *py.Object) string {
	if b, err := os.ReadFile(filepath.Join(root, ".om", "local.json")); err == nil {
		if o, err := py.ParseObject(b); err == nil {
			if v, ok := o.Get("workspace_id"); ok && py.Truthy(v) {
				return py.Str(v)
			}
		}
	}
	if v, ok := cfg.Get("workspace_id"); ok {
		return py.Str(v)
	}
	return strings.ToLower(filepath.Base(root))
}

func readConfig(root string) *py.Object {
	if b, err := os.ReadFile(filepath.Join(root, ".om", "config.json")); err == nil {
		if o, err := py.ParseObject(b); err == nil {
			return o
		}
	}
	return py.NewObject()
}

func autoRollback(cfg *py.Object) bool {
	if g, ok := cfg.Get("gitops"); ok {
		if o, ok := g.(*py.Object); ok {
			if v, ok := o.Get("auto_rollback"); ok {
				return py.Truthy(v)
			}
		}
	}
	return true
}

// rollBack returns to the commit that was running and redeploys it, unless the tree was edited meanwhile.
func (s *Sync) rollBack(root, prevHead string, reconcile func(kind string)) {
	if _, dirty, _ := RunGit([]string{"status", "--porcelain"}, root); py.Strip(dirty) != "" { // edited while the probe ran
		s.p("\033[31m❌ Uncommitted changes appeared during the update; not rolling back automatically.\033[0m")
		s.p("  Roll back by hand when ready: git reset --hard %s", short(prevHead, ""))
		return
	}
	s.p("\033[33m⏪ Auto-Rollback triggered: Reverting to %s...\033[0m", short(prevHead, ""))
	RunGit([]string{"reset", "--hard", prevHead}, root)
	if reconcile != nil {
		reconcile("rollback")
	}
	s.p("\033[32m✓ Rolled back to last known good state.\033[0m")
}

// SyncWorkspace pulls remote state, reconciles containers/routes via reconcile(kind), and rolls back if unhealthy.
// verify(rev) is asked before anything is pulled; false refuses the incoming commit. Both may be nil.
func (s *Sync) SyncWorkspace(root, branch string, force, rebase bool, reconcile func(kind string), verify func(rev string) bool) bool {
	s.p("\033[1m🔄 Initiating GitOps Reconciliation on %s...\033[0m", branch)
	// Both --force and the auto-rollback use `git reset --hard`, which would silently destroy uncommitted work, so
	// a dirty tree is never synced.
	if _, st, _ := RunGit([]string{"status", "--porcelain"}, root); py.Strip(st) != "" {
		s.p("\033[31m❌ Uncommitted changes in workspace; refusing to sync.\033[0m")
		s.p("  Commit or stash them first (see 'git status').")
		return false
	}
	if code, _, err := RunGit([]string{"fetch", "origin", branch}, root); code != 0 {
		s.p("\033[31m❌ Git fetch failed:\033[0m %s", err)
		return false
	}
	if verify != nil && !verify("origin/"+branch) {
		return false
	}
	_, prevHead, _ := RunGit([]string{"rev-parse", "HEAD"}, root) // the rollback anchor
	if !s.pull(root, branch, force, rebase) {
		return false
	}
	_, newHead, _ := RunGit([]string{"rev-parse", "HEAD"}, root)
	if prevHead == newHead {
		s.p("\033[32m✓ System already matches remote state. Zero drift detected.\033[0m")
		return true
	}
	s.p("\033[32m✓ Successfully pulled updates (%s ──► %s)\033[0m", short(prevHead, ""), short(newHead, ""))
	// Apply the new state (compose up + route regeneration) and verify it
	cfg := readConfig(root)
	ws := workspaceID(root, cfg)
	if reconcile != nil {
		reconcile("sync")
	}
	s.p("  Running synthetic health probe on Caddy ingress...")
	if s.Health(s.WorkspaceVhosts(ws)) {
		s.p("\033[32m✓ Reconciliation complete: System healthy and verified.\033[0m")
		return true
	}
	s.p("\033[31m❌ Health check failed after update!\033[0m")
	if autoRollback(cfg) && prevHead != "" {
		s.rollBack(root, prevHead, reconcile)
	}
	return false
}
