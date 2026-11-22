package cli

import (
	"os"
	"path/filepath"

	"github.com/Chitakasa/om/internal/py"
)

// cmdUpgrade brings om itself up to date: it fast-forwards the checkout om lives in, rebuilds through the installer
// (which refreshes the scheduled jobs and restarts the watcher and the dashboard) and says what is left to restart.
// It never discards anything: a checkout with uncommitted changes, or one that cannot fast-forward, is left alone.
func (a *App) cmdUpgrade(ns Namespace) error {
	home := a.D.Home
	git, err := a.LookPath("git")
	if err != nil {
		return Die("om upgrade needs git: it updates the checkout in %s.", home)
	}
	if _, err := os.Stat(filepath.Join(home, ".git")); err != nil {
		return Die("%s is not a git checkout, so there is nothing to pull into. Clone it (git clone https://github.com/Chitakasa/om %s) or download a newer release.", home, home)
	}
	g := func(args ...string) (string, string) {
		r := a.RunIn(append([]string{git, "-C", home}, args...), home, nil)
		out := py.Strip(r.Stdout)
		if r.Code != 0 {
			msg := py.Strip(r.Stderr)
			if msg == "" {
				msg = out
			}
			return "", msg
		}
		return out, ""
	}
	if out, msg := g("status", "--porcelain"); msg != "" {
		return Die("git status failed in %s: %s", home, msg)
	} else if out != "" {
		return Die("There are uncommitted changes in %s: commit or stash them first (om upgrade only fast-forwards, it never discards anything).", home)
	}
	before, msg := g("rev-parse", "--short", "HEAD")
	if msg != "" {
		return Die("git failed in %s: %s", home, msg)
	}
	a.p("  Fetching the new code...")
	if _, msg := g("fetch", "--quiet"); msg != "" {
		return Die("git fetch failed: %s", msg)
	}
	if _, msg := g("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"); msg != "" {
		return Die("This branch has no upstream to pull from. Set one, for example: git -C %s branch --set-upstream-to=origin/main", home)
	}
	if _, msg := g("merge", "--ff-only", "--quiet", "@{u}"); msg != "" {
		return Die("Cannot fast-forward %s (local commits, or the branch has diverged): %s", home, msg)
	}
	after, _ := g("rev-parse", "--short", "HEAD")
	if before == after {
		a.p("\033[32m✓ om is up to date (%s).\033[0m If you pulled by hand, rebuild with install.sh.", after)
		return nil
	}
	a.p("  %s → %s", before, after)
	if a.GOOS == "windows" {
		a.p("  A running om.exe cannot replace itself. Finish in a new window:\n    powershell -ExecutionPolicy Bypass -File %s", filepath.Join(home, "install.ps1"))
		return nil
	}
	// the installer without questions (it asks about sudo steps when it has a terminal): build, wrapper, jobs, watcher, dashboard
	if code := a.Passthrough([]string{"bash", "-c", `exec bash "$1" </dev/null`, "om-upgrade", filepath.Join(home, "install.sh")}, home, nil); code != 0 {
		return Die("install.sh failed (exit %d): the new code is pulled; run %s to see why.", code, filepath.Join(home, "install.sh"))
	}
	if ns.Bool("core") {
		a.p("  Restarting the core (--core)...")
		if code := a.Passthrough([]string{filepath.Join(home, "build", "om"), "core", "restart"}, home, nil); code != 0 {
			return Die("om core restart failed (exit %d): run `om doctor`.", code)
		}
		a.p("\033[32m✓ om upgraded to %s; the watcher, the dashboard and the core run it.\033[0m", after)
		return nil
	}
	a.p("\033[32m✓ om upgraded to %s; the watcher and the dashboard run it.\033[0m", after)
	a.p("  The core's other containers were not restarted. If CHANGELOG.md says the core's configuration changed, run `om core restart` (or `om upgrade --core` next time).")
	return nil
}
