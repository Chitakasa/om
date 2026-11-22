package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Chitakasa/om/internal/dashboard"
	"github.com/Chitakasa/om/internal/migration"
	"github.com/Chitakasa/om/internal/probe"
	"github.com/Chitakasa/om/internal/state"
)

const rootRefusal = `om does not run as root (sudo).
  Containers run rootless under your own user: a service that escapes its container lands as
  an ordinary user, not as root. Under sudo om would use root's container engine, root's state
  and root's containers — a second, separate om whose files your user cannot change.
  Run ` + "`om`" + ` as yourself. The few host steps that need root (om firewall, om boot, the installer's
  port setting) ask for sudo themselves.`

const notWorkspace = "fatal: not an om workspace (or any parent directory).\nRun 'om init [name]' here, or cd into an existing workspace (see `om list`)."

// ensureStateMigrated is the one-time move of pre-split state out of OM_HOME. The edge bind-mounts that state, so a
// running core is stopped first and brought back on the new paths.
func (a *App) ensureStateMigrated() error {
	if !migration.LegacyStatePresent(a.D) {
		return nil
	}
	os.MkdirAll(a.D.State, 0o755)
	unlock, err := state.FileLock(a.D.State + "/migrate.lock")
	if err != nil {
		return Die("%s", err)
	}
	defer unlock()
	if !migration.LegacyStatePresent(a.D) {
		return nil
	}
	rt := a.Runtime()
	was := false
	for _, c := range state.CoreContainers {
		was = was || a.Eng.ContainerRunning(rt, c)
	}
	a.p("\033[1m📦 Moving om state out of %s\033[0m (one time)\n  settings → %s\n  state    → %s", a.D.Home, a.D.UserEnv, a.D.State)
	if was {
		// Not core down: that would mint fresh state at the new paths before the old moves.
		a.Run(append([]string{rt, "stop"}, state.CoreContainers...))
	}
	lines, err := migration.MigrateLegacyState(a.D)
	if err != nil {
		return Die("%s", err)
	}
	for _, l := range lines {
		a.p("  \033[36m%s\033[0m", l)
	}
	if was {
		if ok, _ := a.Core.Up(rt, true, true); ok {
			a.Syncer.PruneOrphanRoutes(rt, true, false, false)
			a.p("  \033[32m✓ Global Core restarted on the new paths.\033[0m")
		} else {
			a.p("  \033[31m✗ Core did not come back; run `om doctor`.\033[0m")
		}
	}
	return nil
}

// Dispatch runs one parsed command.
func (a *App) Dispatch(ns Namespace) error {
	cmd := ns.Str("command")
	root, _ := a.workspaceRoot()
	switch cmd {
	case "version", "completion", "uninstall":
	default:
		if err := a.ensureStateMigrated(); err != nil {
			return err
		}
	}
	// commands that work anywhere
	switch cmd {
	case "init":
		return a.cmdInit(ns)
	case "list":
		return a.cmdList(ns)
	case "ports":
		return a.cmdPorts(ns)
	case "core":
		return a.cmdCore(ns)
	case "doctor":
		return a.cmdDoctor(ns)
	case "auth":
		return a.cmdAuth(ns)
	case "firewall":
		return a.cmdFirewall(ns)
	case "boot":
		return a.cmdBoot(ns)
	case "secrets":
		return a.cmdSecrets(root, ns)
	case "vpn":
		return a.cmdVPN(ns)
	case "links":
		return a.cmdLinks(ns)
	case "notify":
		return a.cmdNotify()
	case "prune":
		return a.cmdPrune(ns)
	case "config":
		return a.cmdConfig(ns)
	case "completion":
		return a.cmdCompletion(ns.Str("shell"))
	case "exposure":
		return a.cmdExposure(ns)
	case "uninstall":
		return a.cmdUninstall(ns)
	case "version":
		a.p("om %s", a.Version)
		return nil
	case "sync":
		return a.cmdSync(root, ns)
	case "autosync":
		return a.cmdAutosync(root, ns)
	case "docs":
		return a.cmdDocs(ns)
	case "policy":
		return a.cmdPolicy(root, ns)
	case "egress":
		return a.cmdEgress(root, ns)
	case "", "status":
		return a.cmdStatus(root, ns)
	}
	if root == "" {
		return Die("%s", notWorkspace)
	}
	switch cmd {
	case "down":
		return a.cmdDown(root, ns)
	case "start":
		return a.cmdStart(root, ns)
	case "stop":
		return a.cmdStop(root, ns, ns.Bool("all"))
	case "restart":
		if err := a.cmdStop(root, ns, ns.Bool("all")); err != nil {
			return err
		}
		return a.cmdStart(root, ns)
	case "update":
		return a.cmdUpdate(root, ns)
	case "edit":
		return a.cmdEdit(root, ns)
	case "dev":
		return a.cmdDev(root, ns)
	case "scripts", "script":
		return a.cmdScripts(root, ns)
	case "add":
		return a.cmdAdd(root, ns)
	case "remove", "rm":
		return a.cmdRemove(root, ns)
	case "disable":
		return a.cmdDisable(root, ns)
	case "enable":
		return a.cmdEnable(root, ns)
	case "logs":
		return a.cmdLogs(root, ns)
	case "shell":
		return a.cmdShell(root, ns)
	case "run":
		return a.cmdRun(root, ns)
	case "reload":
		return a.cmdReload(root, ns)
	case "routes":
		return a.cmdRoutes(root, ns)
	case "network":
		return a.cmdNetwork(root, ns)
	case "lock":
		return a.cmdLock(root, ns)
	case "log":
		return a.cmdLog(root, ns)
	case "rollback":
		return a.cmdRollback(root, ns)
	case "fsck":
		return a.cmdFsck(root, ns)
	case "scan":
		return a.cmdScan(root)
	case "drift":
		return a.cmdDrift(root, ns)
	case "preview":
		return a.cmdPreview(root, ns)
	}
	return Die("unknown command %s", cmd)
}

// Main is the program: it returns the exit code.
func (a *App) Main(args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok && errors.Is(e, errInterrupted) {
				code = 130
				return
			}
			panic(r)
		}
	}()
	// The dashboard container runs `om dashboard` (as the image's user, often root): not a user-facing command.
	// installer plumbing: create the folders and files the core mounts (no engine needed)
	if len(args) == 1 && args[0] == "_prepare" {
		if err := a.Core.EnsureCorePrerequisites(); err != nil {
			return a.fail(Die("%s", err))
		}
		// an upgrade from another om (the Python version): scheduled jobs that name a program that is gone
		if changed := a.Sched.Refresh(); len(changed) > 0 {
			a.p("  Scheduled jobs now run this om: %s", strings.Join(changed, ", "))
		}
		return 0
	}
	if len(args) > 0 && args[0] == "probe" {
		return probe.Run(args[1:], a.Out, a.Err, a.Getenv)
	}
	if len(args) == 2 && args[0] == "dashboard" && args[1] == "health" {
		if err := dashboard.Health(dashboard.FromEnv(a.Getenv).Addr); err != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == "dashboard" {
		if err := dashboard.New(dashboard.FromEnv(a.Getenv)).Run(); err != nil {
			fmt.Fprintln(a.Err, "error:", err)
			return 1
		}
		return 0
	}
	if os.Geteuid() == 0 && a.GOOS != "windows" {
		return a.fail(Die("%s", rootRefusal))
	}
	ns, err := a.Parser.Parse(args)
	if err != nil {
		var h *HelpRequest
		var pe *ParseError
		switch {
		case errors.As(err, &h):
			fmt.Fprint(a.Out, h.Text)
			return 0
		case errors.As(err, &pe):
			fmt.Fprint(a.Err, pe.Error())
			return 2
		}
		fmt.Fprintln(a.Err, err)
		return 2
	}
	// the port blocks are settings: every command that names a service port reads them from here
	priv, pub, stream, _ := a.Settings().PortBases()
	state.SetPortBases(priv, pub, stream)
	return a.fail(a.Dispatch(ns))
}

var errInterrupted = errors.New("interrupted")

// fail turns a command's error into the exit code, printing its message the way die() does.
func (a *App) fail(err error) int {
	if err == nil {
		return 0
	}
	var e *ExitError
	if errors.As(err, &e) {
		if e.Msg != "" {
			if a.StderrTTY && a.Getenv("NO_COLOR") == "" {
				fmt.Fprintf(a.Err, "\033[31m%s\033[0m\n", e.Msg)
			} else {
				fmt.Fprintln(a.Err, e.Msg)
			}
		}
		return e.Code
	}
	fmt.Fprintln(a.Err, "error:", err)
	return 1
}
