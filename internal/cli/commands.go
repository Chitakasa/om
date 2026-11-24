package cli

import (
	"strings"

	"github.com/Chitakasa/om/internal/state"
)

// Code generated once from the Python parser (testdata/cli_spec.json) and maintained by hand since.

const coreDescription = `actions:
  status    core containers and the addresses they answer on (default)
  start     start the core: resolve om.env (LAN, VPN, ports), write its config, create the containers
  stop      stop the core; the self-heal timer leaves it stopped until ` + "`" + `om core start` + "`" + `
  restart   whole core: re-detect LAN/VPN addresses, rewrite its config, recreate every container
            and re-attach them to the workspace networks (a few seconds of downtime)
  restart <names>
            only those containers, as they are (no re-detection), e.g. ` + "`" + `om core restart router dashboard` + "`" + `
  reload    drop routes of deleted workspaces and hot-reload the edge's routes (no downtime)
  update    pull the core's pinned images and recreate what changed
  heal      what the self-heal timer runs: revive dead containers, restart on address changes
  watch     Linux, local engine: restart a container the moment its process dies unseen`

// commands is every `om` subcommand, in registration order (the order of the "invalid choice" message).
var commands = []*Command{
	{
		Name: "init",
		Help: "Initialize a workspace in the current directory",
		Args: []Arg{
			{Dest: "name", Nargs: "?", Help: "Workspace id (default: directory name)"},
		},
	},
	{
		Name: "list",
		Help: "List registered workspaces",
		Args: []Arg{
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output"},
			{Flags: []string{"--prune"}, Dest: "prune", Action: "store_true", Help: "Forget workspaces whose folder no longer exists"},
		},
	},
	{
		Name: "ports",
		Help: "Show host port bindings and any leaks",
	},
	{
		Name: "status",
		Help: "Show core and workspace status",
		Args: []Arg{
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output"},
		},
	},
	{
		Name: "scripts",
		Help: "List workspace scripts",
	},
	{
		Name: "script",
	},
	{
		Name:        "core",
		Help:        "Manage the Global Core (edge, router, dashboard)",
		Description: coreDescription, RawDescription: true,
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"start", "stop", "restart", "reload", "update", "heal", "watch", "status"}, Default: "status", Help: "What to do with the core (default: status)"},
			{Dest: "services", Nargs: "*", Help: "with restart: only these core containers (caddy, router, egress, sockguard, dashboard)"},
		},
	},
	{
		Name: "start",
		Help: "Start services (and the core if needed)",
		Args: []Arg{
			{Dest: "target", Nargs: "?", Help: "One service or project (default: all of them)"},
			{Flags: []string{"--build"}, Dest: "build", Action: "store_true", Help: "Rebuild images of services with a build: section"},
		},
	},
	{
		Name: "stop",
		Help: "Stop services (core stays up)",
		Args: []Arg{
			{Dest: "target", Nargs: "?", Help: "One service or project (default: all of them)"},
			{Flags: []string{"--all"}, Dest: "all", Action: "store_true", Help: "Also stop the Global Core"},
		},
	},
	{
		Name: "down",
		Help: "Stop the workspace and the Global Core",
	},
	{
		Name: "restart",
		Help: "Restart services",
		Args: []Arg{
			{Dest: "target", Nargs: "?", Help: "One service or project (default: all of them)"},
			{Flags: []string{"--build"}, Dest: "build", Action: "store_true", Help: "Rebuild images of services with a build: section"},
		},
	},
	{
		Name: "update",
		Help: "Move pinned images to the newest digests, commit the lock, redeploy",
		Args: []Arg{
			{Dest: "target", Nargs: "?", Help: "Only this service's folder (default: the whole workspace)"},
			{Flags: []string{"--dry-run"}, Dest: "dry_run", Action: "store_true", Help: "Only show which images have newer digests"},
			{Flags: []string{"--image"}, Dest: "image", Action: "append", Help: "Only update this image (as `--dry-run` prints it); repeatable", Metavar: "REF"},
			{Flags: []string{"-i", "--choose"}, Dest: "choose", Action: "store_true", Help: "Ask for each image with a newer digest"},
		},
	},
	{
		Name: "add",
		Help: "Scaffold a service or project",
		Args: []Arg{
			{Dest: "name", Help: "Name of the new service: lowercase letters, digits and -"},
			{Flags: []string{"--project"}, Dest: "project", Action: "store_true", Help: "Live-reload dev project in projects/"},
			{Flags: []string{"--port"}, Dest: "port", Type: "int", Help: "Port the container listens on"},
			{Flags: []string{"--image"}, Dest: "image", Help: "Container image (requires --port)"},
			{Flags: []string{"--public"}, Dest: "public", Action: "store_true", Help: "Also expose on the LAN (public tier)"},
			{Flags: []string{"--domain"}, Dest: "domain", Help: "Informational domain label"},
			{Flags: []string{"--icon"}, Dest: "icon", Help: "Emoji for the dashboard card"},
			{Flags: []string{"--desc"}, Dest: "desc", Help: "Description for the dashboard card"},
			{Flags: []string{"--no-web"}, Dest: "no_web", Action: "store_true", Help: "Background daemon without web UI"},
		},
	},
	{
		Name:    "remove",
		Aliases: []string{"rm"},
		Help:    "Remove a service (moved to .om/trash)",
		Args: []Arg{
			{Dest: "service", Help: "The service to remove"},
			{Flags: []string{"--data"}, Dest: "data", Action: "store_true", Help: "Also move data/<service> to the trash"},
			{Flags: []string{"-y", "--yes"}, Dest: "yes", Action: "store_true", Help: "Do not ask for confirmation"},
		},
	},
	{
		Name: "disable",
		Help: "Stop a service and keep it off (reversible with `om enable`)",
		Args: []Arg{
			{Dest: "service", Help: "The service to stop and keep off"},
		},
	},
	{
		Name: "enable",
		Help: "Undo `om disable`",
		Args: []Arg{
			{Dest: "service", Help: "The service to switch back on"},
		},
	},
	{
		Name: "edit",
		Help: "Edit a service's labels (scope, port, icon, ...)",
		Args: []Arg{
			{Dest: "service", Help: "The service to change"},
			{Flags: []string{"--scope"}, Dest: "scope", Choices: []string{"public", "private"}, Help: "private (this machine and your VPN) or public (the LAN too)"},
			{Flags: []string{"--port"}, Dest: "port", Type: "int", Help: "The container port om routes to"},
			{Flags: []string{"--icon"}, Dest: "icon", Help: "Emoji for the dashboard card"},
			{Flags: []string{"--desc"}, Dest: "desc", Help: "Description for the dashboard card"},
			{Flags: []string{"--name"}, Dest: "name", Help: "Title of the dashboard card"},
		},
	},
	{
		Name: "dev",
		Help: "Start a project and follow its logs",
		Args: []Arg{
			{Dest: "project", Help: "The project to start (a folder in projects/)"},
		},
	},
	{
		Name: "logs",
		Help: "Show a service's logs",
		Args: []Arg{
			{Dest: "service", Help: "The service whose logs to show"},
			{Flags: []string{"-f", "--follow"}, Dest: "follow", Action: "store_true", Help: "Keep following new lines"},
			{Flags: []string{"-n", "--tail"}, Dest: "tail", Type: "int", Default: 100, Help: "How many recent lines to show first"},
		},
	},
	{
		Name: "shell",
		Help: "Open a shell (or run a command) in a service",
		Args: []Arg{
			{Dest: "service", Help: "The service to open a shell in"},
			{Dest: "cmd", Nargs: "...", Help: "A command to run there instead of a shell"},
		},
	},
	{
		Name: "run",
		Help: "Run a workspace script",
		Args: []Arg{
			{Dest: "script", Help: "The script's name, without extension, from scripts/"},
			{Dest: "args", Nargs: "...", Help: "Arguments passed on to the script"},
		},
	},
	{
		Name: "reload",
		Help: "Regenerate routes and hot-reload the proxy",
	},
	{
		Name: "routes",
		Help: "Show this workspace's URLs",
		Args: []Arg{
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output"},
		},
	},
	{
		Name: "network",
		Help: "Show this workspace's network, or harden it (internal)",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"show", "harden"}, Default: "show", Help: "show (default) or harden"},
		},
	},
	{
		Name: "drift",
		Help: "Compare the workspace with its git remote",
	},
	{
		Name: "lock",
		Help: "Pin images missing from .om/lock.json to their registry digest",
	},
	{
		Name: "log",
		Help: "Generations of this workspace (deploy history)",
		Args: []Arg{
			{Flags: []string{"-n"}, Dest: "n", Type: "int", Default: 0, Help: "Show only the last N"},
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output"},
		},
	},
	{
		Name: "rollback",
		Help: "Deploy an earlier generation's commit (default: the previous one)",
		Args: []Arg{
			{Dest: "generation", Nargs: "?", Type: "int", Help: "The generation number (default: the previous clean one)"},
		},
	},
	{
		Name: "fsck",
		Help: "Verify generation chain, signature, and running images against the lock",
	},
	{
		Name: "scan",
		Help: "Count critical/high vulnerabilities in the pinned images (needs trivy or grype)",
	},
	{
		Name: "egress",
		Help: "Show refused outbound calls and the om.egress line to allow them",
		Args: []Arg{
			{Dest: "target", Nargs: "*", Help: "Optional service name or 'log'"},
			{Flags: []string{"--apply"}, Dest: "apply", Action: "store_true", Help: "Write suggested om.egress line into the compose file"},
			{Flags: []string{"--since"}, Dest: "since", Default: "24h", Help: "How far back to read the proxy log (default 24h)"},
			{Flags: []string{"--all"}, Dest: "all", Action: "store_true", Help: "Every workspace, not only this one"},
		},
	},
	{
		Name: "policy",
		Help: "Check compose files against the policy gate",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"check"}, Default: "check", Help: "check (the only action)"},
			{Flags: []string{"--all"}, Dest: "all", Action: "store_true", Help: "Check every registered workspace"},
		},
	},
	{
		Name: "sync",
		Help: "Pull from git, reconcile, health-check, roll back on failure",
		Args: []Arg{
			{Flags: []string{"--force"}, Dest: "force", Action: "store_true", Help: "Reset to the remote branch"},
			{Flags: []string{"--rebase"}, Dest: "rebase", Action: "store_true", Help: "Rebase local commits onto the remote"},
			{Flags: []string{"--scheduled"}, Dest: "scheduled", Action: "store_true", Help: "(used by the scheduler) sync all auto-sync workspaces"},
		},
	},
	{
		Name: "autosync",
		Help: "Scheduled GitOps sync for this workspace",
		Args: []Arg{
			{Dest: "action", Choices: []string{"on", "off", "status"}, Help: "on, off or status"},
			{Flags: []string{"--every"}, Dest: "every", Type: "int", Help: "Minutes between syncs (with 'on')"},
		},
	},
	{
		Name: "doctor",
		Help: "Diagnose the installation and security perimeter",
		Args: []Arg{
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output (exit code 1 on any failure)"},
		},
	},
	{
		Name: "exposure",
		Help: "Who can reach what: this machine, the VPN's devices, the LAN; per service, its address rules and outbound access",
		Args: []Arg{
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output"},
		},
	},
	{
		Name: "auth",
		Help: "Require a login for the private tier",
		Args: []Arg{
			{Dest: "action", Choices: []string{"set", "add", "remove", "list", "off", "status"}, Help: "set, add or remove a login; list them; off; or status"},
			{Dest: "user", Nargs: "?", Help: "The login name (letters, digits, . _ -)"},
		},
	},
	{
		Name: "links",
		Help: "Cross-workspace links (om.link / om.link.allow)",
		Args: []Arg{
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output"},
		},
	},
	{
		Name: "preview",
		Help: "Run a branch as its own throw-away workspace: om preview <branch> | rm <branch> | list",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Default: "start", Help: "<branch> to start it, rm <branch>, or list"},
			{Dest: "branch", Nargs: "?", Help: "The branch to run (with rm: the preview to remove)"},
		},
	},
	{
		Name: "vpn",
		Help: "VPNs whose devices reach the private tier: list, trust|untrust <iface>, allow|disallow <device>, devices",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"list", "trust", "untrust", "allow", "disallow", "devices"}, Default: "list", Help: "list (default), trust, untrust, allow, disallow or devices"},
			{Dest: "name", Nargs: "?", Help: "trust/untrust: interface (wg0, zt…) or address; allow/disallow: device address, range or VPN name"},
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output (list)"},
			{Flags: []string{"--no-apply"}, Dest: "no_apply", Action: "store_true", Help: "allow/disallow: leave the host firewall alone (the VPN's private tier closes until `om firewall apply`)"},
		},
	},
	{
		Name: "firewall",
		Help: "Host firewall: only om's ingress reachable; `log`: who was refused, who connected",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"show", "apply", "remove", "status", "log"}, Default: "status", Help: "show, apply or remove the rules; status (default); or log"},
			{Flags: []string{"--since"}, Dest: "since", Default: "24h", Help: "With log: how far back (default 24h)"},
		},
	},
	{
		Name: "boot",
		Help: "Start containers automatically at boot",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"enable", "disable", "status"}, Default: "status", Help: "enable, disable or status (default)"},
		},
	},
	{
		Name: "secrets",
		Help: "Service secrets (age): init, set <project>/<name>, list, rekey; decrypt / migrate <file> <project>/<name> read and move old om-v2 files",
		Args: []Arg{
			{Dest: "action", Choices: []string{"init", "set", "list", "rekey", "decrypt", "migrate"}, Help: "init, set, list, rekey, decrypt or migrate"},
			{Dest: "file", Nargs: "?", Help: "decrypt / migrate: the old secret file"},
			{Dest: "destination", Nargs: "?", Help: "migrate: <project>/<name> to store the secret under (age)"},
			{Flags: []string{"-o", "--output"}, Dest: "output", Help: "decrypt: write the plain text to this file instead of printing it"},
			{Flags: []string{"--allow-unauthenticated"}, Dest: "allow_unauthenticated", Action: "store_true", Help: "read an old om-v1 file, which has no integrity check"},
		},
	},
	{
		Name: "docs",
		Help: "List om's docs, or read one (om docs guide | architecture | design)",
		Args: []Arg{
			{Dest: "name", Nargs: "?", Help: "guide, architecture, design, … (none lists them all)"},
			{Flags: []string{"--path"}, Dest: "path", Action: "store_true", Help: "Print the file path instead (open it in an editor or browser)"},
		},
	},
	{
		Name: "prune",
		Help: "List images nothing uses and no lock pins; --yes removes them",
		Args: []Arg{
			{Flags: []string{"-y", "--yes"}, Dest: "yes", Action: "store_true", Help: "Remove the images, not only list them"},
		},
	},
	{
		Name: "config",
		Help: "Settings in om.env: show, get <KEY>, set KEY=value (checked, file kept 0600), unset <KEY>",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"show", "get", "set", "unset"}, Default: "show", Help: "show (default), get, set or unset"},
			{Dest: "arg", Nargs: "?", Help: "get/unset: the setting (OM_POLICY); set: KEY=value"},
			{Flags: []string{"--reveal"}, Dest: "reveal", Action: "store_true", Help: "show/get: print secret values (OM_NOTIFY_URL) instead of ***"},
			{Flags: []string{"--json"}, Dest: "json", Action: "store_true", Help: "Machine-readable output (show)"},
		},
	},
	{
		Name: "notify",
		Help: "Notifications about image updates: `om notify test` sends one on every channel",
		Args: []Arg{
			{Dest: "action", Nargs: "?", Choices: []string{"test"}, Default: "test", Help: "test (the only action)"},
		},
	},
	{
		Name: "completion",
		Help: "Print a shell completion script",
		Args: []Arg{
			{Dest: "shell", Choices: []string{"bash", "zsh", "fish"}, Help: "bash, zsh or fish"},
		},
	},
	{
		Name: "upgrade",
		Help: "Upgrade om itself: pull the new code, rebuild, restart what runs the old build",
		Args: []Arg{
			{Flags: []string{"--core"}, Dest: "core", Action: "store_true", Help: "Also restart the whole core (`om core restart`), needed when the changelog says its configuration changed"},
		},
	},
	{
		Name: "uninstall",
		Help: "Stop om and remove its command",
		Args: []Arg{
			{Flags: []string{"--purge"}, Dest: "purge", Action: "store_true", Help: "Also delete @OM_HOME@, @STATE_DIR@ and @USER_ENV@"},
			{Flags: []string{"-y", "--yes"}, Dest: "yes", Action: "store_true", Help: "Do not ask for confirmation"},
		},
	},
	{
		Name: "version",
		Help: "Print the version",
	},
}

// helpGroups is how `om --help` lists the commands.
var helpGroups = []HelpGroup{
	{"Everyday", []string{"init", "add", "start", "stop", "restart", "status", "logs", "doctor"}},
	{"Services", []string{"edit", "remove", "disable", "enable", "shell", "dev", "update", "scripts", "run", "routes", "preview"}},
	{"Deploy and GitOps", []string{"sync", "autosync", "drift", "lock", "log", "rollback", "fsck", "secrets", "policy"}},
	{"Network and security", []string{"exposure", "vpn", "firewall", "auth", "links", "network", "egress", "ports"}},
	{"Platform and upkeep", []string{"core", "config", "boot", "notify", "list", "prune", "scan", "reload", "down", "docs", "completion", "version", "upgrade", "uninstall"}},
}

// NewParser builds the `om` command line. Help texts that name om's folders get this machine's (d).
func NewParser(version string, d state.Dirs) *Parser {
	r := strings.NewReplacer("@OM_HOME@", d.Home, "@STATE_DIR@", d.State, "@USER_ENV@", d.UserEnv)
	table := make([]*Command, len(commands))
	for i, c := range commands {
		cc := *c
		cc.Help, cc.Description = r.Replace(c.Help), r.Replace(c.Description)
		cc.Args = make([]Arg, len(c.Args))
		for j, g := range c.Args {
			g.Help = r.Replace(g.Help)
			cc.Args[j] = g
		}
		table[i] = &cc
	}
	return &Parser{Prog: "om", Version: version, Description: "om — self-host anything, privately and safely (Podman + Caddy)",
		Commands: table, Groups: helpGroups}
}
