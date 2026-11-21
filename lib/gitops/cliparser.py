#!/usr/bin/env python3
"""The `om` command line: every command, its arguments and help text (argparse). Moved out of bin/om;
dispatch stays there."""

from __future__ import annotations

import argparse

from gitops import omstate
from gitops.omstate import VERSION


def _add_basic_commands(sub) -> None:
    """Init, list, ports, status, scripts."""
    p = sub.add_parser("init", help="Initialize a workspace in the current directory")
    p.add_argument("name", nargs="?", help="Workspace id (default: directory name)")
    p = sub.add_parser("list", help="List registered workspaces")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.add_argument("--prune", action="store_true", help="Forget workspaces whose folder no longer exists")
    sub.add_parser("ports", help="Show host port bindings and any leaks")
    p = sub.add_parser("status", help="Show core and workspace status")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    sub.add_parser("scripts", help="List workspace scripts")
    sub.add_parser("script", help=argparse.SUPPRESS)


def _add_core_command(sub) -> None:
    """The Global Core."""
    p = sub.add_parser("core", help="Manage the Global Core (edge, router, dashboard)",
                       formatter_class=argparse.RawDescriptionHelpFormatter, description="""\
actions:
  status    core containers and the addresses they answer on (default)
  start     start the core: resolve om.env (LAN, VPN, ports), write its config, create the containers
  stop      stop the core; the self-heal timer leaves it stopped until `om core start`
  restart   whole core: re-detect LAN/VPN addresses, rewrite its config, recreate every container
            and re-attach them to the workspace networks (a few seconds of downtime)
  restart <names>
            only those containers, as they are (no re-detection), e.g. `om core restart router dashboard`
  reload    drop routes of deleted workspaces and hot-reload the edge's routes (no downtime)
  update    pull the core's pinned images and recreate what changed
  heal      what the self-heal timer runs: revive dead containers, restart on address changes
  watch     Linux, local engine: restart a container the moment its process dies unseen""")
    p.add_argument("action", nargs="?", default="status", choices=["start", "stop", "restart", "reload", "update", "heal", "watch", "status"])
    p.add_argument("services", nargs="*", help="with restart: only these core containers (caddy, router, egress, sockguard, dashboard)")


def _add_workload_commands(sub) -> None:
    """Starting, stopping, scaffolding and running services."""
    p = sub.add_parser("start", help="Start services (and the core if needed)")
    p.add_argument("target", nargs="?")
    p.add_argument("--build", action="store_true", help="Rebuild images of services with a build: section")
    p = sub.add_parser("stop", help="Stop services (core stays up)")
    p.add_argument("target", nargs="?")
    p.add_argument("--all", action="store_true", help="Also stop the Global Core")
    sub.add_parser("down", help="Stop the workspace and the Global Core")
    p = sub.add_parser("restart", help="Restart services")
    p.add_argument("target", nargs="?")
    p.add_argument("--build", action="store_true", help="Rebuild images of services with a build: section")
    p = sub.add_parser("update", help="Move pinned images to the newest digests, commit the lock, redeploy")
    p.add_argument("target", nargs="?")
    p.add_argument("--dry-run", action="store_true", help="Only show which images have newer digests")
    p.add_argument("--image", action="append", metavar="REF", help="Only update this image (as `--dry-run` prints it); repeatable")
    p.add_argument("-i", "--choose", action="store_true", help="Ask for each image with a newer digest")

    p = sub.add_parser("add", help="Scaffold a service or project")
    p.add_argument("name")
    p.add_argument("--project", action="store_true", help="Live-reload dev project in projects/")
    p.add_argument("--port", type=int, help="Port the container listens on")
    p.add_argument("--image", help="Container image (requires --port)")
    p.add_argument("--public", action="store_true", help="Also expose on the LAN (public tier)")
    p.add_argument("--domain", help="Informational domain label")
    p.add_argument("--icon")
    p.add_argument("--desc")
    p.add_argument("--no-web", action="store_true", help="Background daemon without web UI")
    p = sub.add_parser("remove", aliases=["rm"], help="Remove a service (moved to .om/trash)")
    p.add_argument("service")
    p.add_argument("--data", action="store_true", help="Also move data/<service> to the trash")
    p.add_argument("-y", "--yes", action="store_true")
    p = sub.add_parser("disable", help="Stop a service and keep it off (reversible with `om enable`)")
    p.add_argument("service")
    p = sub.add_parser("enable", help="Undo `om disable`")
    p.add_argument("service")
    p = sub.add_parser("edit", help="Edit a service's labels (scope, port, icon, ...)")
    p.add_argument("service")
    p.add_argument("--scope", choices=["public", "private"])
    p.add_argument("--port", type=int)
    p.add_argument("--icon")
    p.add_argument("--desc")
    p.add_argument("--name")
    p = sub.add_parser("dev", help="Start a project and follow its logs")
    p.add_argument("project")
    p = sub.add_parser("logs", help="Show a service's logs")
    p.add_argument("service")
    p.add_argument("-f", "--follow", action="store_true")
    p.add_argument("-n", "--tail", type=int, default=100)
    p = sub.add_parser("shell", help="Open a shell (or run a command) in a service")
    p.add_argument("service")
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    p = sub.add_parser("cli", help="Run the command-line tool a service ships (its om.cli label); no service: list them")
    p.add_argument("service", nargs="?")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p = sub.add_parser("run", help="Run a workspace script")
    p.add_argument("script")
    p.add_argument("args", nargs=argparse.REMAINDER)


def _add_gitops_commands(sub) -> None:
    """Routes, generations, egress, policy and sync."""
    sub.add_parser("reload", help="Regenerate routes and hot-reload the proxy")
    p = sub.add_parser("routes", help="Show this workspace's URLs")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p = sub.add_parser("network", help="Show this workspace's network, or harden it (internal)")
    p.add_argument("action", nargs="?", default="show", choices=["show", "harden"])
    sub.add_parser("drift", help="Compare the workspace with its git remote")
    sub.add_parser("lock", help="Pin images missing from .om/lock.json to their registry digest")
    p = sub.add_parser("log", help="Generations of this workspace (deploy history)")
    p.add_argument("-n", type=int, default=0, help="Show only the last N")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p = sub.add_parser("rollback", help="Deploy an earlier generation's commit (default: the previous one)")
    p.add_argument("generation", nargs="?", type=int)
    sub.add_parser("fsck", help="Verify generation chain, signature, and running images against the lock")
    sub.add_parser("scan", help="Count critical/high vulnerabilities in the pinned images (needs trivy or grype)")
    p = sub.add_parser("egress", help="Show refused outbound calls and the om.egress line to allow them")
    p.add_argument("target", nargs="*", help="Optional service name or 'log'")
    p.add_argument("--apply", action="store_true", help="Write suggested om.egress line into the compose file")
    p.add_argument("--since", default="24h", help="How far back to read the proxy log (default 24h)")
    p.add_argument("--all", action="store_true", help="Every workspace, not only this one")
    p = sub.add_parser("policy", help="Check compose files against the policy gate")
    p.add_argument("action", nargs="?", default="check", choices=["check"])
    p.add_argument("--all", action="store_true", help="Check every registered workspace")
    p = sub.add_parser("sync", help="Pull from git, reconcile, health-check, roll back on failure")
    p.add_argument("--force", action="store_true", help="Reset to the remote branch")
    p.add_argument("--rebase", action="store_true", help="Rebase local commits onto the remote")
    p.add_argument("--scheduled", action="store_true", help="(used by the scheduler) sync all auto-sync workspaces")
    p = sub.add_parser("autosync", help="Scheduled GitOps sync for this workspace")
    p.add_argument("action", choices=["on", "off", "status"])
    p.add_argument("--every", type=int, help="Minutes between syncs (with 'on')")


def _add_host_commands(sub) -> None:
    """Doctor, logins, VPN, firewall, boot, secrets, docs and housekeeping."""
    p = sub.add_parser("doctor", help="Diagnose the installation and security perimeter")
    p.add_argument("--json", action="store_true", help="Machine-readable output (exit code 1 on any failure)")
    p = sub.add_parser("exposure", help="Who can reach what: this machine, the VPN's devices, the LAN; per service, its address rules and outbound access")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p = sub.add_parser("auth", help="Require a login for the private tier")
    p.add_argument("action", choices=["set", "add", "remove", "list", "off", "status"])
    p.add_argument("user", nargs="?")
    p = sub.add_parser("links", help="Cross-workspace links (om.link / om.link.allow)")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p = sub.add_parser("preview", help="Run a branch as its own throw-away workspace: om preview <branch> | rm <branch> | list")
    p.add_argument("action", nargs="?", default="start", help="<branch> to start it, rm <branch>, or list")
    p.add_argument("branch", nargs="?")
    p = sub.add_parser("vpn", help="VPNs whose devices reach the private tier: list, trust|untrust <iface>, allow|disallow <device>, devices")
    p.add_argument("action", nargs="?", default="list", choices=["list", "trust", "untrust", "allow", "disallow", "devices"])
    p.add_argument("name", nargs="?", help="trust/untrust: interface (wg0, zt…) or address; allow/disallow: device address, range or VPN name")
    p.add_argument("--json", action="store_true", help="Machine-readable output (list)")
    p.add_argument("--no-apply", action="store_true",
                   help="allow/disallow: leave the host firewall alone (the VPN's private tier closes until `om firewall apply`)")
    p = sub.add_parser("firewall", help="Host firewall: only om's ingress reachable; `log`: who was refused, who connected")
    p.add_argument("action", nargs="?", default="status", choices=["show", "apply", "remove", "status", "log"])
    p.add_argument("--since", default="24h", help="With log: how far back (default 24h)")
    p = sub.add_parser("boot", help="Start containers automatically at boot")
    p.add_argument("action", nargs="?", default="status", choices=["enable", "disable", "status"])
    p = sub.add_parser("secrets", help="Service secrets (age): init, set <project>/<name>, list, rekey; decrypt / migrate <file> <project>/<name> read and move old om-v2 files")
    p.add_argument("action", choices=["init", "set", "list", "rekey", "decrypt", "migrate"])
    p.add_argument("file", nargs="?")
    p.add_argument("destination", nargs="?", help="migrate: <project>/<name> to store the secret under (age)")
    p.add_argument("-o", "--output")
    p.add_argument("--allow-unauthenticated", action="store_true", help="read an old om-v1 file, which has no integrity check")
    p = sub.add_parser("docs", help="List om's docs, or read one (om docs guide | architecture | design)")
    p.add_argument("name", nargs="?")
    p.add_argument("--path", action="store_true", help="Print the file path instead (open it in an editor or browser)")
    p = sub.add_parser("prune", help="List images nothing uses and no lock pins; --yes removes them")
    p.add_argument("-y", "--yes", action="store_true")
    p = sub.add_parser("config", help="Settings in om.env: show, get <KEY>, set KEY=value (checked, file kept 0600), unset <KEY>")
    p.add_argument("action", nargs="?", default="show", choices=["show", "get", "set", "unset"])
    p.add_argument("arg", nargs="?", help="get/unset: the setting (OM_POLICY); set: KEY=value")
    p.add_argument("--reveal", action="store_true", help="show/get: print secret values (OM_NOTIFY_URL) instead of ***")
    p.add_argument("--json", action="store_true", help="Machine-readable output (show)")
    p = sub.add_parser("notify", help="Notifications about image updates: `om notify test` sends one on every channel")
    p.add_argument("action", nargs="?", default="test", choices=["test"])
    p = sub.add_parser("completion", help="Print a shell completion script")
    p.add_argument("shell", choices=["bash", "zsh", "fish"])
    p = sub.add_parser("uninstall", help="Stop om and remove its command")
    p.add_argument("--purge", action="store_true", help=f"Also delete {omstate.OM_HOME}, {omstate.STATE_DIR} and {omstate.USER_ENV}")
    p.add_argument("-y", "--yes", action="store_true")
    sub.add_parser("version", help="Print the version")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="om", description="om — Universal Workspace & GitOps Platform")
    parser.add_argument("--version", action="version", version=f"om {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    _add_basic_commands(sub)
    _add_core_command(sub)
    _add_workload_commands(sub)
    _add_gitops_commands(sub)
    _add_host_commands(sub)
    return parser
