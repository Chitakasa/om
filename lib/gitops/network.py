#!/usr/bin/env python3
"""Workspace networks and edge proxy reloads for the om substrate."""

from pathlib import Path

from gitops.core import CORE_DIR, EDGE, ensure_network, network_is_internal, run, core_compose, write_runtime_files

def ensure_workspace_network(workspace_id: str, runtime: str = "podman") -> str:
    """Ensure the workspace's dedicated bridge network exists; new ones are internal (no way out
    except om_egress). An existing open network is reported, never changed: `om network harden`."""
    net_name = f"{workspace_id}_net"
    if not ensure_network(runtime, net_name, internal=True):
        print(f"\033[33mWarning: failed to create network {net_name}\033[0m")
    elif not network_is_internal(runtime, net_name):
        print(f"\033[33m⚠ {net_name} still has open internet access. Run `om network harden` "
              "(services then reach only the hosts in their om.egress label).\033[0m")
    return net_name

def _mounted_caddyfile_is_stale(runtime: str) -> bool:
    """A single-file bind mount pins the inode: editors that replace the file leave the
    container reading the old one, so a plain reload would silently apply stale config."""
    host = (CORE_DIR / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    inside = run([runtime, "exec", EDGE, "cat", "/etc/caddy/Caddyfile"])
    return inside.returncode == 0 and inside.stdout != host

def reload_caddy(runtime: str = "podman", workspace_id: str | None = None, quiet: bool = False) -> bool:
    """Validate, then hot-reload the edge route table (recreating the edge if its Caddyfile mount is stale)."""
    if run([runtime, "container", "inspect", EDGE]).returncode != 0:
        if not quiet:
            print("\033[33mℹ Edge proxy is not running; routes apply on next `om core start`.\033[0m")
        return False

    if _mounted_caddyfile_is_stale(runtime):
        write_runtime_files(runtime)
        r = run(core_compose(runtime, "up", "-d", "--force-recreate", "caddy"), cwd=CORE_DIR)
        ok = r.returncode == 0
        if not quiet:
            print("\033[32m✓ Edge proxy recreated with the updated Caddyfile.\033[0m" if ok
                  else f"\033[31mEdge recreate failed:\033[0m {(r.stderr or r.stdout).strip()[-800:]}")
        return ok

    val = run([runtime, "exec", EDGE, "caddy", "validate", "--config", "/etc/caddy/Caddyfile"])
    if val.returncode != 0:
        lines = [l for l in (val.stderr or val.stdout).splitlines() if "error" in l.lower()] or [(val.stderr or val.stdout).strip()]
        print(f"\033[31m✗ Caddy config invalid — live routes left unchanged:\033[0m {lines[-1][-600:]}")
        return False
    res = run([runtime, "exec", EDGE, "caddy", "reload", "--config", "/etc/caddy/Caddyfile"])
    if res.returncode == 0:
        if not quiet:
            print("\033[32m✓ Caddy route table hot-reloaded (zero downtime).\033[0m")
        return True
    print(f"\033[31mCaddy reload error: {res.stderr.strip()[-600:]}\033[0m")
    return False
