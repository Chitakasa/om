#!/usr/bin/env python3
"""
doctor.py — `om doctor`: verify the installation, the network perimeter and common
failure modes, and print a concrete fix for every problem found.

Each check returns (status, message, fix) with status in PASS / WARN / FAIL.
"""

import json
import re
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

from gitops import core, enginectl, exposure, hostsetup, migration, omsettings, omstate, vpndetect, wsregistry
from gitops.exposure import other_login_users as _other_login_users

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


def _http(host_header: str, path: str = "/", addr: str = "127.0.0.1", port: int | None = None, timeout: float = 3.0):
    """HTTP status for a request, 0 if the connection was refused/aborted."""
    port = port or omsettings.edge_ports()[0]
    req = urllib.request.Request(f"http://{addr}:{port}{path}", headers={"Host": host_header, "User-Agent": "om-doctor"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def check_python():
    v = sys.version_info
    if v < (3, 10):
        return FAIL, f"Python {v.major}.{v.minor}", "Install Python 3.10 or newer."
    return PASS, f"Python {v.major}.{v.minor}.{v.micro}", ""

def check_engine(runtime):
    eng = enginectl.engine_info(runtime)
    if not eng["ok"]:
        return FAIL, f"{runtime} not responding", "Start your container engine (`podman machine start`, Docker Desktop, or `systemctl start docker`)."
    mode = ("rootless" if eng["rootless"] else "rootful") + (", VM" if eng["remote_vm"] else "")
    return PASS, f"{runtime} ({mode}), socket {eng['socket']}", ""

def check_compose(runtime):
    if enginectl.compose_available(runtime):
        return PASS, f"`{runtime} compose` available", ""
    return FAIL, f"`{runtime} compose` missing", "Install docker-compose v2 (or podman-compose)."

def check_ports(runtime):
    eng = enginectl.engine_info(runtime)
    if omstate.IS_LINUX and eng["rootless"] and not eng["remote_vm"]:
        start, low = enginectl.unprivileged_port_start(), min(omsettings.edge_ports())
        if start is not None and start > low:
            return FAIL, f"unprivileged ports start at {start}", \
                f"echo 'net.ipv4.ip_unprivileged_port_start={low}' | sudo tee /etc/sysctl.d/99-om.conf && sudo sysctl --system"
    return PASS, f"can bind {'/'.join(map(str, omsettings.edge_ports()))}", ""

def check_core(runtime):
    down = [c for c in omstate.CORE_CONTAINERS if not enginectl.container_running(runtime, c)]
    if down:
        return FAIL, f"not running: {', '.join(down)}", "om core start"
    retired = [c for c in omstate.RETIRED_CONTAINERS if omstate.run([runtime, "container", "inspect", c]).returncode == 0]
    if retired:
        return WARN, f"removed parts still present: {', '.join(retired)}", "om core restart"
    return PASS, f"{', '.join(omstate.CORE_CONTAINERS)} running", ""

def check_healthchecks(runtime):
    """Running workspace containers without a healthcheck: `om update`, auto-updates and the heal timer
    can only judge a service by its health."""
    wanted = set(wsregistry.read_registry())
    r = omstate.run([runtime, "ps", "--format", '{{.Names}}\t{{.Status}}\t{{index .Labels "com.docker.compose.project"}}'])
    bare = []
    for line in r.stdout.splitlines() if r.returncode == 0 else []:
        name, status, project = (line.split("\t") + ["", ""])[:3]
        if project in wanted and "(" not in status:
            bare.append(name)
    if bare:
        return WARN, f"no healthcheck: {', '.join(sorted(bare))}", "add a healthcheck: to the service in its compose file"
    return PASS, "every running workspace container has a healthcheck", ""

def check_router_networks(runtime):
    want = {n for w in wsregistry.read_registry() for n in [f"{w}_net"] + enginectl.project_networks(runtime, w)}
    r = omstate.run([runtime, "inspect", omstate.ROUTER, "--format", "{{json .NetworkSettings.Networks}}"])
    try:
        have = set(json.loads(r.stdout).keys())
    except Exception:
        return WARN, "could not inspect router networks", "om core restart"
    missing = sorted(want - have)
    if missing:
        return FAIL, f"router not attached to {', '.join(missing)} (their services are unreachable)", "om core start"
    return PASS, f"router attached to {len(want)} workspace and project network(s)", ""

def check_edge_isolated(runtime):
    r = omstate.run([runtime, "inspect", omstate.EDGE, "--format", "{{json .NetworkSettings.Networks}}"])
    try:
        nets = set(json.loads(r.stdout).keys())
    except Exception:
        return WARN, "could not inspect edge networks", ""
    extra = sorted(n for n in nets if n != "om_core_net")
    if extra:
        return FAIL, f"edge proxy is on workspace network(s) {', '.join(extra)} — containers there can reach the private tier", \
            "om core restart   (and remove any `network connect ... om_caddy` from your scripts)"
    return PASS, "edge proxy reachable only from om_core_net", ""

def check_published_ports(runtime):
    r = omstate.run([runtime, "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    leaks = []
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if name in omstate.CORE_CONTAINERS or "->" not in ports:
            continue
        leaks.append(f"{name} ({ports})")
    if leaks:
        return FAIL, "containers publish host ports, bypassing the proxy: " + "; ".join(leaks), \
            "Replace `ports:` with `expose:` in their compose files, then `om start`."
    return PASS, "no container publishes host ports except the edge", ""

def check_drift(runtime):
    d = core.runtime_drift(runtime)
    if d:
        return WARN, d[0], "om core restart"
    return PASS, "ingress addresses match this network", ""

def check_rebinding():
    code = _http("attacker.example", "/api/workspaces")
    if code in (0, 403):
        return PASS, "foreign Host on the private tier is refused (DNS-rebinding safe)", ""
    return FAIL, f"foreign Host got HTTP {code}", "Restore the explicit host list and `:80 { abort }` in core/caddy/Caddyfile."

def check_private_reachable():
    code = _http("localhost", "/healthz")
    if code in (200, 401):
        return PASS, f"private tier answers on {omsettings.base_url()}/", ""
    return FAIL, f"{omsettings.base_url()}/ returned {code or 'no answer'}", "om core restart; then om doctor"

_ROUTER_PROBE = """
import socket
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
s.connect("/run/om-router/router.sock")
s.sendall(b"GET / HTTP/1.1\\r\\nHost: x\\r\\nX-Om-Upstream: om_dashboard:80\\r\\n\\r\\n")
try: print("forwarded" if s.recv(64) else "refused")
except OSError: print("refused")
"""

def check_router_token(runtime):
    """The router listens on no network (only the edge's socket), and refuses a request without the edge token."""
    listen = omstate.run([runtime, "exec", omstate.ROUTER, "netstat", "-lnt"])
    if listen.returncode == 0 and "LISTEN" in listen.stdout:
        return FAIL, "the router listens on the network: containers can connect to it", "om core restart (core/caddy/router/Caddyfile binds a unix socket only)"
    r = omstate.run([runtime, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                  "-v", "om_router_sock:/run/om-router:ro", _probe_image(), "python3", "-c", _ROUTER_PROBE])
    if r.stdout.strip() == "refused":
        return PASS, "router listens on no network; on its socket it refuses requests without the edge token", ""
    return FAIL, f"router probe: {r.stdout.strip() or r.stderr.strip()[-160:]!r} (expected 'refused')", \
        "Check core/caddy/router/Caddyfile and data/edge_token in the om state dir; om core restart"

_SOCK_PROBE = """
import http.client, os, socket, sys
class U(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.connect(os.environ["OM_ENGINE_SOCKET_PATH"])
def code(m, p):
    c = U("localhost", timeout=5); c.request(m, p); return c.getresponse().status
print(int(os.path.exists("/var/run/docker.sock")), code("GET", "/containers/json"), code("POST", "/containers/om_dashboard/kill"))
"""

def check_engine_filter(runtime):
    """The dashboard must see the engine only through om_sockguard: list allowed, writes refused, no raw socket."""
    r = omstate.run([runtime, "exec", "om_dashboard", "python3", "-c", _SOCK_PROBE])
    if r.stdout.split() == ["0", "200", "403"]:
        return PASS, "dashboard has read-only engine access (writes → 403, no raw socket)", ""
    return FAIL, f"engine filter probe returned {r.stdout.strip() or r.stderr.strip()[-200:]!r} (expected '0 200 403')", "om core restart; check core/caddy/sockguard/Caddyfile"

_EGRESS_PROBE = """
import socket, urllib.request, sys
def dns():
    try: socket.gethostbyname("example.com"); return "open"
    except OSError: return "blocked"
def direct():
    try: socket.create_connection(("1.1.1.1", 443), timeout=4); return "open"
    except OSError: return "blocked"
def host(addrs):
    for addr in addrs:
        for port in (22, 80, 443, 2019, 9091):
            try: socket.create_connection((addr, port), timeout=2); return f"open:{addr}:{port}"
            except OSError: pass
    return "blocked"
def proxy(target):
    h = urllib.request.ProxyHandler({"https": "http://om_egress:3128"})
    try: urllib.request.build_opener(h).open(f"https://{target}/", timeout=8); return "open"
    except Exception as e: return "refused" if ("407" in str(e) or "403" in str(e)) else "error"
def raw_forge():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        return "open"
    except (PermissionError, OSError):
        return "blocked"
target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].replace(".", "").isdigit() else "example.com"
addrs = sys.argv[2:] if target != "example.com" else sys.argv[1:]
print(dns(), direct(), host(addrs), proxy(target), raw_forge())
"""

def _probe_image() -> str:
    """The pinned python image the core already uses (no extra pull)."""
    core_file = omstate.CORE_DIR / "compose.yml" if (omstate.CORE_DIR / "compose.yml").exists() else omstate.CORE_DIR / "docker-compose.yml"
    for line in core_file.read_text(encoding="utf-8").splitlines():
        if "image:" in line and "/python:" in line:
            return line.split("image:", 1)[1].strip()
    return ""

def _open_egress_with_data(runtime, wpath: Path, svc: str, mode: str) -> str:
    """'writable volume' / 'secrets' if the service in this workspace folder combines open egress with data it
    could leak and does not waive the rule; '' otherwise."""
    cfiles = [wpath / "compose.yml", wpath / "docker-compose.yml",
              *wpath.glob("*/compose.yml"), *wpath.glob("*/docker-compose.yml"),
              *wpath.glob("*/*/compose.yml"), *wpath.glob("*/*/docker-compose.yml")]
    from gitops import policy
    for cf in cfiles:
        if not cf.is_file():
            continue
        cfg_res = policy.compose_config(runtime, cf, omstate.parse_env_file(omstate.RUNTIME_ENV))
        if not cfg_res or not cfg_res[0]:
            continue
        svc_dict = (cfg_res[0].get("services") or {}).get(svc)
        if not svc_dict:
            continue
        waived = [w.strip() for w in policy._labels(svc_dict).get(policy.ALLOW_LABEL, "").split(",") if w.strip()]
        has_writes, has_secrets = policy._writes(svc_dict), bool(svc_dict.get("secrets"))
        if (has_writes or has_secrets) and "egress" not in waived:
            return "writable volume" if has_writes else "secrets"
    return ""


def _probe_target(members: list[str], rules: dict) -> str:
    """A host to probe: an exact (not wildcard) allowed host of a service on this network, so the probe also shows that
    one service's allowlist does not open the proxy to another; else example.com."""
    for svc_name in members:
        for svc_key, hosts in rules.items():
            if svc_key in svc_name and isinstance(hosts, list):
                for h in hosts:
                    if not h.startswith("*."):
                        return h
    return "example.com"


def _probe_network(runtime, net: str, rules: dict, hosts: list[str]) -> tuple[str, str]:
    """Run the egress probe from inside one internal network: ("open" | "bad" | "noproxy" | "ok", detail)."""
    members = omstate.run([runtime, "ps", "--filter", f"network={net}", "--format", "{{.Names}}"]).stdout.split()
    # where a service may go out, the proxy answers but demands its assigned source IP; elsewhere it is absent
    proxy = "refused" if omstate.EGRESS in members else "error"
    r = omstate.run([runtime, "run", "--rm", "--network", net, "--read-only", "--cap-drop", "ALL",
                     _probe_image(), "python3", "-c", _EGRESS_PROBE, _probe_target(members, rules), *hosts])
    if r.stdout.split() != ["blocked", "blocked", "blocked", proxy, "blocked"]:
        return "bad", f"{net}: {r.stdout.strip() or r.stderr.strip()[-120:]!r} (expected blocked ×3, proxy {proxy}, raw_forge blocked)"
    return ("noproxy" if proxy == "error" else "ok"), net


def _probe_networks(runtime) -> tuple[list, list, list]:
    """(open networks, failed probes, networks with no proxy at all) over every workspace and project network."""
    open_nets, bad, no_proxy = [], [], []
    env = omstate.parse_env_file(omstate.RUNTIME_ENV)
    hosts = [a for a in [env.get("LAN_IP", "")] + omsettings.vpn_hosts() if a and not a.endswith(".invalid") and re.fullmatch(r"[0-9.]+", a)]
    from gitops import egress
    for wid in sorted(wsregistry.read_registry()):
        rules = egress._load_rules(wid)
        for net in [f"{wid}_net"] + enginectl.project_networks(runtime, wid):
            if omstate.run([runtime, "network", "inspect", net]).returncode != 0:
                continue
            if not enginectl.network_is_internal(runtime, net):
                open_nets.append(net)
                continue
            outcome, detail = _probe_network(runtime, net, rules, hosts)
            if outcome == "bad":
                bad.append(detail)
            elif outcome == "noproxy":
                no_proxy.append(net)
    return open_nets, bad, no_proxy


def _learn_status(remaining: int) -> str:
    if remaining == -1:
        return "permanent"
    return f"{remaining // 3600}h {(remaining % 3600) // 60}m left" if remaining > 0 else "expired"


def _open_egress_services(runtime):
    """((status, message, fix) when a service combines open egress with data, else None; services in learn mode;
    services in audit mode)."""
    from gitops import egress
    learning, auditing = [], []
    for wid, info in sorted(wsregistry.read_registry().items()):
        wpath = Path(info.get("path", ""))
        for svc, mode in sorted(egress._load_rules(wid).items()):
            if mode in (egress.LEARN, egress.INTERNET, egress.AUDIT) and wpath.is_dir():
                problem = _open_egress_with_data(runtime, wpath, svc, mode)
                if problem:
                    return (FAIL, f"service '{wid}/{svc}' has {problem} with om.egress={mode} (refused by policy)",
                            "list the hosts it needs or waive with om.policy.allow=egress"), [], []
            if mode == egress.LEARN:
                learning.append(f"{wid}/{svc} ({_learn_status(egress.learn_remaining(wid, svc))})")
            elif mode == egress.AUDIT:
                auditing.append(f"{wid}/{svc}")
    return None, learning, auditing


def check_egress(runtime):
    """Each workspace network: internal (no DNS, no route out) and om_egress enforces source-IP ACLs; cross-service reuse & IP forging blocked."""
    open_nets, bad, no_proxy = _probe_networks(runtime)
    if bad:
        return FAIL, "egress probe failed (expected dns, direct, host addresses blocked; proxy refused without assigned IP; raw forging blocked): " + "; ".join(bad), "om core restart; check egress ACLs and container capabilities; om start"
    refused, learning, auditing = _open_egress_services(runtime)
    if refused:
        return refused
    warns, fixes = [], []
    if open_nets:
        warns.append(f"open network(s) with internet access: {', '.join(open_nets)}")
        fixes.append("cd <workspace> && om network harden (project networks: om start recreates them internal)")
    if learning:
        warns.append(f"in learn mode (any public host allowed): {', '.join(learning)}")
        fixes.append("om egress log <svc> --apply, then list the hosts")
    if auditing:
        warns.append(f"in audit mode (any public host allowed, permanently logged): {', '.join(auditing)}")
        fixes.append("om egress log <svc> to inspect; use om.egress=<hosts> to enforce specific destinations")
    if warns:
        return WARN, "; ".join(warns), "; ".join(fixes)
    return PASS, ("workspace networks are internal; only om_egress leads out (source-IP ACL enforced)"
                  + (f"; no proxy at all on {len(no_proxy)} network(s) without om.egress" if no_proxy else "")), ""

_ISOLATION_PROBE = """
import errno, socket, sys
name, ip = sys.argv[1], sys.argv[2]
def dns():
    try: socket.gethostbyname(name); return "open"
    except OSError: return "blocked"
def direct():
    s = socket.socket(); s.settimeout(3)
    try: s.connect((ip, 80)); return "open"
    except ConnectionRefusedError: return "open"          # an answer, even a refusal, means a path exists
    except OSError: return "blocked"                      # no route / timeout
    finally: s.close()
print(dns(), direct())
"""

def check_project_isolation(runtime):
    """A container on one folder's network cannot reach another folder's service (by name or address)."""
    pairs, bad = 0, []
    for wid in sorted(wsregistry.read_registry()):
        members = {}
        for net in enginectl.project_networks(runtime, wid):
            r = omstate.run([runtime, "ps", "--filter", f"network={net}", "--format", "{{.Names}}"])
            svcs = [m for m in r.stdout.split() if m not in (omstate.ROUTER, omstate.EGRESS, omstate.STREAM_ROUTER)]
            if svcs:
                members[net] = svcs[0]
        nets = sorted(members)
        for a, b in zip(nets, nets[1:] + nets[:1], strict=False) if len(nets) > 1 else []:
            target = members[b]
            ip = omstate.run([runtime, "inspect", "--format", f'{{{{(index .NetworkSettings.Networks "{b}").IPAddress}}}}', target]).stdout.strip()
            if not ip:
                continue
            r = omstate.run([runtime, "run", "--rm", "--network", a, "--read-only", "--cap-drop", "ALL",
                          _probe_image(), "python3", "-c", _ISOLATION_PROBE, target, ip])
            pairs += 1
            if r.stdout.split() != ["blocked", "blocked"]:
                bad.append(f"{a} → {target}: {r.stdout.strip() or r.stderr.strip()[-120:]!r}")
    if bad:
        return FAIL, "a folder's network reaches another folder's service: " + "; ".join(bad), "om core restart; om start in that workspace"
    if not pairs:
        return PASS, "no workspace has two folders with running services to compare", ""
    return PASS, f"folders are isolated from each other ({pairs} pair(s) probed: no name, no route)", ""

def check_generations():
    """Each workspace: generation log chains, and what runs is a clean, signed commit."""
    from gitops import generations
    bad, weak = [], []
    for wid, d in sorted(wsregistry.read_registry().items()):
        if not Path(d.get("path", "")).exists():
            continue
        problems = generations.verify_chain(wid)
        if problems:
            bad.append(f"{wid}: {problems[0]}")
            continue
        cur = generations.current(wid)
        if not cur:
            weak.append(f"{wid}: never deployed through om")
        elif not cur.get("commit"):
            weak.append(f"{wid}: not a git repository")
        elif cur.get("dirty"):
            weak.append(f"{wid}: generation {cur['n']} is dirty (uncommitted files)")
        elif not cur.get("signer"):
            weak.append(f"{wid}: generation {cur['n']} is unsigned")
    if bad:
        return FAIL, "generation log broken: " + "; ".join(bad), "om fsck in that workspace; the state dir may have been edited"
    if weak:
        return WARN, "; ".join(weak), "commit (signed) and `om start`; then OM_SIGNED=enforce in om.env"
    return PASS, "every workspace runs a clean, signed generation; logs chain", ""

# What may listen in the edge container, and where. Anything else is a new door.
_EDGE_LISTENERS = {("tcp", "80"): "any", ("tcp", "443"): "any", ("udp", "443"): "any",
                   ("tcp", "81"): "any", ("tcp", "444"): "any", ("udp", "444"): "any",  # the VPN's private tier
                   ("tcp", "8080"): "any", ("tcp", "8443"): "any", ("udp", "8443"): "any",
                   ("tcp", "2019"): "loopback"}

def check_admin_surface(runtime):
    """Nothing administrative listens where the network can reach it: only the edge ports;
    Caddy's admin API on loopback inside the container."""
    r = omstate.run([runtime, "exec", omstate.EDGE, "netstat", "-lntu"])
    if r.returncode != 0:
        return WARN, "could not list listeners in the edge container", "om core restart"
    bad = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        proto, local = parts[0].rstrip("6"), parts[3]
        addr, _, port = local.rpartition(":")
        where = _EDGE_LISTENERS.get((proto, port))
        if proto == "tcp" and port.isdigit() and any(base <= int(port) < base + omstate.PORT_SLOTS
                                                     for base in (omstate.PRIVATE_PORT_BASE, omstate.PUBLIC_PORT_BASE)):
            where = "any"  # a service's own port (generated from its route)
        if not (where == "any" or (where == "loopback" and addr in ("127.0.0.1", "::1"))):
            bad.append(f"{proto} {local}")
    if bad:
        return FAIL, "unexpected listener(s) in the edge: " + ", ".join(bad), "find what opened it (podman exec om_caddy netstat -lntu); om core restart"
    return PASS, "edge listens only on its web ports and the services' own ports; Caddy admin on loopback only", ""

def check_workspaces_fsck():
    """Every workspace runs what its signed generation and lock say (`om fsck` in each)."""
    import subprocess
    om_bin = omstate.OM_HOME / "bin" / "om"
    bad = []
    for wid, d in sorted(wsregistry.read_registry().items()):
        path = Path(d.get("path", ""))
        if not (path / ".om" / "config.json").exists():
            continue
        r = subprocess.run([sys.executable, str(om_bin), "fsck"], cwd=path, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            first = next((ln.strip() for ln in r.stdout.splitlines() if "✗" in ln), "fsck failed")
            bad.append(f"{wid}: {first.replace(chr(27), '')[:120]}")
    if bad:
        return FAIL, "; ".join(bad), "om fsck in that workspace"
    return PASS, "every workspace's running images match its lock; generation logs chain", ""

def check_custom_routes():
    """Services carrying their own Caddy rules (om.caddy): allowed, but always visible."""
    custom = sorted(f.stem for f in omstate.ROUTES_DIR.glob("*.caddy") if "# custom:" in f.read_text(encoding="utf-8")[:400])
    if custom:
        return PASS, f"own Caddy rules (om.caddy, checked against the allowed directives): {', '.join(custom)}", ""
    return PASS, "no service carries its own Caddy rules", ""

def check_links(runtime):
    """Cross-workspace links: both sides declared, attached, nothing else on their networks."""
    from gitops import links
    found, problems = links.describe(runtime)
    if problems:
        return WARN, "; ".join(problems), "om links — fix the labels, then om start"
    return PASS, f"{len(found)} cross-workspace link(s), each a private network of exactly two services", ""

def check_vpn():
    """Which VPNs reach the private tier; tunnels present but not trusted."""
    trusted = vpndetect.vpn_items(omsettings.load_settings().get("OM_VPN", ""))
    untrusted = [i for i, ip in vpndetect.vpn_candidates() if i not in trusted and ip not in trusted]
    note = (f"; not trusted: {', '.join(untrusted)} (`om vpn trust <iface>` if only your devices are on it)" if untrusted else "")
    hosts = omsettings.vpn_hosts()
    allowed = omsettings.vpn_allow()
    if allowed and hosts and not hostsetup.vpn_allow_enforced():
        return FAIL, (f"OM_VPN_ALLOW ({', '.join(allowed)}) is not in the host firewall: the VPN's private tier is closed"
                      + note), "om firewall apply"
    if allowed and hosts:
        msg = f"only {', '.join(allowed)} reach the private tier over {', '.join(trusted)} (enforced by the firewall); "
        if hostsetup.vpn_fallback_applied():
            return PASS, msg + "other VPN devices get the public tier, at the same address" + note, ""
        if omstate.IS_WINDOWS:
            return PASS, msg + "other VPN devices get the public tier on port 8080 (Windows Firewall cannot redirect)" + note, ""
        return WARN, (msg + "other VPN devices get no answer at the private address, the public tier only on port 8080"
                      + note), "om firewall apply"
    if not hosts:
        return PASS, "no VPN trusted: the private tier is on this machine only" + note, ""
    return PASS, (f"every device on {', '.join(trusted)} reaches the private tier ({', '.join(hosts)}) — keep joining it to devices"
                  " you approve, or list yours with `om vpn allow <device>`" + note), ""

def check_net_policy():
    """Services restricted by address (om.net.allow / om.net.deny): their rules are in the applied firewall."""
    pols = wsregistry.net_policies()
    stale = hostsetup.stale_net_rules()
    missing = [k for k, p in sorted(pols.items()) if not hostsetup.net_policy_enforced(k, p)]
    if missing:
        return FAIL, f"om.net rules not in the host firewall for {', '.join(missing)} (their own ports stay closed)", "om firewall apply"
    if stale:
        return WARN, f"the firewall still restricts {', '.join(stale)} by old om.net rules", "om firewall apply"
    if not pols:
        return PASS, "no service is restricted by address (om.net.allow / om.net.deny)", ""
    return PASS, f"{len(pols)} service(s) restricted by address, enforced by the host firewall: {', '.join(sorted(pols))}", ""

def check_vpn_isolation():
    """A VPN device that sends a *.localhost Host gets nothing: those sites answer this machine only."""
    ips = [h for h in omsettings.vpn_hosts() if re.fullmatch(r"[0-9.]+", h)]
    if not ips:
        return PASS, "no VPN trusted", ""
    code = _http("om-doctor.dashboard.localhost", "/healthz", addr=ips[0])
    if code == 0:
        return PASS, f"*.localhost sites answer this machine only (VPN {ips[0]} with such a Host: refused)", ""
    return FAIL, f"VPN address {ips[0]} answers a *.localhost Host (HTTP {code})", "om core restart (VPN must land on edge :81/:444)"

def check_lan_tier():
    lan = omstate.parse_env_file(omstate.RUNTIME_ENV).get("LAN_IP", "")
    if not lan or lan.endswith(".invalid"):
        return PASS, "LAN tier disabled", ""
    code = _http(lan, "/api/system", addr=lan)
    open_private = []
    for key, slot in sorted(wsregistry.service_slots().items()):
        try:
            with socket.create_connection((lan, omstate.PRIVATE_PORT_BASE + slot), timeout=1):
                open_private.append(f"{key} (:{omstate.PRIVATE_PORT_BASE + slot})")
        except OSError:
            pass
    if open_private:
        return FAIL, f"private service ports answer on the LAN address: {', '.join(open_private)}", "om core restart (ports.yml binds them to loopback and VPN only)"
    if code == 403:
        return PASS, f"LAN tier ({lan}) is public-scoped (/api/system → 403); private service ports closed there", ""
    if code == 0:
        return WARN, f"LAN tier ({lan}) not answering", "om core restart (LAN address may have changed)"
    return FAIL, f"LAN tier returned {code} for /api/system (expected 403)", "Check the :8080 site in core/caddy/Caddyfile"

def check_localhost_dns():
    try:
        socket.getaddrinfo("om-doctor.dashboard.localhost", 80)
        return PASS, "*.localhost resolves on this OS", ""
    except OSError:
        return WARN, "*.localhost names don't resolve for CLI tools on this OS (browsers still resolve them)", \
            "Use browsers for <ws>.<svc>.localhost, or add entries to your hosts file."

def check_firewall():
    st = hostsetup.firewall_status()
    if st == "active" and hostsetup.logging_applied() is False:
        return WARN, "host firewall active, but applied before logging: refusals and connections are not logged", "om firewall apply"
    if st == "active":
        return PASS, "host firewall active; refusals and connections logged (`om firewall log`)", ""
    if st == "unknown":
        return WARN, "host firewall state unknown on this OS", "om firewall apply"
    return WARN, "host firewall not active — any port a program opens is reachable from the LAN", "om firewall apply"

def check_boot(runtime):
    st = hostsetup.boot_status(runtime)
    if st.startswith("enabled") and "only after" not in st:
        return PASS, "containers restart at boot", ""
    if st.startswith("managed"):
        return WARN, st, ""
    return WARN, f"start at boot: {st}", "om boot enable"

def check_token_not_logged(runtime):
    """The edge token never appears in om's own container logs (an unfiltered error log would carry it)."""
    tok = omsettings.edge_token()
    leaked = [c for c in (omstate.EDGE, omstate.ROUTER)
              if tok in (lambda r: r.stdout + r.stderr)(omstate.run([runtime, "logs", c]))]
    if leaked:
        return FAIL, f"the edge token appears in the logs of {', '.join(leaked)}: treat it as known", \
            f"rm {omstate.TOKEN_FILE} && om core restart   (a new token; the logged one becomes useless)"
    return PASS, "the edge token appears in no om log", ""

def check_secrets_tracked():
    """om's program folder must hold no machine state (CA key, edge token, registry)."""
    if migration.legacy_state_present():
        return WARN, f"machine state still inside {omstate.OM_HOME}", "Run any `om` command (e.g. `om status`) to move it out once."
    git_dir = omstate.OM_HOME / ".git"
    if git_dir.exists():
        r = omstate.run(["git", "-C", str(omstate.OM_HOME), "ls-files", "core/data", "core/.env", "core/.runtime.env", "config"])
        if r.stdout.strip():
            return FAIL, "old state files are still tracked by git", "git -C ~/.om rm -r --cached core/data core/.env core/.runtime.env config"
    return PASS, f"program in {omstate.OM_HOME}, state in {omstate.STATE_DIR}", ""

def check_secret_modes():
    """Files that hold secrets are readable by their owner only (POSIX; Windows follows the profile's ACLs)."""
    if omstate.IS_WINDOWS:
        return PASS, "Windows: secret files follow your profile's permissions", ""
    from gitops import agesecrets, egress
    files = [omstate.TOKEN_FILE, omstate.RUNTIME_ENV, agesecrets.KEY_FILE,
             *egress.EGRESS_DIR.glob("creds/*"), *egress.EGRESS_DIR.glob("overrides/*")]
    loose = [f"{p.name} ({p.stat().st_mode & 0o777:o})" for p in files if p.is_file() and p.stat().st_mode & 0o077]
    if loose:
        return WARN, "secret files readable by other users: " + ", ".join(loose), f"chmod 600 {' '.join(str(p) for p in files if p.is_file())}"
    return PASS, "edge token, age key and egress credentials are readable by you only", ""

def check_orphan_routes():
    """Routes of workspaces whose folder is gone (deleted without `om remove`)."""
    reg = wsregistry.read_registry()
    orphans = set()
    for f in omstate.ROUTES_DIR.glob("*") if omstate.ROUTES_DIR.is_dir() else []:
        try:
            m = migration._GENERATED_ROUTE_RE.search(f.read_text(encoding="utf-8")[:400])
        except OSError:
            continue
        ws = m.group(1) if m else None
        if ws and ws != "core":
            path = reg.get(ws, {}).get("path")
            if not (path and (Path(path) / ".om" / "config.json").is_file()):
                orphans.add(ws)
    if orphans:
        return WARN, f"routes left by missing workspace(s): {', '.join(sorted(orphans))}", "om core reload   (prunes them once their containers are stopped)"
    return PASS, "every route belongs to an existing workspace", ""

def check_registry():
    missing = [w for w, d in wsregistry.read_registry().items() if not Path(d.get("path", "")).exists()]
    if missing:
        return WARN, f"workspace folder(s) missing: {', '.join(missing)}", "Reconnect the drive, or `om list --prune`."
    return PASS, f"{len(wsregistry.read_registry())} workspace(s) registered", ""

def check_private_reach():
    """Who the private tier answers: this machine, and the VPN's devices (all of them, or the allow-list)."""
    t = exposure.tiers()
    vpn = t["vpn"]
    if vpn["trusted"] and not vpn["allow_list"] and not t["login"]:
        return (WARN, f"every device on {'/'.join(vpn['trusted'])} reaches your private services (no device allow-list, no login)",
                "om vpn allow <a device of yours>, or om auth add <user>")
    parts = ["this machine"]
    if vpn["trusted"]:
        parts.append("VPN: " + (", ".join(vpn["allow_list"]) if vpn["allow_list"] else "every device") + (", behind a login" if t["login"] else ""))
    return PASS, "private tier reached by " + "; ".join(parts) + " (om exposure shows each service)", ""


def check_auth():
    if any(omstate.AUTH_DIR.glob("*.conf")):
        return PASS, "private tier requires login", ""
    trusted = {u.strip() for u in omsettings.load_settings().get("OM_TRUSTED_USERS", "").split(",") if u.strip()}
    others = [u for u in _other_login_users() if u not in trusted]
    if others:
        return FAIL, f"private tier has no login and other people can log in here ({', '.join(others)}): they can use your services",\
            "om auth add <user>  (or, if they are yours: OM_TRUSTED_USERS=<user> in om.env)"
    return PASS, "no login on the private tier: only you use this machine; your VPN decides who else reaches it", ""


def check_stream_published_ports(runtime):
    """Only declared stream ports (default range 22000-22199 and explicit ports from stream_ports.json)
    are published on om_stream_edge, and no other container publishes stream ports."""
    st_ports = wsregistry.stream_ports()
    declared_ports = {omstate.STREAM_PORT_BASE + i for i in range(omstate.STREAM_PORT_SLOTS)}
    for info in st_ports.values():
        hp = info.get("host_port")
        if hp:
            declared_ports.add(hp)

    # Inspect om_stream_edge
    r = omstate.run([runtime, "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    edge_ports_str = ""
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if name == omstate.STREAM_EDGE:
            edge_ports_str = ports
            break

    published = set()
    for part in edge_ports_str.split(","):
        part = part.strip()
        if "->" not in part:
            continue
        host_side = part.split("->")[0].rpartition(":")[2]
        if "-" in host_side:
            lo, hi = host_side.split("-", 1)
            if lo.isdigit() and hi.isdigit():
                for p in range(int(lo), int(hi) + 1):
                    published.add(p)
        elif host_side.isdigit():
            published.add(int(host_side))

    undeclared = sorted(published - declared_ports)
    if undeclared:
        return FAIL, f"undeclared port(s) published on {omstate.STREAM_EDGE}: {', '.join(map(str, undeclared))}", \
            "om core restart (ports.yml binds only declared stream ports)"

    # Check that no other container publishes declared or default stream ports
    leaks = []
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if name in (omstate.EDGE, omstate.STREAM_EDGE):
            continue
        for part in ports.split(","):
            if "->" not in part:
                continue
            host_side = part.split("->")[0].rpartition(":")[2]
            p_val = int(host_side) if host_side.isdigit() else None
            if p_val and p_val in declared_ports:
                leaks.append(f"{name} (:{p_val})")

    if leaks:
        return FAIL, f"containers publish stream ports, bypassing stream proxy: {'; '.join(leaks)}", \
            "om core restart (ports.yml binds only declared stream ports)"

    return PASS, "only declared stream ports are bound/published", ""


def check_stream_firewall():
    """A host firewall rule exists for each declared stream port."""
    if hostsetup.firewall_status() != "active":
        return WARN, "host firewall is not active (`om firewall apply` to enforce perimeter)", "om firewall apply"

    st_priv, st_pub = hostsetup.stream_firewall_ports()

    if omstate.IS_LINUX:
        nft_text = hostsetup._read(hostsetup.NFT_INSTALLED)
        if not nft_text:
            return FAIL, "applied host firewall (/etc/om-firewall.nft) is empty or missing", "om firewall apply"
        missing = []
        for p in st_pub:
            pattern = re.compile(rf"tcp\s+dport\s+{{?[^}}]*\b{re.escape(p)}\b[^}}]*}}?\s+accept")
            if not pattern.search(nft_text):
                missing.append(p)
        ips = hostsetup.vpn_ips()
        if ips and st_priv:
            for p in st_priv:
                pattern = re.compile(rf"ip\s+daddr\s+{{?[^}}]*}}\s+tcp\s+dport\s+{{?[^}}]*\b{re.escape(p)}\b[^}}]*}}?\s+accept")
                if not pattern.search(nft_text):
                    missing.append(p)
        if missing:
            return FAIL, f"firewall rule missing for stream port(s): {', '.join(sorted(set(missing)))}", "om firewall apply"
    elif omstate.IS_MACOS:
        pf_text = hostsetup._read(hostsetup.PF_INSTALLED)
        if not pf_text:
            return FAIL, "applied host firewall (/etc/pf.anchors/om) is empty or missing", "om firewall apply"
        missing = []
        for p in st_pub:
            if f"port {{ {p} }}" not in pf_text and f"port {p}" not in pf_text:
                missing.append(p)
        if missing:
            return FAIL, f"firewall rule missing for stream port(s): {', '.join(sorted(set(missing)))}", "om firewall apply"
    elif omstate.IS_WINDOWS:
        r = omstate.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      "Get-NetFirewallRule -Group om -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"])
        names = set(r.stdout.splitlines()) if r.returncode == 0 else set()
        if st_pub and not any("om public stream ports" in n for n in names):
            return FAIL, "firewall rule missing for public stream ports", "om firewall apply"

    return PASS, "a firewall rule exists for each stream port", ""


_STREAM_ISOLATION_PROBE = """
import socket, sys

def probe(host, port, timeout=2.0):
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return "unreachable"
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "unreachable"
    finally:
        s.close()

results = [probe(h, int(p)) for h, p in [arg.split(":") for arg in sys.argv[1:]]]
print(" ".join(results))
"""

def check_stream_isolation(runtime):
    """From inside a workspace container, om_stream_router and om_stream_edge are unreachable
    (expect refused/timeout), and a different workspace's stream target is unreachable."""
    st_ports = wsregistry.stream_ports()
    reg = wsregistry.read_registry()
    checked = 0

    for wid in sorted(reg):
        net = f"{wid}_net"
        if omstate.run([runtime, "network", "inspect", net]).returncode != 0:
            continue

        other_targets = []
        for other_key, info in st_ports.items():
            other_ws, _, other_svc = other_key.partition("/")
            if other_ws != wid:
                cport = info.get("container_port", 25565)
                other_targets.append(f"{other_ws}_{other_svc}:{cport}")

        probe_args = [f"{omstate.STREAM_EDGE}:22000", f"{omstate.STREAM_ROUTER}:1"]
        if other_targets:
            probe_args.append(other_targets[0])

        r = omstate.run([runtime, "run", "--rm", "--network", net, "--read-only", "--cap-drop", "ALL",
                      _probe_image(), "python3", "-c", _STREAM_ISOLATION_PROBE, *probe_args])
        statuses = r.stdout.split()
        if not statuses:
            continue

        checked += 1
        edge_status = statuses[0] if len(statuses) > 0 else "error"
        router_status = statuses[1] if len(statuses) > 1 else "error"
        other_status = statuses[2] if len(statuses) > 2 else "unreachable"

        if edge_status == "open":
            return FAIL, f"from {net}: {omstate.STREAM_EDGE} is directly reachable over network", \
                "Ensure om_stream_edge is only on om_core_net and om_stream_router has no network listener"

        if router_status == "open":
            return FAIL, f"from {net}: {omstate.STREAM_ROUTER} has an open network port", \
                "Ensure om_stream_edge is only on om_core_net and om_stream_router has no network listener"

        if other_status == "open":
            return FAIL, f"from {net}: cross-workspace stream target {probe_args[2]} is reachable", \
                "Ensure om_stream_edge is only on om_core_net and om_stream_router has no network listener"

    if not checked:
        return PASS, "no workspace networks available to probe stream isolation", ""
    return PASS, f"stream router and edge are isolated from workspace containers ({checked} network(s) probed)", ""


# (title, check function, takes the engine runtime). In three stages: the basics; the perimeter checks, which
# need a running core (skipped when the basics fail); the host checks, which always run.
BASIC_CHECKS = (
    ("Python", check_python, False), ("Engine", check_engine, True), ("Compose", check_compose, True),
    ("Ports", check_ports, True), ("Core", check_core, True),
)
PERIMETER_CHECKS = (
    ("Router", check_router_networks, True), ("Edge isolation", check_edge_isolated, True),
    ("Published ports", check_published_ports, True), ("Address drift", check_drift, True),
    ("Private tier", check_private_reachable, False), ("DNS rebinding", check_rebinding, False),
    ("Router token", check_router_token, True), ("Token not logged", check_token_not_logged, True),
    ("Engine filter", check_engine_filter, True), ("Admin surface", check_admin_surface, True),
    ("Running = lock", check_workspaces_fsck, False), ("Egress", check_egress, True),
    ("Project isolation", check_project_isolation, True), ("Generations", check_generations, False),
    ("LAN tier", check_lan_tier, False), ("VPN", check_vpn, False), ("VPN isolation", check_vpn_isolation, False),
    ("Address rules", check_net_policy, False), ("Links", check_links, True), ("Custom routes", check_custom_routes, False),
    ("Healthchecks", check_healthchecks, True), ("Stream ports", check_stream_published_ports, True),
    ("Stream firewall", check_stream_firewall, False), ("Stream isolation", check_stream_isolation, True),
)
HOST_CHECKS = (
    (".localhost DNS", check_localhost_dns, False), ("Firewall", check_firewall, False), ("Boot", check_boot, True),
    ("Login", check_auth, False), ("Private reach", check_private_reach, False), ("Secret files", check_secret_modes, False), ("State", check_secrets_tracked, False),
    ("Registry", check_registry, False), ("Orphan routes", check_orphan_routes, False),
)


def _run_checks(checks, runtime: str) -> list:
    return [(title, *fn(*((runtime,) if takes_runtime else ()))) for title, fn, takes_runtime in checks]


def run_doctor(runtime: str, as_json: bool = False) -> int:
    results = _run_checks(BASIC_CHECKS, runtime)
    if results[-1][1] == PASS and results[1][1] == PASS:  # the core runs on a working engine
        results += _run_checks(PERIMETER_CHECKS, runtime)
    results += _run_checks(HOST_CHECKS, runtime)

    fails = sum(1 for r in results if r[1] == FAIL)
    if as_json:
        print(json.dumps({"version": omstate.VERSION, "runtime": runtime, "failures": fails,
                          "warnings": sum(1 for r in results if r[1] == WARN),
                          "checks": [{"check": t, "status": st, "detail": m, "fix": f} for t, st, m, f in results]}, indent=2))
        return 1 if fails else 0
    colors = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m"}
    print(f"\n\033[1mom doctor\033[0m  (om {omstate.VERSION}, {runtime})")
    print("═" * 78)
    for title, status, msg, fix in results:
        print(f"  {colors[status]}{status}\033[0m  {title:<16} {msg}")
        if fix and status != PASS:
            print(f"        ↳ {fix}")
    fails = sum(1 for r in results if r[1] == FAIL)
    warns = sum(1 for r in results if r[1] == WARN)
    print("─" * 78)
    print(f"  {fails} failure(s), {warns} warning(s)\n")
    return 1 if fails else 0
