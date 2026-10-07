#!/usr/bin/env python3
"""
doctor.py — `om doctor`: verify the installation, the network perimeter and common
failure modes, and print a concrete fix for every problem found.

Each check returns (status, message, fix) with status in PASS / WARN / FAIL.
"""

import os
import re
import sys
import json
import socket
import urllib.error
import urllib.request
from pathlib import Path

from gitops import core, hostsetup

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


def _http(host_header: str, path: str = "/", addr: str = "127.0.0.1", port: int | None = None, timeout: float = 3.0):
    """HTTP status for a request, 0 if the connection was refused/aborted."""
    port = port or core.edge_ports()[0]
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
    eng = core.engine_info(runtime)
    if not eng["ok"]:
        return FAIL, f"{runtime} not responding", "Start your container engine (`podman machine start`, Docker Desktop, or `systemctl start docker`)."
    mode = ("rootless" if eng["rootless"] else "rootful") + (", VM" if eng["remote_vm"] else "")
    return PASS, f"{runtime} ({mode}), socket {eng['socket']}", ""

def check_compose(runtime):
    if core.compose_available(runtime):
        return PASS, f"`{runtime} compose` available", ""
    return FAIL, f"`{runtime} compose` missing", "Install docker-compose v2 (or podman-compose)."

def check_ports(runtime):
    eng = core.engine_info(runtime)
    if core.IS_LINUX and eng["rootless"] and not eng["remote_vm"]:
        start, low = core.unprivileged_port_start(), min(core.edge_ports())
        if start is not None and start > low:
            return FAIL, f"unprivileged ports start at {start}", \
                f"echo 'net.ipv4.ip_unprivileged_port_start={low}' | sudo tee /etc/sysctl.d/99-om.conf && sudo sysctl --system"
    return PASS, f"can bind {'/'.join(map(str, core.edge_ports()))}", ""

def check_core(runtime):
    down = [c for c in core.CORE_CONTAINERS if not core.container_running(runtime, c)]
    if down:
        return FAIL, f"not running: {', '.join(down)}", "om core start"
    retired = [c for c in core.RETIRED_CONTAINERS if core.run([runtime, "container", "inspect", c]).returncode == 0]
    if retired:
        return WARN, f"removed parts still present: {', '.join(retired)}", "om core restart"
    return PASS, f"{', '.join(core.CORE_CONTAINERS)} running", ""

def check_router_networks(runtime):
    want = {f"{w}_net" for w in core.read_registry()}
    r = core.run([runtime, "inspect", core.ROUTER, "--format", "{{json .NetworkSettings.Networks}}"])
    try:
        have = set(json.loads(r.stdout).keys())
    except Exception:
        return WARN, "could not inspect router networks", "om core restart"
    missing = sorted(want - have)
    if missing:
        return FAIL, f"router not attached to {', '.join(missing)} (those workspaces are unreachable)", "om core start"
    return PASS, f"router attached to {len(want)} workspace network(s)", ""

def check_edge_isolated(runtime):
    r = core.run([runtime, "inspect", core.EDGE, "--format", "{{json .NetworkSettings.Networks}}"])
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
    r = core.run([runtime, "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    leaks = []
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if name in core.CORE_CONTAINERS or "->" not in ports:
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
        return PASS, f"private tier answers on {core.base_url()}/", ""
    return FAIL, f"{core.base_url()}/ returned {code or 'no answer'}", "om core restart; then om doctor"

def check_router_token(runtime):
    """A request without the edge token must be refused by the router (probed from inside it; caddy images ship busybox wget)."""
    r = core.run([runtime, "exec", core.ROUTER, "wget", "-q", "-T", "3", "-O", "-", "--header", "X-Om-Upstream: om_dashboard:80", "http://127.0.0.1:8000/"])
    if r.returncode != 0:
        return PASS, "router refuses requests without the edge token", ""
    return FAIL, "router forwarded a request without the edge token", "Check core/caddy/router/Caddyfile and data/edge_token in the om state dir; om core restart"

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
    r = core.run([runtime, "exec", "om_dashboard", "python3", "-c", _SOCK_PROBE])
    if r.stdout.split() == ["0", "200", "403"]:
        return PASS, "dashboard has read-only engine access (writes → 403, no raw socket)", ""
    return FAIL, f"engine filter probe returned {r.stdout.strip() or r.stderr.strip()[-200:]!r} (expected '0 200 403')", "om core restart; check core/caddy/sockguard/Caddyfile"

_EGRESS_PROBE = """
import socket, urllib.request
def dns():
    try: socket.gethostbyname("example.com"); return "open"
    except OSError: return "blocked"
def direct():
    try: socket.create_connection(("1.1.1.1", 443), timeout=4); return "open"
    except OSError: return "blocked"
def host():
    import sys
    for addr in sys.argv[1:]:
        for port in (22, 80, 443, 2019, 9091):
            try: socket.create_connection((addr, port), timeout=2); return f"open:{addr}:{port}"
            except OSError: pass
    return "blocked"
def proxy():
    h = urllib.request.ProxyHandler({"https": "http://om_egress:3128"})
    try: urllib.request.build_opener(h).open("https://example.com/", timeout=8); return "open"
    except Exception as e: return "refused" if ("407" in str(e) or "403" in str(e)) else "error"
print(dns(), direct(), host(), proxy())
"""

def _probe_image() -> str:
    """The pinned python image the core already uses (no extra pull)."""
    for line in (core.CORE_DIR / "docker-compose.yml").read_text(encoding="utf-8").splitlines():
        if "image:" in line and "/python:" in line:
            return line.split("image:", 1)[1].strip()
    return ""

def check_egress(runtime):
    """Each workspace network: internal (no DNS, no route out) and om_egress demands a credential."""
    open_nets, bad = [], []
    for wid in sorted(core.read_registry()):
        net = f"{wid}_net"
        if core.run([runtime, "network", "inspect", net]).returncode != 0:
            continue
        if not core.network_is_internal(runtime, net):
            open_nets.append(wid)
            continue
        env = core.parse_env_file(core.RUNTIME_ENV)
        hosts = [a for a in [env.get("LAN_IP", "")] + core.vpn_hosts() if a and not a.endswith(".invalid") and re.fullmatch(r"[0-9.]+", a)]
        r = core.run([runtime, "run", "--rm", "--network", net, "--read-only", "--cap-drop", "ALL",
                      _probe_image(), "python3", "-c", _EGRESS_PROBE, *hosts])
        if r.stdout.split() != ["blocked", "blocked", "blocked", "refused"]:
            bad.append(f"{wid}: {r.stdout.strip() or r.stderr.strip()[-120:]!r}")
    if bad:
        return FAIL, "egress probe failed (expected dns, direct, host addresses blocked; proxy refused without credential): " + "; ".join(bad), "om core restart; om network harden"
    from gitops import egress
    learning = [f"{f.stem}/{svc}" for f in sorted((egress.EGRESS_DIR / "creds").glob("*.rules"))
                for svc, h in sorted(egress._load_rules(f.stem).items()) if h == egress.LEARN]
    warns, fixes = [], []
    if open_nets:
        warns.append(f"open network(s) with internet access: {', '.join(open_nets)}")
        fixes.append("cd <workspace> && om network harden")
    if learning:
        warns.append(f"in learn mode (any public host allowed): {', '.join(learning)}")
        fixes.append("om egress log --all, then replace om.egress=learn with the listed hosts")
    if warns:
        return WARN, "; ".join(warns), "; ".join(fixes)
    return PASS, "workspace networks are internal; only om_egress leads out, per-service credential required", ""

def check_generations():
    """Each workspace: generation log chains, and what runs is a clean, signed commit."""
    from gitops import generations
    bad, weak = [], []
    for wid, d in sorted(core.read_registry().items()):
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
                   ("tcp", "8080"): "any", ("tcp", "8443"): "any", ("udp", "8443"): "any",
                   ("tcp", "2019"): "loopback"}

def check_admin_surface(runtime):
    """Nothing administrative listens where the network can reach it: only the edge ports;
    Caddy's admin API on loopback inside the container."""
    r = core.run([runtime, "exec", core.EDGE, "netstat", "-lntu"])
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
        if not (where == "any" or (where == "loopback" and addr in ("127.0.0.1", "::1"))):
            bad.append(f"{proto} {local}")
    if bad:
        return FAIL, "unexpected listener(s) in the edge: " + ", ".join(bad), "find what opened it (podman exec om_caddy netstat -lntu); om core restart"
    return PASS, "edge listens only on its web ports; Caddy admin on loopback only", ""

def check_workspaces_fsck():
    """Every workspace runs what its signed generation and lock say (`om fsck` in each)."""
    import subprocess
    om_bin = core.OM_HOME / "bin" / "om"
    bad = []
    for wid, d in sorted(core.read_registry().items()):
        path = Path(d.get("path", ""))
        if not (path / ".om" / "config.json").exists():
            continue
        r = subprocess.run([sys.executable, str(om_bin), "fsck"], cwd=path, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            first = next((l.strip() for l in r.stdout.splitlines() if "✗" in l), "fsck failed")
            bad.append(f"{wid}: {first.replace(chr(27), '')[:120]}")
    if bad:
        return FAIL, "; ".join(bad), "om fsck in that workspace"
    return PASS, "every workspace's running images match its lock; generation logs chain", ""

def check_vpn():
    """Which VPN reaches the private tier; with Tailscale, whether Tailnet Lock guards who joins."""
    hosts = core.vpn_hosts()
    if not hosts:
        return PASS, "no VPN: the private tier is on this machine only (OM_VPN)", ""
    ip, _ = core.detect_tailscale()
    if ip and ip in hosts:
        cli = core.tailscale_cli()
        out = core.run([cli, "lock", "status"]).stdout if cli else ""
        if "enabled" in out.lower() and "not enabled" not in out.lower():
            return PASS, f"Tailscale ({ip}) with Tailnet Lock: only devices you sign can join", ""
        return WARN, f"Tailscale ({ip}) without Tailnet Lock: whoever controls your Tailscale login (or its servers) can add a device that reaches the private tier", \
            "tailscale lock init --gen-disablements 1 --confirm <trusted node keys>   (see `tailscale lock` docs; keep the disablement secret offline)"
    return PASS, f"VPN address(es) {', '.join(hosts)} reach the private tier (keys you hold decide who joins)", ""

def check_lan_tier():
    lan = core.parse_env_file(core.RUNTIME_ENV).get("LAN_IP", "")
    if not lan or lan.endswith(".invalid"):
        return PASS, "LAN tier disabled", ""
    code = _http(lan, "/api/system", addr=lan)
    if code == 403:
        return PASS, f"LAN tier ({lan}) is public-scoped (/api/system → 403)", ""
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
    if st == "active":
        return PASS, "host firewall active", ""
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

def check_secrets_tracked():
    """om's program folder must hold no machine state (CA key, edge token, registry)."""
    if core.legacy_state_present():
        return WARN, f"machine state still inside {core.OM_HOME}", "Run any `om` command (e.g. `om status`) to move it out once."
    git_dir = core.OM_HOME / ".git"
    if git_dir.exists():
        r = core.run(["git", "-C", str(core.OM_HOME), "ls-files", "core/data", "core/.env", "core/.runtime.env", "config"])
        if r.stdout.strip():
            return FAIL, "old state files are still tracked by git", "git -C ~/.om rm -r --cached core/data core/.env core/.runtime.env config"
    return PASS, f"program in {core.OM_HOME}, state in {core.STATE_DIR}", ""

def check_orphan_routes():
    """Routes of workspaces whose folder is gone (deleted without `om remove`)."""
    reg = core.read_registry()
    orphans = set()
    for f in core.ROUTES_DIR.glob("*") if core.ROUTES_DIR.is_dir() else []:
        try:
            m = core._GENERATED_ROUTE_RE.search(f.read_text(encoding="utf-8")[:400])
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
    missing = [w for w, d in core.read_registry().items() if not Path(d.get("path", "")).exists()]
    if missing:
        return WARN, f"workspace folder(s) missing: {', '.join(missing)}", "Reconnect the drive, or `om list --prune`."
    return PASS, f"{len(core.read_registry())} workspace(s) registered", ""

def _other_login_users() -> list[str]:
    """Other human accounts on this machine (Linux/macOS passwd; uid >= 1000 with a login shell)."""
    try:
        import pwd
        me = os.getuid()
        return sorted(u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000 and u.pw_uid != me and u.pw_uid < 60000
                      and not u.pw_shell.endswith(("nologin", "false")))
    except (ImportError, AttributeError):
        return []

def check_auth():
    if any(core.AUTH_DIR.glob("*.conf")):
        return PASS, "private tier requires login", ""
    others = _other_login_users()
    if others:
        return WARN, f"private tier has no login and other people can log in here ({', '.join(others)}): they can use your services",\
            "om auth add <user>"
    return PASS, "no login on the private tier: only you use this machine; your VPN decides who else reaches it", ""


def run_doctor(runtime: str) -> int:
    checks = [
        ("Python", check_python, ()), ("Engine", check_engine, (runtime,)), ("Compose", check_compose, (runtime,)),
        ("Ports", check_ports, (runtime,)), ("Core", check_core, (runtime,)),
    ]
    results = []
    for title, fn, args in checks:
        results.append((title, *fn(*args)))
    core_ok = results[-1][1] == PASS and results[1][1] == PASS
    if core_ok:
        for title, fn, args in [
            ("Router", check_router_networks, (runtime,)), ("Edge isolation", check_edge_isolated, (runtime,)),
            ("Published ports", check_published_ports, (runtime,)), ("Address drift", check_drift, (runtime,)),
            ("Private tier", check_private_reachable, ()), ("DNS rebinding", check_rebinding, ()),
            ("Router token", check_router_token, (runtime,)), ("Engine filter", check_engine_filter, (runtime,)),
            ("Admin surface", check_admin_surface, (runtime,)), ("Running = lock", check_workspaces_fsck, ()),
            ("Egress", check_egress, (runtime,)), ("Generations", check_generations, ()), ("LAN tier", check_lan_tier, ()),
            ("VPN", check_vpn, ()),
        ]:
            results.append((title, *fn(*args)))
    for title, fn, args in [
        (".localhost DNS", check_localhost_dns, ()), ("Firewall", check_firewall, ()), ("Boot", check_boot, (runtime,)),
        ("Login", check_auth, ()), ("State", check_secrets_tracked, ()), ("Registry", check_registry, ()),
        ("Orphan routes", check_orphan_routes, ()),
    ]:
        results.append((title, *fn(*args)))

    colors = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m"}
    print(f"\n\033[1mom doctor\033[0m  (om {core.VERSION}, {runtime})")
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
