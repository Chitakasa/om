#!/usr/bin/env python3
"""Pure route logic for 'om': compose labels, route options, service metadata, the om.caddy snippet
validator and the Caddy vhost/alias renderers. No engine or registry access (bin/om applies them)."""

from __future__ import annotations

import ipaddress
import re

from gitops import omsettings, omstate

# Compose labels that shape a service's routes; om itself never special-cases a service name.
#   om.route.keep_prefix=true          the app serves under /<svc>/ (its own base URL): its root redirects there
#   om.route.aliases=/a,/b             top-level paths on the dashboard's address redirected to the service's
#                                      own port (path and query kept: /a/x?q -> http://<host>:<port>/a/x?q)
#   om.route.dashboard_paths=/api/x*   paths on the service's address answered by the om dashboard instead
LABEL_RE = re.compile(r"""^-?\s*["']?((?:dashboard|om)\.[a-z0-9_.]+)\s*[=:]\s*["']?(.*?)["']?\s*$""")
ROUTE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]*\*?$")

def compose_labels(content: str) -> dict[str, str]:
    """dashboard.* / om.* labels of a compose file, in list (`- k=v`) or map (`k: v`) form."""
    labels = {}
    for line in content.splitlines():
        m = LABEL_RE.match(line.strip())
        if m:
            labels[m.group(1)] = m.group(2).strip()
    return labels

def label_paths(labels: dict[str, str], key: str, sname: str) -> list[str]:
    """Comma-separated route paths from a label. Anything that is not a plain path is dropped,
    so a compose file can never inject Caddy directives into the edge config."""
    paths = []
    for p in (x.strip() for x in labels.get(key, "").split(",")):
        if not p:
            continue
        if ROUTE_PATH_RE.match(p) and "//" not in p and "/../" not in p + "/":
            paths.append(p)
        else:
            print(f"  \033[33m⚠ {sname}: ignoring invalid path '{p}' in {key}\033[0m")
    return paths

# Who may connect to a service's own ports, by source address (IPv4/IPv6 address or CIDR range):
#   om.net.allow=100.101.0.7,192.168.1.0/24   only these (and this machine)
#   om.net.deny=192.168.1.66                   everyone but these (deny wins over allow)
# Enforced by the host firewall (`om firewall apply`): the edge cannot see client addresses, because
# rootless port forwarding hands it every connection from one internal address.
NET_ALLOW, NET_DENY = "om.net.allow", "om.net.deny"
# om.net.allow=vpn: the devices on the VPN allow-list (OM_VPN_ALLOW, `om vpn allow`). Kept as the word in
# the policy and expanded by the firewall when it renders, so the label follows the list.
VPN_KEYWORD = "vpn"

def net_policy(labels: dict[str, str], vpn_allow: list[str] | None = None) -> tuple[dict | None, list[str]]:
    """({"allow": [...] | None, "deny": [...]}, problems), or (None, []) when neither label is set.
    allow None = no allow-list; an empty list never occurs (an all-invalid label is a problem)."""
    out, problems = {}, []
    for key, field in ((NET_ALLOW, "allow"), (NET_DENY, "deny")):
        items = [x.strip() for x in labels.get(key, "").split(",") if x.strip()]
        nets, keyword = [], False
        for x in items:
            if x.lower() == VPN_KEYWORD:
                if field == "deny":
                    problems.append(f"{key}: `{VPN_KEYWORD}` is only for {NET_ALLOW}")
                elif not (omsettings.vpn_allow() if vpn_allow is None else vpn_allow):
                    problems.append(f"{key}: `{VPN_KEYWORD}` needs a VPN allow-list first (om vpn allow <device>)")
                else:
                    keyword = True
                continue
            try:
                nets.append(ipaddress.ip_network(x, strict=False))
            except ValueError:
                problems.append(f"{key}: `{x}` is not an IP address or range")
        if items:
            out[field] = ([VPN_KEYWORD] if keyword else []) + \
                [str(n) for n in sorted(set(nets), key=lambda n: (n.version, n.network_address, n.prefixlen))]
    if not out:
        return None, problems
    return {"allow": out.get("allow"), "deny": out.get("deny", [])}, problems

def route_options(content: str, sname: str, labels: dict | None = None) -> dict:
    labels = compose_labels(content) if labels is None else labels
    net, net_problems = net_policy(labels)
    return {
        "keep_prefix": labels.get("om.route.keep_prefix", "").lower() == "true",
        "aliases": [p.rstrip("*").rstrip("/") for p in label_paths(labels, "om.route.aliases", sname)],
        "dashboard_paths": label_paths(labels, "om.route.dashboard_paths", sname),
        "net": net,
        "net_problems": net_problems,
        # om.log=off: no access log at the edge and no connection log in the firewall for this service
        "log": "off" if labels.get("om.log", "").strip().lower() == "off" else "on",
    }

def config_meta(cfg: dict, sname: str) -> tuple[tuple[int, bool, bool], dict]:
    """((port, is_public, no_web), dashboard.*/om.* labels) from the engine's normalized `compose config`:
    no regex over YAML, so comments, anchors and multi-line values cannot mislead it."""
    labels, expose = {}, []
    for svc in ((cfg or {}).get("services") or {}).values():
        raw = (svc or {}).get("labels") or {}
        if isinstance(raw, list):
            raw = dict(ln.split("=", 1) if "=" in ln else (ln, "") for ln in raw)
        labels.update({str(k): str(v) for k, v in raw.items() if str(k).startswith(("dashboard.", "om."))})
        expose += [str(e).split("/")[0] for e in (svc or {}).get("expose") or []]
        # `ports:` (refused by the policy gate, but run under OM_POLICY=warn): the container side
        expose += [str(p.get("target", "")) for p in (svc or {}).get("ports") or [] if isinstance(p, dict)]
    port = labels.get("dashboard.port", "")
    exposed = next((int(e) for e in expose if e.isdigit()), None)
    return ((int(port) if port.isdigit() else exposed or 8080),
            labels.get("dashboard.scope", "").lower() == "public",
            labels.get("dashboard.web", "").lower() == "false"), labels

def parse_service_meta(content: str, sname: str) -> tuple[int, bool, bool]:
    """Extract (port, is_public, no_web) from a compose file. Public requires an explicit dashboard.scope=public."""
    label_port = None
    mapped_port = None
    scope = None
    no_web = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "dashboard.port=" in line or "dashboard.port:" in line:
            p_str = line.split("dashboard.port")[1].lstrip("=: ").strip('"').strip("'")
            if p_str.isdigit():
                label_port = int(p_str)
        elif "dashboard.scope=" in line or "dashboard.scope:" in line:
            scope = line.split("dashboard.scope")[1].lstrip("=: ").strip('"').strip("'").lower()
        elif "dashboard.web=" in line or "dashboard.web:" in line:
            no_web = line.split("dashboard.web")[1].lstrip("=: ").strip('"').strip("'").lower() == "false"
        elif line.startswith("-") and not line.startswith("- /"):
            cand = line[1:].strip().strip('"').strip("'")
            if cand.isdigit():
                mapped_port = int(cand)
            elif ":" in cand and cand.split(":")[-1].split("/")[0].isdigit():
                mapped_port = int(cand.split(":")[-1].split("/")[0])
    return label_port or mapped_port or 8080, scope == "public", no_web

# A service's own Caddy rules: `om.caddy` next to its compose file, added to all of its sites
# (its .localhost name and its own ports) and run before om proxies the request. Only directives
# that shape the request or the answer are allowed: nothing that reads files, reaches another
# upstream, or reads om's environment (the edge token is in it). Checked by validate_snippet.
SNIPPET_FILE = "om.caddy"
SNIPPET_CONTAINERS = {"handle", "handle_path", "route"}
SNIPPET_DIRECTIVES = SNIPPET_CONTAINERS | {"header", "request_header", "redir", "rewrite", "uri", "respond",
                                           "encode", "basic_auth", "request_body", "error", "abort", "vars",
                                           "map", "method"}
SNIPPET_MATCHERS = {"path", "path_regexp", "host", "method", "header", "header_regexp", "query",
                    "protocol", "expression", "not", "vars", "vars_regexp"}
SNIPPET_FORBIDDEN = ("{$", "{env.", "{file.", "<<", "import")
# The edge sees every client as one internal address (rootless port forwarding), so a rule on the
# client address would match everyone or no one: refused, pointing to om.net.allow / om.net.deny.
SNIPPET_CLIENT_ADDRESS = ("remote_ip", "client_ip", "{remote", "{http.request.remote")

def validate_snippet(text: str) -> list[str]:
    """Problems in a service's om.caddy (empty = allowed). Context-aware: directives where
    directives go, matcher types inside @matcher blocks, other blocks' contents unchecked except
    for the forbidden placeholders, which are refused anywhere."""
    problems, stack = [], ["directives"]
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for bad in SNIPPET_FORBIDDEN:
            if bad in line:
                problems.append(f"line {n}: `{bad}` is not allowed (it could read files or om's environment)")
        for bad in SNIPPET_CLIENT_ADDRESS:
            if bad in line:
                problems.append(f"line {n}: `{bad}`: the edge cannot see client addresses; "
                                f"restrict by address with {NET_ALLOW} / {NET_DENY} labels instead")
        tokens = line.split()
        if tokens == ["}"]:
            if len(stack) == 1:
                problems.append(f"line {n}: unbalanced }}")
            else:
                stack.pop()
            continue
        if "{" in tokens[:-1] or "}" in tokens:
            problems.append(f"line {n}: put each block's {{ at the end of a line and }} on its own line")
            continue
        opens = tokens[-1] == "{"
        head = tokens[0]
        ctx = stack[-1]
        if ctx == "directives":
            if head.startswith("@"):
                kind = tokens[1] if len(tokens) > 1 and tokens[1] != "{" else None
                if kind and kind not in SNIPPET_MATCHERS:
                    problems.append(f"line {n}: matcher type `{kind}` is not allowed (allowed: {', '.join(sorted(SNIPPET_MATCHERS))})")
                if opens:
                    stack.append("matcher")
                continue
            if head not in SNIPPET_DIRECTIVES:
                problems.append(f"line {n}: directive `{head}` is not allowed (allowed: {', '.join(sorted(SNIPPET_DIRECTIVES))})")
            if opens:
                stack.append("directives" if head in SNIPPET_CONTAINERS else "opaque")
        elif ctx == "matcher":
            if head not in SNIPPET_MATCHERS:
                problems.append(f"line {n}: matcher type `{head}` is not allowed")
            if opens:
                stack.append("opaque")
        elif opens:
            stack.append("opaque")
    if len(stack) != 1:
        problems.append("unbalanced { }")
    return problems

def _service_body(upstream: str, sname: str, opts: dict, dashboard: str = "to_dashboard") -> str:
    body = f"    import to_workspace {upstream}\n"
    if opts.get("dashboard_paths"):
        handles = "".join(f"    handle {p} {{\n        import {dashboard}\n    }}\n" for p in opts["dashboard_paths"])
        body = f"{handles}    handle {{\n        import to_workspace {upstream}\n    }}\n"
    if opts.get("keep_prefix"):
        body = f"    redir / /{sname}/\n" + body
    if opts.get("snippet"):  # the service's om.caddy runs first, in order, then om's own handling
        body = "    route {\n" + _indent(opts["snippet"]) + _indent(body) + "    }\n"
    return body

def _indent(text: str) -> str:
    return "".join(f"    {line}\n" if line else "\n" for line in text.rstrip("\n").split("\n"))

def render_vhost(ws_id: str, sname: str, port: int, opts: dict | None = None, slot: int | None = None,
                 is_public: bool = False) -> str:
    """The service's *.localhost vhost, plus — with a slot — its own ports: 20000+slot on loopback
    and the VPN, and if public 21000+slot on the LAN and the VPN. One origin per service, so one
    service's scripts can never read another's pages; a foreign Host is aborted (DNS rebinding)."""
    opts = opts or {}
    upstream = f"{ws_id}_{sname}:{port}"
    body = _service_body(upstream, sname, opts)
    if opts.get("log") == "off":  # om.log=off: the edge keeps no trace of this service's requests
        body = "    log_skip\n" + body
    custom = f"\n# custom: {SNIPPET_FILE} of this service is included below" if opts.get("snippet") else ""
    out = f"""# ==============================================================================
# Service: {sname} ({ws_id}){custom}
# ==============================================================================
http://{ws_id}.{sname}.localhost {{
    import security_headers
    import private_auth
{body}}}
"""
    if slot is None:
        return out
    out += f"""
http://:{omstate.PRIVATE_PORT_BASE + slot} {{
    import security_headers
    import private_auth
    @foreign not host {{$PRIVATE_NAMES}}
    handle @foreign {{
        abort
    }}
    handle {{
{_indent(body)}    }}
}}
"""
    if is_public:
        pbody = _service_body(upstream, sname, opts, "to_dashboard_public")
        if opts.get("log") == "off":
            pbody = "    log_skip\n" + pbody
        out += f"""
http://:{omstate.PUBLIC_PORT_BASE + slot} {{
    import security_headers
    @foreign not host {{$PUBLIC_NAMES}}
    handle @foreign {{
        abort
    }}
    handle {{
{_indent(pbody)}    }}
}}
"""
    return out

def render_alias(ws_id: str, sname: str, port_no: int, is_public: bool, opts: dict | None = None) -> str:
    """Redirects on the dashboard's address: /<svc> and each om.route.aliases path go to the
    service's own port, on the same host the visitor used."""
    opts = opts or {}
    title = f"# Public Alias: {sname} ({ws_id})" if is_public else f"# Private Alias: {sname} ({ws_id})"
    root = f"/{sname}/" if opts.get("keep_prefix") else "/"
    lines = [title, f"redir /{sname} http://{{host}}:{port_no}{root}", f"redir /{sname}/* http://{{host}}:{port_no}{root}"]
    for a in opts.get("aliases", []):
        lines += [f"redir {a} http://{{host}}:{port_no}{{uri}}", f"redir {a}/* http://{{host}}:{port_no}{{uri}}"]
    return "\n".join(lines) + "\n"
