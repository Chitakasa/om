#!/usr/bin/env python3
"""Scaffolding for `om add`: validate the request, then render the compose file and project files. Pure functions
(no engine, no registry), so they are tested directly; bin/om's cmd_add applies them and starts the routes."""

from __future__ import annotations

import json
from pathlib import Path

from gitops.workspace import SAFE_DOMAIN_RE, is_safe_name

PROJECT_SERVER_JS = """// Minimal dev server scaffolded by `om add --project`. Edit freely: `node --watch` restarts on save.
const http = require("http");
const port = Number(process.env.PORT || 3000);
http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<h1>${process.env.PROJECT_NAME} is running</h1><p>Edit server.js — it reloads automatically.</p>`);
}).listen(port, () => console.log(`listening on :${port}`));
"""

# Non-root images that run with no capabilities and a read-only filesystem
DEFAULT_SERVICE_IMAGE = "docker.io/nginxinc/nginx-unprivileged:1.31-alpine"   # listens on 8080
DEFAULT_PROJECT_IMAGE = "docker.io/library/node:24-alpine"

# The labels every scaffold sets (label, example, what it does); docs/LABELS.md lists them with LABEL_MENU.
ACTIVE_LABELS = (
    ("workspace.id", "my-workspace", "the workspace the service belongs to; keeps names unique across workspaces"),
    ("dashboard.name", "Web", "the card's title on the dashboard"),
    ("dashboard.icon", "🌐", "the card's icon"),
    ("dashboard.description", "A small web server", "the card's description"),
    ("dashboard.port", "8080", "the container port om routes to"),
    ("dashboard.domain", "web.my-workspace.localhost", "the address shown for the service (informational)"),
    ("dashboard.scope", "private", "`private` (this machine and your VPN) or `public` (the LAN too)"),
    ("dashboard.web", "true", "`false` for a background service with no web address"),
)

# The labels a user can add to a service beyond the ones every scaffold sets: (group, ((label, example, what it
# does), …)). `render_compose` writes them as a commented menu; a test holds this table to the labels om documents,
# so a label cannot be added to om without appearing here.
LABEL_MENU = (
    ("Routing", (
        ("om.route.aliases", "/a,/b", "redirect these top-level paths on the dashboard's address to this service"),
        ("om.route.keep_prefix", "true", "the app serves itself under /<service>/"),
        ("om.route.dashboard_paths", "/api/x*", "paths on this service's address answered by the dashboard"),
        ("om.tcp", "5432", "publish this container port as a raw TCP route"),
        ("om.tcp.port", "15432", "the host port for om.tcp (default: a free slot)"),
    )),
    ("Who can reach it", (
        ("om.net.allow", "vpn", "only these addresses reach its own ports (vpn = your VPN allow-list)"),
        ("om.net.deny", "203.0.113.0/24", "never these addresses"),
        ("om.link", "<ws>/<svc>", "a private network with exactly one other service"),
        ("om.link.allow", "<ws>/<svc>", "who may link to this service (both sides must agree)"),
        ("om.network", "shared", "join the workspace-wide network instead of this folder's own"),
    )),
    ("Outbound traffic", (
        ("om.egress", "audit", "audit | learn | internet | host,*.host: where it may connect out (default: nowhere)"),
        ("om.egress.learn_ttl", "24h", "how long learn mode records"),
        ("om.egress.jvm", "true", "hand the proxy settings to a JVM service"),
    )),
    ("Resources and updates", (
        ("om.mem", "256m", "memory limit"),
        ("om.pids", "200", "process limit"),
        ("om.cpus", "0.5", "CPU limit"),
        ("om.update", "hold", "hold: keep the image's pin; auto: the scheduled sync updates it"),
    )),
    ("Logging and policy", (
        ("om.log", "off", "leave no trace: no access or connection log, no output kept"),
        ("om.policy.allow", "mounts", "waive these deploy-gate rules for this service (om policy check)"),
    )),
    ("Dashboard", (
        ("dashboard.hide", "true", "keep it off the dashboard"),
        ("dashboard.path", "/x/", "where the dashboard link opens on the service's address"),
        ("dashboard.url", "https://example.org/", "open this address instead of the service's own port"),
        ("dashboard.search", "true", "the service is the browser's search engine"),
        ("dashboard.search_url", "/search?q={searchTerms}", "its search address"),
        ("workspace.category", "tools", "reported by /api/services"),
    )),
)


def label_menu(indent: str = "      ") -> str:
    """LABEL_MENU as commented compose list entries, one line each, grouped under a heading."""
    entries = [(f'- "{label}={example}"', note, group) for group, items in LABEL_MENU for label, example, note in items]
    width = max(len(e[0]) for e in entries)
    out, last = [f"{indent}# More om labels, uncomment what you need (om docs guide):"], None
    for text, note, group in entries:
        if group != last:
            out.append(f"{indent}# {group}")
            last = group
        out.append(f"{indent}# {text.ljust(width)}  # {note}")
    return "\n".join(out) + "\n"


def yaml_label_safe(value: str) -> bool:
    return not any(c in value for c in '"\\\n\r')


def plan(args, ws_id: str, root: Path) -> dict:
    """The validated request as a dict (name, dest, image, port, domain, icon, desc, ...).
    Raises ValueError with the message to show when something is wrong."""
    name = args.name.lower().replace(" ", "-")
    if not is_safe_name(name):
        raise ValueError(f"Error: invalid name '{name}' (allowed: lowercase letters, digits, '-')")
    is_project = args.project
    dest = root / ("projects" if is_project else "services") / name
    if dest.exists():
        raise ValueError(f"Error: '{name}' already exists at {dest}")
    if args.image and not args.port and not args.no_web:
        raise ValueError("Error: with --image, also pass --port (the port that image listens on inside the container).")
    if is_project:
        image, port = args.image or DEFAULT_PROJECT_IMAGE, args.port or 3000
    else:
        image, port = args.image or DEFAULT_SERVICE_IMAGE, args.port or 8080
    domain = (args.domain or f"{ws_id}.{name}.localhost").lower()
    icon = args.icon or ("⚡" if is_project else "📦")
    desc = args.desc or (f"Developer project: {name}" if is_project else f"Self-hosted service: {name}")
    if not SAFE_DOMAIN_RE.match(domain):
        raise ValueError(f"Error: invalid domain '{domain}'")
    if any(c.isspace() for c in image) or not yaml_label_safe(image):
        raise ValueError(f"Error: invalid image '{image}'")
    if not (yaml_label_safe(icon) and yaml_label_safe(desc)):
        raise ValueError("Error: --icon/--desc must not contain quotes, backslashes or newlines")
    return {"ws_id": ws_id, "name": name, "dest": dest, "is_project": is_project, "image": image, "port": port,
            "domain": domain, "icon": icon, "desc": desc, "custom_image": bool(args.image),
            "public": bool(args.public), "no_web": bool(args.no_web)}


def project_files(p: dict) -> dict[str, str]:
    """{file name: content} written next to the compose file of a project that uses the default Node image."""
    if not (p["is_project"] and not p["custom_image"]):
        return {}
    package = {"name": p["name"], "private": True, "scripts": {"dev": "node --watch server.js"}}
    return {"server.js": PROJECT_SERVER_JS, "package.json": json.dumps(package, indent=2) + "\n"}


def hardening(custom_image: bool) -> str:
    """Least privilege. om's own images are known to run with no capabilities and a read-only filesystem;
    an image of your choice usually starts as root and switches user, so it keeps only the five capabilities
    that needs."""
    if custom_image:
        return """    # Most images start as root and switch to their own user, which needs these five;
    # remove them if your image runs as non-root from the start.
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - FOWNER
      - SETGID
      - SETUID
"""
    return """    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
"""


def render_compose(p: dict) -> str:
    """The service's compose.yml: 'expose' (never 'ports') keeps it off host interfaces; the edge is the only ingress."""
    ws_id, name, port = p["ws_id"], p["name"], p["port"]
    project_bits = ""
    if p["is_project"] and not p["custom_image"]:
        project_bits = f"""    working_dir: /app
    command: ["node", "--watch", "server.js"]
    environment:
      - PORT={port}
      - PROJECT_NAME={name}
    volumes:
      - ./:/app:Z
"""
    image, icon, desc, domain = p["image"], p["icon"], p["desc"], p["domain"]
    args_public, args_no_web = p["public"], p["no_web"]
    hardening_text = hardening(p["custom_image"])
    label_menu_text = label_menu()
    return f"""# priority: 50
services:
  {name}:
    image: {image}
    container_name: ${{WORKSPACE_ID:-{ws_id}}}_{name}
    restart: unless-stopped
{project_bits}    security_opt:
      - no-new-privileges:true
{hardening_text}    labels:
      - "workspace.id=${{WORKSPACE_ID:-{ws_id}}}"
      - "dashboard.name={name.title()}"
      - "dashboard.icon={icon}"
      - "dashboard.description={desc}"
      - "dashboard.port={port}"
      - "dashboard.domain={domain}"
      - "dashboard.scope={'public' if args_public else 'private'}"
      - "dashboard.web={'false' if args_no_web else 'true'}"
{label_menu_text}    expose:
      - "{port}"
    networks:
      - default

networks:
  default:
    name: ${{WORKSPACE_NET:-{ws_id}_net}}
    external: true
"""


def label_updates(args) -> dict[str, str]:
    """The dashboard labels `om edit` was asked to set. Raises ValueError with the message to show."""
    wanted = {"dashboard.scope": args.scope and args.scope.lower(), "dashboard.port": args.port and str(args.port),
              "dashboard.icon": args.icon, "dashboard.description": args.desc, "dashboard.name": args.name}
    updates = {k: v for k, v in wanted.items() if v}
    if not updates:
        raise ValueError("No edits specified. Use --scope, --port, --icon, --desc, or --name.")
    if not all(yaml_label_safe(v) for v in updates.values()):
        raise ValueError("Error: values must not contain quotes, backslashes or newlines")
    return updates


def _edit_existing_labels(lines: list[str], updates: dict) -> tuple[list[str], bool]:
    """Set each label in the service's `labels:` list (replacing the line that has it, adding the others after the
    last list entry); (new lines, whether a labels list was found)."""
    new_lines, in_labels, found_labels, handled = [], False, False, set()
    labels_indent = "      "
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("labels:"):
            in_labels = found_labels = True
            labels_indent = line[:len(line) - len(line.lstrip())] + "  "
            new_lines.append(line)
            continue
        if in_labels:
            if stripped.startswith("-") and any(f"{k}=" in stripped for k in updates):
                for k, v in updates.items():
                    if f"{k}=" in stripped:
                        new_lines.append(f'{labels_indent}- "{k}={v}"')
                        handled.add(k)
                        break
                continue
            if not stripped.startswith("-") and stripped and not stripped.startswith("#"):
                for k, v in updates.items():
                    if k not in handled:
                        new_lines.append(f'{labels_indent}- "{k}={v}"')
                        handled.add(k)
                in_labels = False
        new_lines.append(line)
    if found_labels:
        new_lines += [f'{labels_indent}- "{k}={v}"' for k, v in updates.items() if k not in handled]
    return new_lines, found_labels


def _insert_labels_block(lines: list[str], updates: dict) -> list[str]:
    """A new `labels:` block after the first `image:` or `container_name:` line."""
    final, inserted = [], False
    for line in lines:
        final.append(line)
        if not inserted and line.strip().startswith(("image:", "container_name:")):
            indent = line[:len(line) - len(line.lstrip())]
            final.append(f"{indent}labels:")
            final.extend(f'{indent}  - "{k}={v}"' for k, v in updates.items())
            inserted = True
    return final


def edit_labels(text: str, updates: dict) -> str:
    """The compose file with these labels set, everything else untouched."""
    lines, found = _edit_existing_labels(text.splitlines(), updates)
    return "\n".join(lines if found else _insert_labels_block(lines, updates)) + "\n"
