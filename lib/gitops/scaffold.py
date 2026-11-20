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
      # Opt in when needed (om docs guide):
      # - "om.egress=audit"     # permanent: all public egress allowed & logged, no expiry
      # - "om.egress=learn"     # discovery: record what it uses, then apply with om egress log --apply
      # - "om.net.allow=vpn"    # only the devices on your VPN allow-list
      # - "om.log=off"          # leave no trace: no access or connection log, no output kept
    expose:
      - "{port}"
    networks:
      - default

networks:
  default:
    name: ${{WORKSPACE_NET:-{ws_id}_net}}
    external: true
"""
