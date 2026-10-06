#!/usr/bin/env python3
"""The gate (om_gate, Authelia) — see docs/adr/0001-gate-and-door-build-vs-reuse.md.

Everything Authelia knows is rendered here from two sources, never edited by hand:
  * the verified access-file head: people, their devices and grants;
  * each workspace's service levels (`om.access` = shared | member | private), written by
    `om start` into $OM_STATE_DIR/gate/services/<ws>.json.

  shared   any enrolled device (door subnet)                         policy bypass
  member   any enrolled device + a person with a grant, by passkey     policy one_factor
  private  that person's own devices + grant, on the private domain    one_factor, 5-minute session

Passwords exist only during an invitation (one-time, shown once); `om approve` replaces them with
an unusable hash, so a passkey is the only way in. Registering a passkey needs Authelia's
elevation code, which its filesystem notifier writes to a file only om reads (`om pending`).
"""

import json
import os
import re
import secrets
import socket
import time

from gitops.core import STATE_DIR, load_settings, run

GATE = "om_gate"
GATE_DIR = STATE_DIR / "gate"
LEVELS = ("shared", "member", "private")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def domains(settings: dict | None = None) -> tuple[str, str]:
    """(OM_DOMAIN, private sibling). Default `<hostname>.internal` / `<hostname>-p.internal`."""
    s = settings if settings is not None else load_settings()
    d = (s.get("OM_DOMAIN", "auto") or "auto").strip().lower()
    if d == "auto":
        host = re.sub(r"[^a-z0-9-]", "-", socket.gethostname().split(".")[0].lower()).strip("-") or "om"
        d = f"{host}.internal"
    first, _, rest = d.partition(".")
    return d, f"{first}-p.{rest}"


def host_for(ws: str, svc: str, level: str, settings: dict | None = None) -> str:
    d, p = domains(settings)
    return f"{ws}-{svc}.{p if level == 'private' else d}"


def level_of(labels: dict) -> str | None:
    """om.access value, None if unreadable. A missing label means private (fail closed)."""
    v = str(labels.get("om.access", "private") or "private").strip().lower()
    return v if v in LEVELS else None


# ── State ───────────────────────────────────────────────────────────────────

def _write(path, text, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    if private:
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def ensure_base():
    for d in ("config", "data", "services"):
        (GATE_DIR / d).mkdir(parents=True, exist_ok=True)
    hc = GATE_DIR / "healthcheck.env"  # Authelia writes this at start; the root fs is read-only
    if not hc.exists():
        hc.write_text("", encoding="utf-8")
    sec = GATE_DIR / "secrets.json"
    if not sec.exists():
        _write(sec, json.dumps({k: secrets.token_hex(32) for k in ("jwt", "session", "storage")}) + "\n", private=True)


def save_services(ws: str, levels: dict):
    """{svc: level} for one workspace (called when its routes are generated)."""
    _write(GATE_DIR / "services" / f"{ws}.json", json.dumps(dict(sorted(levels.items()))) + "\n")


def all_services() -> dict:
    out = {}
    for f in sorted((GATE_DIR / "services").glob("*.json")):
        for svc, level in _json(f, {}).items():
            out[(f.stem, svc)] = level
    return out


# ── Rendering ───────────────────────────────────────────────────────────────

def _active_grants(person: dict, today: str) -> set:
    return {g["service"] for g in person.get("grants", []) if not g.get("until") or g["until"] >= today}


def rules(head: dict | None, services: dict, settings: dict | None = None) -> list[dict]:
    head = head or {}
    subnet = (head.get("door") or {}).get("subnet")
    if not subnet:
        return []
    today = time.strftime("%Y-%m-%d")
    people = {n: p for n, p in (head.get("people") or {}).items() if p.get("status") == "active"}
    devices_of = {}
    for d in (head.get("devices") or {}).values():
        if d.get("person"):
            devices_of.setdefault(d["person"], []).append(f"{d['address']}/32")
    out = []
    for (ws, svc), level in sorted(services.items()):
        host = host_for(ws, svc, level, settings)
        granted = sorted(n for n, p in people.items() if f"{ws}/{svc}" in _active_grants(p, today))
        if level == "shared":
            out.append({"domain": host, "networks": [subnet], "policy": "bypass"})
        elif level == "member" and granted:
            out.append({"domain": host, "networks": [subnet], "subject": [f"user:{n}" for n in granted], "policy": "one_factor"})
        elif level == "private":
            for n in granted:
                if devices_of.get(n):  # only the person's own devices
                    out.append({"domain": host, "networks": sorted(devices_of[n]), "subject": [f"user:{n}"], "policy": "one_factor"})
    return out


def _y(v) -> str:
    return json.dumps(v)  # JSON scalars and flow lists are valid YAML


def render_config(head: dict | None, settings: dict | None = None) -> str:
    sec = _json(GATE_DIR / "secrets.json", {})
    d, p = domains(settings)
    lines = [
        "# Generated by om from the signed access file and om.access labels — do not edit.",
        "server:", "  address: 'tcp://:9091/'",
        "log:", "  level: info",
        "theme: auto",
        "ntp:", "  disable_startup_check: true", "  disable_failure: true",
        "identity_validation:", "  reset_password:", f"    jwt_secret: {_y(sec.get('jwt', ''))}",
        "authentication_backend:", "  refresh_interval: always", "  password_reset:", "    disable: true",
        "  file:", "    path: /config/users.yml", "    watch: true",
        "webauthn:", "  enable_passkey_login: true", "  display_name: om",
        "session:", f"  secret: {_y(sec.get('session', ''))}", "  cookies:",
        f"    - domain: {_y(d)}", f"      authelia_url: {_y('https://auth.' + d)}", "      inactivity: '8h'", "      expiration: '7d'",
        f"    - domain: {_y(p)}", f"      authelia_url: {_y('https://auth.' + p)}", "      inactivity: '5m'", "      expiration: '12h'",
        "storage:", f"  encryption_key: {_y(sec.get('storage', ''))}", "  local:", "    path: /data/db.sqlite3",
        "notifier:", "  filesystem:", "    filename: /data/notification.txt",
        "access_control:", "  default_policy: deny",
    ]
    # Authelia rejects default_policy deny with an empty rule list; this rule matches nothing real.
    rs = rules(head, all_services(), settings) or [{"domain": "nothing.invalid", "networks": ["127.0.0.1/32"], "policy": "deny"}]
    if rs:
        lines.append("  rules:")
        for r in rs:
            lines.append(f"    - domain: {_y(r['domain'])}")
            lines.append(f"      networks: {_y(r['networks'])}")
            if r.get("subject"):
                lines.append(f"      subject: {_y(r['subject'])}")
            lines.append(f"      policy: {r['policy']}")
    return "\n".join(lines) + "\n"


def hash_password(runtime: str, password: str) -> str:
    """argon2id via Authelia's own CLI (om writes no cryptography)."""
    r = run([runtime, "run", "--rm", "--network", "none", "--entrypoint", "authelia", image(),
             "crypto", "hash", "generate", "argon2", "--password", password])
    m = re.search(r"Digest: (\S+)", r.stdout)
    if not m:
        raise RuntimeError(f"hashing failed: {(r.stderr or r.stdout).strip()[-200:]}")
    return m.group(1)


def image() -> str:
    from gitops.core import CORE_DIR
    for line in (CORE_DIR / "docker-compose.yml").read_text(encoding="utf-8").splitlines():
        if "image:" in line and "authelia/authelia" in line:
            return line.split("image:", 1)[1].strip()
    raise RuntimeError("authelia image not found in core/docker-compose.yml")


def render_users(head: dict | None) -> str:
    """users.yml from the people in the access file; hashes live in gate/passwords.json (0600)."""
    hashes = _json(GATE_DIR / "passwords.json", {})
    d, _ = domains()
    lines = ["# Generated by om — do not edit.", "users:"]
    people = (head or {}).get("people") or {}
    for name in sorted(people):
        if name in hashes:
            lines += [f"  {name}:", f"    displayname: {_y(people[name].get('display', name))}",
                      f"    password: {_y(hashes[name])}", f"    email: {_y(name + '@' + d)}"]
    if len(lines) == 2:  # Authelia refuses an empty user list: one disabled user, random unknown password
        lines += ["  om-nobody:", "    disabled: true", "    displayname: nobody",
                  "    password: '$argon2id$v=19$m=65536,t=3,p=4$7nAOHRVjKck2uZI6Dh9jQQ$B/7exdbW2910TX+HkjM7e3KhA1vugmn4egi+k07aobI'", f"    email: {_y('nobody@' + d)}"]
    return "\n".join(lines) + "\n"


def set_password_hash(name: str, hashed: str | None):
    pw = _json(GATE_DIR / "passwords.json", {})
    if hashed is None:
        pw.pop(name, None)
    else:
        pw[name] = hashed
    _write(GATE_DIR / "passwords.json", json.dumps(pw, indent=2, sort_keys=True) + "\n", private=True)


def render(head: dict | None) -> bool:
    """Write config + users; True if the access rules changed (Authelia then needs a restart)."""
    ensure_base()
    users = GATE_DIR / "config" / "users.yml"
    _write(users, render_users(head), private=True)
    cfg = GATE_DIR / "config" / "configuration.yml"
    new = render_config(head)
    old = cfg.read_text(encoding="utf-8") if cfg.exists() else ""
    if new != old:
        _write(cfg, new, private=True)
    return new != old


def apply(runtime: str, head: dict | None) -> bool:
    """Render and make it live: users reload on their own; rule changes restart the gate
    (sessions live in its memory, so people sign in again with their passkey)."""
    changed = render(head)
    if changed and run([runtime, "container", "inspect", GATE]).returncode == 0:
        return run([runtime, "restart", GATE]).returncode == 0
    return True


def credentials(runtime: str, name: str) -> int:
    """Number of passkeys (WebAuthn credentials) a person has registered."""
    r = run([runtime, "exec", GATE, "authelia", "storage", "user", "webauthn", "list", name,
             "--config", "/config/configuration.yml"])
    return sum(1 for line in r.stdout.splitlines() if re.search(r"\b(?:passkey|webauthn|[0-9a-f]{8}-)", line, re.I)) \
        if r.returncode == 0 else 0


def pending_codes() -> list[tuple[str, str, str]]:
    """(time, recipient, code) of Authelia's one-time codes, newest last (from its notifier file)."""
    try:
        text = (GATE_DIR / "data" / "notification.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out = []
    for block in re.split(r"(?m)^Date: ", text)[1:]:
        when = block.splitlines()[0][:19]
        who = re.search(r"Recipient: \{(\S+)", block)
        code = re.search(r"(?m)^\s*([A-Z0-9]{8})\s*$", block)
        if who and code:
            out.append((when, who.group(1), code.group(1)))
    return out
