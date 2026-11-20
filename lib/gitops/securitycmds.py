#!/usr/bin/env python3
"""Private-tier logins, cross-workspace links and secrets commands (moved out of bin/om; bin/om re-exports them)."""

from __future__ import annotations

import getpass
import os
import re
import sys
from pathlib import Path

from gitops import agesecrets, enginectl, links, omstate
from gitops.cli import die, emit_json
from gitops.enginectl import detect_runtime
from gitops.network import reload_caddy
from gitops.omstate import run
from gitops.secrets import decrypt_file
from gitops.workspace import discover_compose_dirs, find_compose_file, resolve_target

AUTH_D = omstate.AUTH_DIR            # private-tier login (state)


def read_auth_users(conf: Path) -> dict:
    """{user: bcrypt hash} from the private-tier basic_auth block."""
    if not conf.exists():
        return {}
    return dict(re.findall(r"^\s+([A-Za-z0-9._-]{1,64})\s+(\$2\S+)\s*$", conf.read_text(encoding="utf-8"), re.M))


def write_auth_users(conf: Path, users: dict):
    if not users:
        conf.unlink(missing_ok=True)
        return
    AUTH_D.mkdir(parents=True, exist_ok=True)
    body = "".join(f"    {u} {h}\n" for u, h in sorted(users.items()))
    conf.write_text(f"basic_auth {{\n{body}}}\n", encoding="utf-8", newline="\n")


def cmd_auth(root, args):
    """Private-tier logins. Several people can each have their own: add/remove one, or set (replace all)."""
    runtime = detect_runtime()
    conf = AUTH_D / "private.conf"
    users = read_auth_users(conf)
    if args.action in ("status", "list"):
        print("  Private-tier login: " + (f"\033[32mon\033[0m ({', '.join(sorted(users))})" if users else "\033[33moff\033[0m"))
        return
    if args.action == "off":
        conf.unlink(missing_ok=True)
        reload_caddy(runtime)
        print("\033[32m✓ Private-tier login disabled.\033[0m")
        return
    user = args.user
    if not user or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user):
        die(f"Usage: om auth {args.action} <user>   (letters, digits, . _ -)")
    if args.action == "remove":
        if user not in users:
            die(f"No login named '{user}'.")
        del users[user]
        write_auth_users(conf, users)
        reload_caddy(runtime)
        print(f"\033[32m✓ Removed login '{user}'.\033[0m" + ("" if users else " Private-tier login is now off."))
        return
    pw = getpass.getpass(f"New password for {user}: ")
    if len(pw) < 4:
        die("Use at least 4 characters.")
    if pw != getpass.getpass("Repeat password: "):
        die("Passwords do not match.")
    if not enginectl.container_running(runtime, "om_caddy"):
        die("The edge proxy must be running (om core start).")
    r = run([runtime, "exec", "-i", "om_caddy", "caddy", "hash-password"], input=pw + "\n")
    hashed = r.stdout.strip().splitlines()[-1] if r.returncode == 0 and r.stdout.strip() else ""
    if not hashed.startswith("$2"):
        die(f"Could not hash the password: {(r.stderr or r.stdout).strip()[-300:]}")
    users = {user: hashed} if args.action == "set" else {**users, user: hashed}
    write_auth_users(conf, users)
    if reload_caddy(runtime):
        print(f"\033[32m✓ Private tier now requires a login ({', '.join(sorted(users))}).\033[0m (LAN public tier unaffected)")


def cmd_links(root, args):
    """Cross-workspace links (om.link / om.link.allow) and what blocks the one-sided ones."""
    runtime = detect_runtime()
    found, problems = links.describe(runtime)
    if getattr(args, "json", False):
        emit_json({"links": [{"consumer": c, "provider": p, "reach_as": r} for c, p, r in found], "problems": problems})
        return
    print("\n\033[1mLINKS\033[0m")
    if not found and not problems:
        print("  None. A service reaches another workspace's service when it declares om.link=<ws>/<svc>"
              " and that service declares om.link.allow=<its ws>/<its svc>.\n")
        return
    for consumer, provider, reach in found:
        print(f"  {consumer:<28} → {provider:<28} reach it as \033[36m{reach}\033[0m")
    for p in problems:
        print(f"  \033[33m⚠ {p}\033[0m")
    print()


def cmd_secrets(root, args):
    if args.action in ("init", "set", "list", "rekey"):
        return cmd_age_secrets(root, args)
    if not args.file:
        die("usage: om secrets decrypt <file> [-o out]")
    src = Path(args.file)
    if not src.is_file():
        die(f"No such file: {src}")
    pw = os.environ.get("OM_SECRET_KEY") or getpass.getpass("Passphrase: ")
    try:
        data = decrypt_file(src, pw)
    except ValueError as e:
        die(str(e))
    if args.output:
        out = Path(args.output)
        omstate.write_private_bytes(out, data)
        print(f"\033[32m✓ Decrypted to {out}\033[0m")
    else:
        sys.stdout.flush()
        sys.stdout.buffer.write(data) if hasattr(sys.stdout, "buffer") else print(data.decode(errors="replace"))


def cmd_age_secrets(root, args):
    if not root:
        die("Run this inside a workspace.")
    runtime = detect_runtime()
    if args.action == "init":
        host = agesecrets.host_recipient(runtime)
        signer = my_signer_line()  # your git SSH signing key: you can decrypt too
        owner = " ".join(signer.split()[2:4]) if signer else ""
        added = agesecrets.write_recipients(root, host, owner)
        print(f"\033[32m✓ {agesecrets.RECIPIENTS_NAME}\033[0m: this host ({host[:16]}…)" + (" and your SSH key" if owner else "") + " can decrypt.")
        print(f"  Commit it. Back up {agesecrets.KEY_FILE} off-host: without it (or your SSH key) secrets cannot be read.")
        if added:
            print("  This machine was added to an existing list: on a machine that can already decrypt (or here, if your")
            print("  SSH key has no passphrase), run `om secrets rekey` and commit, so the existing secrets open here too.")
        return
    if args.action == "rekey":
        key = Path(os.path.expanduser(run(["git", "config", "--get", "user.signingkey"]).stdout.strip() or "~/.ssh/id_ed25519.pub"))
        ssh_key = key.with_suffix("") if key.suffix == ".pub" else key
        try:
            files = agesecrets.rekey(runtime, root, ssh_key)
        except RuntimeError as e:
            die(str(e))
        print(f"\033[32m✓ {len(files)} secret(s) re-encrypted for {len(agesecrets.recipients(root))} recipient(s)\033[0m — commit them.")
        return
    if args.action == "list":
        for _, d in discover_compose_dirs(root):
            for f in sorted((d / "secrets").glob("*.age")) if (d / "secrets").is_dir() else []:
                print(f"  {d.name}/{f.name[:-4]}")
        return
    target = args.file or ""
    project, _, name = target.partition("/")
    if not agesecrets.NAME_RE.match(name or ""):
        die("usage: om secrets set <project>/<name>   (value read from stdin, or asked for)")
    d = resolve_target(root, project)
    value = sys.stdin.buffer.read() if not sys.stdin.isatty() else getpass.getpass(f"Value for {target}: ").encode()
    if not value:
        die("Empty value.")
    agesecrets.host_recipient(runtime)
    (d / "secrets").mkdir(exist_ok=True)
    out = d / "secrets" / f"{name}.age"
    out.write_bytes(agesecrets.encrypt(runtime, root, value))
    print(f"\033[32m✓ {out.relative_to(root)}\033[0m (encrypted; commit it). In {find_compose_file(d).name}:")
    print(f"    services:\n      <svc>:\n        secrets: [{name}]        # read it from /run/secrets/{name}\n"
          f"    secrets:\n      {name}:\n        file: ./secrets/{name}")


def my_signer_line() -> str:
    """`<email> namespaces="git" <key>` for the user's git SSH signing key, or ''."""
    def cfg(key):
        r = run(["git", "config", "--get", key])
        return r.stdout.strip() if r.returncode == 0 else ""
    email, key = cfg("user.email"), cfg("user.signingkey")
    if cfg("gpg.format") != "ssh" or not email or not key:
        return ""
    if not key.startswith(("ssh-", "sk-", "ecdsa-")):
        try:
            key = Path(os.path.expanduser(key)).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return f'{email} namespaces="git" {" ".join(key.split()[:2])}'
