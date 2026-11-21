#!/usr/bin/env python3
"""`om config show|get|set|unset`: om.env without a text editor, with every value checked and the file kept 0600."""

from __future__ import annotations

import difflib
import ipaddress
import re

from gitops import notify, omsettings
from gitops.cli import die, emit_json

SECRET = {"OM_NOTIFY_URL"}  # shown as *** unless --reveal: an ntfy topic URL is a bearer-like secret
OWN_COMMAND = {"OM_VPN": "om vpn trust|untrust <interface>", "OM_VPN_ALLOW": "om vpn allow|disallow <device>"}
_PORT_RE = re.compile(r"\d{1,5}(?:-\d{1,5})?")
_USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}\$?")


def _port(v: str) -> int:
    if not v.isdigit() or not 1 <= int(v) <= 65535:
        raise ValueError(f"`{v}` is not a port (1-65535)")
    return int(v)


def _one_of(*words):
    def check(v: str):
        if v.lower() not in words:
            raise ValueError(f"must be one of: {', '.join(words)}")
    return check


def _port_list(v: str):
    for item in (i.strip() for i in v.split(",") if i.strip()):
        if not _PORT_RE.fullmatch(item):
            raise ValueError(f"`{item}` is not a port or a range like 1714-1764")
        lo, _, hi = item.partition("-")
        if _port(lo) > (_port(hi) if hi else int(lo)):
            raise ValueError(f"`{item}`: the range runs backwards")


def _lan_ip(v: str):
    if v.lower() in ("auto", "off"):
        return
    try:
        ipaddress.IPv4Address(v)
    except ValueError:
        raise ValueError("must be auto, off or an IPv4 address") from None


def _notify(v: str):
    words = [w for w in v.lower().replace(" ", "").split(",") if w]
    if v.lower() in ("auto", "off"):
        return
    if not words or any(w not in ("desktop", "webhook") for w in words):
        raise ValueError("must be auto, off or a comma list of: desktop, webhook")


def _notify_url(v: str):
    if v and not notify.webhook_url_ok(v):
        raise ValueError("must be https:// (or http:// to this machine or a private address)")


def _users(v: str):
    for u in (i.strip() for i in v.split(",") if i.strip()):
        if not _USER_RE.fullmatch(u):
            raise ValueError(f"`{u}` is not an account name")


def _wallpapers(v: str):
    if not v.strip():
        raise ValueError("must be auto or a folder path")


# key -> (check, what to do after changing it). The keys are exactly those of omsettings.USER_ENV_TEMPLATE
# (a test holds the two together), so a new setting cannot be added to one without the other.
SCHEMA = {
    "OM_LAN_IP": (_lan_ip, "om core restart"),
    "OM_NOTIFY": (_notify, ""),
    "OM_NOTIFY_URL": (_notify_url, ""),
    "OM_TRUSTED_USERS": (_users, ""),
    "OM_WALLPAPERS_DIR": (_wallpapers, "om core restart"),
    "OM_HTTP_PORT": (_port, "om core restart, then om firewall apply"),
    "OM_HTTPS_PORT": (_port, "om core restart, then om firewall apply"),
    "OM_FIREWALL_EXTRA_TCP": (_port_list, "om firewall apply"),
    "OM_FIREWALL_EXTRA_UDP": (_port_list, "om firewall apply"),
    "OM_POLICY": (_one_of("enforce", "warn"), ""),
    "OM_SIGNED": (_one_of("auto", "warn", "enforce"), ""),
}
KEYS = set(SCHEMA) | set(OWN_COMMAND)


def _key(name: str) -> str:
    key = name.strip().upper()
    if key in OWN_COMMAND:
        die(f"{key} has its own command, which also updates the firewall: {OWN_COMMAND[key]}")
    if key not in SCHEMA:
        near = difflib.get_close_matches(key, sorted(SCHEMA), n=1)
        die(f"Unknown setting {name!r}." + (f" Did you mean {near[0]}?" if near else " `om config show` lists them."))
    return key


def check_value(key: str, value: str) -> str | None:
    """None when `value` is fine for `key`, else why not."""
    try:
        SCHEMA[key][0](value.strip())
    except ValueError as e:
        return str(e)
    return None


def current(reveal: bool = False) -> dict:
    """{key: value as om reads it}; secrets masked unless `reveal`."""
    settings = omsettings.load_settings()
    return {k: ("***" if k in SECRET and v and not reveal else v) for k, v in sorted(settings.items()) if k in KEYS}


def cmd_config(args):
    action = args.action
    if action == "show":
        values = current(args.reveal)
        if args.json:
            emit_json(values)
            return
        print(f"\n\033[1mSETTINGS\033[0m  ({omsettings.USER_ENV})\n")
        for k, v in values.items():
            print(f"  {k:<24} {v if v != '' else '(empty)'}")
        print("\n  Change one: om config set KEY=value   (OM_VPN / OM_VPN_ALLOW: om vpn …)\n")
        return
    if action == "get":
        if not args.arg:
            die("Usage: om config get <KEY>")
        key = args.arg.strip().upper()
        if key not in KEYS:
            _key(args.arg)
        print(current(args.reveal)[key])
        return
    if action == "set":
        key, sep, value = (args.arg or "").partition("=")
        if not sep:
            die("Usage: om config set KEY=value")
        key, value = _key(key), value.strip()
        why = check_value(key, value)
        if why:
            die(f"{key}={value}: {why}")
        omsettings.set_setting(key, value)
        print(f"\033[32m✓ {key}={'***' if key in SECRET and value else value}\033[0m")
        if SCHEMA[key][1]:
            print(f"  Then run: {SCHEMA[key][1]}")
        return
    if action == "unset":
        if not args.arg:
            die("Usage: om config unset <KEY>")
        key = _key(args.arg)
        omsettings.set_setting(key, "")
        print(f"\033[32m✓ {key} back to its default\033[0m")
        if SCHEMA[key][1]:
            print(f"  Then run: {SCHEMA[key][1]}")
        return
    die(f"Unknown action {action!r}.")
