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

# key -> (accepted values, what it does): the text of docs/SETTINGS.md. A test holds its keys to KEYS.
ABOUT = {
    "OM_LAN_IP": ("`auto`, `off`, or an IPv4 address",
                  "The address om treats as this machine's LAN address, where the public tier is served. `auto` detects it; `off` turns the LAN tier off."),
    "OM_VPN": ("`auto`, or interfaces / addresses such as `wg0,10.8.0.1`",
               "The VPNs trusted to reach the private tier: only VPNs whose members are all your own devices. None by default. Set it with `om vpn trust <interface>`."),
    "OM_VPN_ALLOW": ("empty, or addresses and ranges",
                     "Only these VPN devices reach the private tier; other devices on a trusted VPN get the public tier. Empty means every device on a trusted VPN. Set it with `om vpn allow <device>`; the host firewall enforces it (`om firewall apply`), and until it does the VPN's private tier stays closed."),
    "OM_NOTIFY": ("`auto`, `off`, or a comma list of `desktop`, `webhook`",
                  "Where om sends messages about updates and failures. `auto` is desktop toasts only, so nothing leaves the machine; `webhook` posts to `OM_NOTIFY_URL` and is never automatic. Every message is also written to `notify.log`."),
    "OM_NOTIFY_URL": ("an `https://` URL (`http://` only to this machine or a private address)",
                      "Where the webhook channel posts, for example an ntfy topic. It acts like a password: the file is kept 0600 and `om config` shows it as `***`."),
    "OM_TRUSTED_USERS": ("a comma list of account names",
                         "Other accounts on this machine that are yours. `om doctor` does not count them as people who could use the private tier without a login."),
    "OM_WALLPAPERS_DIR": ("`auto` or a folder",
                          "The folder the dashboard takes wallpapers from. `auto` uses `~/Pictures/Wallpapers` when it exists, else a folder in om's data."),
    "OM_HTTP_PORT": ("1-65535",
                     "The host port of the front door (HTTP). Change it to run a second om, for another OS user, on the same machine."),
    "OM_HTTPS_PORT": ("1-65535", "The host port of the front door (HTTPS)."),
    "OM_FIREWALL_EXTRA_TCP": ("a comma list of ports or ranges",
                              "Extra inbound TCP ports the host firewall lets through, for example `1714-1764`."),
    "OM_FIREWALL_EXTRA_UDP": ("a comma list of ports or ranges", "Extra inbound UDP ports the host firewall lets through."),
    "OM_POLICY": ("`enforce` or `warn`",
                  "The deploy policy gate: privileged containers, host namespaces, `ports:`, engine sockets and sensitive mounts. `enforce` refuses the compose file and names the fix; `warn` only reports. See `om policy check`."),
    "OM_SIGNED": ("`auto`, `warn` or `enforce`",
                  "Signed deploys: a clean commit must be signed by a key in the workspace's `.om/allowed_signers`. `auto` enforces as soon as git is set up to sign with an SSH key, and warns otherwise. A dirty tree always runs as an unsigned dev generation."),
}


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
