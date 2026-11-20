#!/usr/bin/env python3
"""Cross-workspace links: one service may reach one service of another workspace, any protocol.

    consumer labels:  om.link=perso/db            (comma list of <workspace>/<service>)
    provider labels:  om.link.allow=containers/app (comma list; <ws>/* allows a whole workspace)

A link exists only when both sides declare it. om then puts exactly those two containers on a
private internal network of their own (`omlink-<hash>`, nothing else attached, no route out) and
gives the provider the alias `<ws>-<svc>` there, so the consumer reaches it as `perso-db:5432`.
Neither workspace becomes reachable otherwise. Containers are read from the engine (their labels),
so a link works whichever workspace starts first; `om start` and the heal timer keep it attached
after a container is recreated, and remove links nobody declares any more.
"""

import hashlib
import json

from gitops.core import run

LINK_LABEL = "om.link"
ALLOW_LABEL = "om.link.allow"
NET_PREFIX = "omlink-"


def _split(value: str) -> list[str]:
    return [x.strip().lower() for x in (value or "").split(",") if x.strip()]


def containers(runtime: str) -> list[dict]:
    """[{name, ws, svc, labels, networks}] of om workspace containers (running or not)."""
    ids = run([runtime, "ps", "-aq", "--filter", "label=workspace.id"]).stdout.split()
    if not ids:
        return []
    r = run([runtime, "inspect", *ids])
    try:
        data = json.loads(r.stdout or "[]")
    except ValueError:
        return []
    out = []
    for c in data:
        name = c.get("Name", "").lstrip("/")
        labels = (c.get("Config") or {}).get("Labels") or {}
        ws = labels.get("workspace.id", "")
        if not ws or not name.startswith(ws + "_"):
            continue
        out.append({"name": name, "ws": ws, "svc": name[len(ws) + 1:], "labels": labels,
                    "running": bool((c.get("State") or {}).get("Running")),
                    "networks": sorted(((c.get("NetworkSettings") or {}).get("Networks") or {}).keys())})
    return out


def allowed(allow: list[str], consumer: str) -> bool:
    ws = consumer.split("/")[0]
    return consumer in allow or f"{ws}/*" in allow


def desired(conts: list[dict]) -> tuple[dict, list[str]]:
    """({network: (consumer, provider)}, problems) from the containers' labels."""
    by_id = {f"{c['ws']}/{c['svc']}": c for c in conts}
    links, problems = {}, []
    for c in conts:
        me = f"{c['ws']}/{c['svc']}"
        for target in _split(c["labels"].get(LINK_LABEL, "")):
            p = by_id.get(target)
            if "/" not in target:
                problems.append(f"{me}: om.link={target} — use <workspace>/<service>")
            elif not p:
                problems.append(f"{me}: om.link={target} — no such service (not created yet?)")
            elif not allowed(_split(p["labels"].get(ALLOW_LABEL, "")), me):
                problems.append(f"{me}: om.link={target} — {target} does not allow it; add to its labels: om.link.allow={me}")
            else:
                links[network_name(me, target)] = (me, target)
    return links, problems


def network_name(consumer: str, provider: str) -> str:
    return NET_PREFIX + hashlib.sha256(f"{consumer}>{provider}".encode()).hexdigest()[:12]


def alias(provider: str) -> str:
    return provider.replace("/", "-")


def _connect(runtime: str, net: str, container: str, extra: list[str]) -> bool:
    r = run([runtime, "network", "connect", *extra, net, container])
    out = (r.stdout + r.stderr).lower()
    return r.returncode == 0 or "already" in out or "exists" in out


def sync(runtime: str) -> list[str]:
    """Make the link networks match the declarations. Returns problems (one-sided or broken links)."""
    conts = containers(runtime)
    want, problems = desired(conts)
    by_id = {f"{c['ws']}/{c['svc']}": c for c in conts}
    have = set(run([runtime, "network", "ls", "--filter", "label=om.link=true", "--format", "{{.Name}}"]).stdout.split())
    for net, (consumer, provider) in want.items():
        if net not in have:
            run([runtime, "network", "create", "--internal", "--label", "om.link=true",
                 "--label", f"om.link.pair={consumer}>{provider}", net])
        if not _connect(runtime, net, by_id[provider]["name"], ["--alias", alias(provider)]):
            problems.append(f"{consumer} → {provider}: could not attach {provider}")
        if not _connect(runtime, net, by_id[consumer]["name"], []):
            problems.append(f"{consumer} → {provider}: could not attach {consumer}")
        # Anything else on a link network does not belong there.
        for c in conts:
            if net in c["networks"] and f"{c['ws']}/{c['svc']}" not in (consumer, provider):
                run([runtime, "network", "disconnect", net, c["name"]])
    if not conts:  # nothing listed (engine hiccup?): never mistake that for "nobody declares a link any more"
        return problems
    for net in have - set(want):
        for c in conts:
            if net in c["networks"]:
                run([runtime, "network", "disconnect", net, c["name"]])
        run([runtime, "network", "rm", net])
    return problems


def describe(runtime: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """([(consumer, provider, reach-as)], problems) without changing anything."""
    want, problems = desired(containers(runtime))
    return [(c, p, alias(p)) for c, p in sorted(want.values())], problems
