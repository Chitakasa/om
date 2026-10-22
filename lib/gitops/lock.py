#!/usr/bin/env python3
"""Image lock: `.om/lock.json` pins every pulled image to its registry digest.

A workspace commit plus its lock fully describes what runs (GOALS G1): a re-pushed tag changes
nothing until `om lock` / `om update` writes a new digest and you commit it. Digests are the
multi-arch *index* digest from the registry (OCI distribution API, anonymous token flow), so the
same lock works on amd64 and arm64. Services with `build:` are built locally and not locked.
"""

import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from gitops.core import STATE_DIR, run, write_atomic

LOCK_NAME = ".om/lock.json"
OVERRIDE_DIR = STATE_DIR / "lock" / "overrides"
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def parse_ref(ref: str) -> tuple[str, str, str, str]:
    """'nginx:1.31' → (registry, repository, tag, digest) with Docker Hub defaults."""
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", ref
    name, _, tag = path.rpartition(":") if ":" in path.rsplit("/", 1)[-1] else (path, "", "")
    tag = tag or "latest"
    if registry == "docker.io" and "/" not in name:
        name = f"library/{name}"
    return registry, name, tag, digest


def _bearer(challenge: str) -> str:
    """Anonymous token for a `WWW-Authenticate: Bearer realm=…,service=…,scope=…` challenge."""
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = params.pop("realm", "")
    if not realm.startswith("https://"):
        return ""
    url = realm + "?" + "&".join(f"{k}={urllib.request.quote(v)}" for k, v in params.items())
    with urllib.request.urlopen(url, timeout=15) as r:
        body = json.loads(r.read().decode("utf-8"))
    return body.get("token") or body.get("access_token") or ""


def _head(ref: str, reference: str) -> tuple[str, str]:
    """(digest, content type) of manifest `reference` (tag or digest) in ref's repository."""
    registry, name, _, _ = parse_ref(ref)
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    url = f"https://{host}/v2/{name}/manifests/{reference}"
    headers = {"Accept": ACCEPT}
    for _ in range(2):
        req = urllib.request.Request(url, method="HEAD", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                d = r.headers.get("Docker-Content-Digest", "")
                return (d if DIGEST_RE.match(d) else reference if DIGEST_RE.match(reference) else ""), r.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            challenge = e.headers.get("WWW-Authenticate", "")
            if e.code != 401 or "Authorization" in headers or not challenge.lower().startswith("bearer"):
                return "", ""
            try:
                token = _bearer(challenge)
            except (OSError, ValueError):
                return "", ""
            if not token:
                return "", ""
            headers["Authorization"] = f"Bearer {token}"
        except OSError:
            return "", ""
    return "", ""


def registry_digest(ref: str) -> str:
    """Current index digest of `ref`'s tag in its registry, or '' if it cannot be read anonymously."""
    _, _, tag, digest = parse_ref(ref)
    return digest or _head(ref, tag)[0]


def local_digest(runtime: str, ref: str) -> str:
    """Digest of the image the local tag points to (what runs now), preferring the multi-arch
    index digest; for a private registry, the first digest the engine recorded."""
    r = run([runtime, "image", "inspect", "--format", "{{json .RepoDigests}}", ref])
    try:
        candidates = [rd.rsplit("@", 1)[-1] for rd in json.loads(r.stdout or "[]")]
    except ValueError:
        return ""
    candidates = [d for d in candidates if DIGEST_RE.match(d)]
    for d in candidates:
        if any(k in _head(ref, d)[1] for k in ("index", "manifest.list")):
            return d
    return candidates[0] if candidates else ""


def images(cfg: dict | None) -> dict:
    """{service: image ref} for services that pull (not build) their image."""
    out = {}
    for name, svc in ((cfg or {}).get("services") or {}).items():
        if svc and svc.get("image") and not svc.get("build"):
            out[name] = svc["image"]
    return out


def read(root: Path) -> dict:
    try:
        data = json.loads((root / LOCK_NAME).read_text(encoding="utf-8"))
        return {k: v for k, v in (data.get("images") or {}).items() if DIGEST_RE.match(str(v))}
    except (OSError, ValueError, AttributeError):
        return {}


def write(root: Path, pinned: dict):
    body = {"version": 1, "images": dict(sorted(pinned.items()))}
    write_atomic(root / LOCK_NAME, json.dumps(body, indent=2) + "\n")


def resolve(runtime: str, refs, current: dict | None = None, refresh: bool = False) -> tuple[dict, list[str]]:
    """Digest for each ref. Without refresh: the existing pin, else what runs now (local image),
    else the registry's current one. With refresh (`om update`): the registry's current one.
    Returns (pinned, unresolved refs)."""
    current = current or {}
    pinned, missing = {}, []
    for ref in sorted(set(refs)):
        if refresh:
            d = registry_digest(ref) or current.get(ref, "")
        else:
            d = current.get(ref, "") or local_digest(runtime, ref) or registry_digest(ref)
        if d:
            pinned[ref] = d
        else:
            missing.append(ref)
    return pinned, missing


def pinned_ref(ref: str, digest: str) -> str:
    """`repo:tag@sha256:…` — the engine pulls by digest; the tag stays for humans."""
    return ref.split("@", 1)[0] + "@" + digest


def write_override(ws: str, project: str, cfg: dict | None, pinned: dict):
    """Compose override pinning this project's images to the lock, or None if nothing to pin."""
    mine = {s: pinned_ref(ref, pinned[ref]) for s, ref in images(cfg).items() if ref in pinned}
    path = OVERRIDE_DIR / f"{ws}-{hashlib.sha256(project.encode()).hexdigest()[:12]}.yml"
    if not mine:
        path.unlink(missing_ok=True)
        return None
    lines = ["# Generated by om from .om/lock.json — do not edit.", "services:"]
    for svc, ref in sorted(mine.items()):
        lines += [f"  {json.dumps(svc)}:", f"    image: {json.dumps(ref)}"]
    write_atomic(path, "\n".join(lines) + "\n")
    return path
