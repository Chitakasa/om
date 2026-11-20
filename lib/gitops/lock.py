#!/usr/bin/env python3
"""Image lock: `.om/lock.json` pins every pulled image to its registry digest.

A workspace commit plus its lock fully describes what runs (GOALS G1): a re-pushed tag changes
nothing until `om lock` / `om update` writes a new digest and you commit it. Digests are the
multi-arch *index* digest from the registry (OCI distribution API, anonymous token flow), so the
same lock works on amd64 and arm64. Services with `build:` are built locally and not locked.
"""

import hashlib
import json
import platform
import re
import urllib.error
import urllib.request
from pathlib import Path

from gitops.omstate import STATE_DIR, run, write_atomic

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


class _NoAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Blobs redirect to a CDN with its own signed URL; a forwarded registry token makes it refuse."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.headers.pop("Authorization", None)
        return new


def _open(ref: str, path: str, method: str = "GET") -> tuple:
    """(response headers, body) of /v2/<repository>/<path>, following one anonymous Bearer
    challenge; (None, b"") if the registry cannot be read anonymously."""
    registry, name, _, _ = parse_ref(ref)
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    url = f"https://{host}/v2/{name}/{path}"
    headers = {"Accept": ACCEPT}
    opener = urllib.request.build_opener(_NoAuthOnRedirect)
    for _ in range(2):
        req = urllib.request.Request(url, method=method, headers=headers)
        try:
            with opener.open(req, timeout=15) as r:
                return r.headers, (r.read() if method == "GET" else b"")
        except urllib.error.HTTPError as e:
            challenge = e.headers.get("WWW-Authenticate", "")
            if e.code != 401 or "Authorization" in headers or not challenge.lower().startswith("bearer"):
                return None, b""
            try:
                token = _bearer(challenge)
            except (OSError, ValueError):
                return None, b""
            if not token:
                return None, b""
            headers["Authorization"] = f"Bearer {token}"
        except OSError:
            return None, b""
    return None, b""


def _head(ref: str, reference: str) -> tuple[str, str]:
    """(digest, content type) of manifest `reference` (tag or digest) in ref's repository."""
    h, _ = _open(ref, f"manifests/{reference}", "HEAD")
    if h is None:
        return "", ""
    d = h.get("Docker-Content-Digest", "")
    return (d if DIGEST_RE.match(d) else reference if DIGEST_RE.match(reference) else ""), h.get("Content-Type", "")


def describe(ref: str, digest: str) -> dict:
    """{'created': 'YYYY-MM-DD', 'size': compressed bytes} of the image behind `digest` for this
    machine's platform; {} for whatever the registry does not tell anonymously."""
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower(), "")
    try:
        _, body = _open(ref, f"manifests/{digest}")
        manifest = json.loads(body.decode("utf-8"))
        if manifest.get("manifests"):  # an index: take this machine's linux image
            pick = next((m for m in manifest["manifests"] if (m.get("platform") or {}).get("os") == "linux"
                         and (m.get("platform") or {}).get("architecture") == arch), None)
            if not pick:
                return {}
            _, body = _open(ref, f"manifests/{pick['digest']}")
            manifest = json.loads(body.decode("utf-8"))
        out = {"size": sum(int(ln.get("size", 0)) for ln in manifest.get("layers", []))}
        cfg_digest = (manifest.get("config") or {}).get("digest", "")
        if DIGEST_RE.match(cfg_digest):
            _, blob = _open(ref, f"blobs/{cfg_digest}")
            out["created"] = str(json.loads(blob.decode("utf-8")).get("created", ""))[:10]
        return out
    except (ValueError, AttributeError, TypeError):
        return {}


MODES = ("manual", "hold", "auto")


def update_modes(cfg: dict | None) -> tuple[dict, list]:
    """({service: mode}, [unrecognised values]) from the `om.update` label of pulled services.
    `hold` keeps the pin where it is, `auto` lets the scheduled sync move it (and undo it if the
    health check fails); anything else, or no label, is `manual`."""
    modes, bad = {}, []
    for name, svc in ((cfg or {}).get("services") or {}).items():
        if not (svc and svc.get("image") and not svc.get("build")):
            continue
        labels = svc.get("labels") or {}
        if isinstance(labels, list):
            labels = dict(ln.split("=", 1) if "=" in ln else (ln, "") for ln in labels)
        value = str(labels.get("om.update", "manual")).strip().lower()
        if value not in MODES:
            bad.append(f"{name}: om.update={value}")
            value = "manual"
        modes[name] = value
    return modes, bad


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
