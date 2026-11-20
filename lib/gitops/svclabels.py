#!/usr/bin/env python3
"""A compose service's labels as a dict. Compose allows both forms (`labels: {a: b}` and `labels: [a=b]`); the engine's
normalized config can hold either, and every om feature reads labels, so they all read them through here."""


def service_labels(svc: dict | None) -> dict:
    """The labels of a (normalized or raw) compose service; a bare list entry `a` is the label `a` with an empty value."""
    labels = (svc or {}).get("labels") or {}
    if isinstance(labels, list):
        return dict(ln.split("=", 1) if "=" in ln else (ln, "") for ln in labels)
    return labels
