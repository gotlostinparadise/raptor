"""Scope helpers shared across recon sources and the builder.

Name normalisation and in-scope matching are needed by every source that
turns third-party data (CT logs, cert SANs, passive DNS) into subdomains, and
by the builder. Keeping them here — rather than in any one source — avoids both
duplication and a cross-source import that would drag an unrelated source's
registration in as a side effect.
"""

from __future__ import annotations

from typing import Sequence


def normalise_name(name: str) -> str:
    """Lowercase a DNS name and strip a leading wildcard / dot label.

    ``"*.API.Example.com "`` → ``"api.example.com"``. Idempotent.
    """
    return str(name).strip().lower().lstrip("*").lstrip(".")


def in_scope(name: str, roots: Sequence[str]) -> bool:
    """True when ``name`` equals one of ``roots`` or is a subdomain of one.

    Matching is **label-aware**: a bare ``name.endswith(root)`` would also match
    ``notexample.com`` for ``example.com`` and pull out-of-scope hosts into the
    graph. ``name`` is compared as-is; pass a :func:`normalise_name` result.
    """
    for root in roots:
        root = normalise_name(root)
        if not root:
            continue
        if name == root or name.endswith("." + root):
            return True
    return False


def root_of(host: str, roots: Sequence[str]) -> str:
    """Scope root a host belongs to, falling back to its last two labels.

    Prefers an exact/suffix match against ``roots``; if none matches (e.g. an
    external CNAME target), returns the registrable-ish base.
    """
    for r in roots:
        if host == r or host.endswith("." + r):
            return r
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


__all__ = ["normalise_name", "in_scope", "root_of"]
