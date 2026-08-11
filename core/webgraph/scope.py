"""URL / endpoint scope + canonicalisation helpers for the web graph.

The app-layer graph keys endpoints on a *template* (``GET /api/users/{id}``),
not a concrete URL, so that ``/api/users/1`` and ``/api/users/2`` merge onto one
``endpoint`` node — the object id is a *parameter*, and collapsing the two is
exactly what makes BOLA analysis tractable (one node, many object ids replayed
through it). These helpers are shared by every web source and the builder, the
same way :mod:`core.recon.scope` is shared across recon.
"""

from __future__ import annotations

import re
from typing import Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

# A path segment that is really an object identifier, not a route label. Numeric
# ids, UUIDs, long hex/base -like blobs. Mirrors ``core.apitest.inventory``'s
# ``_ID_PARAM_RE`` intent but operates on the concrete path, not the spec.
_NUMERIC_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_HEXBLOB_SEG = re.compile(r"^[0-9a-f]{16,}$", re.I)

# Default ports we fold away so ``https://x`` and ``https://x:443`` share an origin.
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def canonical_origin(url: str) -> str:
    """``scheme://host[:port]`` with default ports dropped and host lowercased.

    ``"HTTPS://Example.com:443/a?b"`` → ``"https://example.com"``. Returns ``""``
    when ``url`` has no scheme+host (a relative reference).
    """
    parts = urlsplit(url.strip())
    if not parts.scheme or not parts.hostname:
        return ""
    host = parts.hostname.lower()
    port = parts.port
    if port is not None and str(port) != _DEFAULT_PORTS.get(parts.scheme.lower()):
        host = f"{host}:{port}"
    return f"{parts.scheme.lower()}://{host}"


def normalise_path(path: str) -> str:
    """Templatise object-id path segments to ``{id}`` and drop a trailing slash.

    ``"/api/Users/42/orders/8f.."`` → ``"/api/Users/{id}/orders/{id}"``. Route
    labels keep their case (paths are case-sensitive); only id-shaped segments
    collapse. The leading slash is preserved; ``""``/``"/"`` → ``"/"``.
    """
    if not path or path == "/":
        return "/"
    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if _NUMERIC_SEG.match(seg) or _UUID_SEG.match(seg) or _HEXBLOB_SEG.match(seg):
            out.append("{id}")
        else:
            out.append(seg)
    norm = "/".join(out)
    if len(norm) > 1 and norm.endswith("/"):
        norm = norm[:-1]
    return norm or "/"


def endpoint_id(method: str, path: str) -> str:
    """Stable ``endpoint`` node id: ``"<METHOD> <normalised-path>"``.

    The method is upper-cased and the path templatised so re-crawling with
    different object ids merges onto one node.
    """
    return f"{(method or 'GET').upper()} {normalise_path(path)}"


def split_url(url: str) -> Tuple[str, str]:
    """Return ``(origin, path)`` for a URL; ``path`` defaults to ``"/"``."""
    parts = urlsplit(url.strip())
    origin = canonical_origin(url)
    return origin, (parts.path or "/")


def in_scope(url: str, origins: Sequence[str]) -> bool:
    """True when ``url``'s canonical origin is one of the allowed ``origins``.

    Same-origin scope is the app-layer equivalent of recon's label-aware host
    scope: it stops a crawl following an off-site link into someone else's app.
    ``origins`` entries are canonicalised before comparison.
    """
    origin = canonical_origin(url)
    if not origin:
        return False
    allowed = {canonical_origin(o) or o.strip().lower().rstrip("/") for o in origins}
    return origin in allowed


def strip_query(url: str) -> str:
    """Drop query + fragment from a URL, keeping scheme/host/path."""
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def canonical_url(url: str) -> Optional[str]:
    """Canonical ``page`` node id: origin + path, query/fragment stripped.

    Returns ``None`` for a URL with no resolvable origin so callers can drop it.
    """
    origin = canonical_origin(url)
    if not origin:
        return None
    parts = urlsplit(url.strip())
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return f"{origin}{path}"


__all__ = [
    "canonical_origin", "normalise_path", "endpoint_id", "split_url",
    "in_scope", "strip_query", "canonical_url",
]
