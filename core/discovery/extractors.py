"""Pure extractors — endpoints and secrets from JavaScript / text.

The browser harness renders SPAs; this mines the *static* JS (and any text) for
the surface that never appears in the DOM: fetch/axios URLs, API paths in string
literals, and leaked credentials. All pure and regex-based, so unit-testable
with no network.

Secrets are never stored verbatim: :func:`extract_secrets` returns a redacted
preview + a SHA-256 fingerprint, so a finding proves a leak without the output
itself becoming a secondary leak.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List
from urllib.parse import urlsplit

# Endpoint-ish string literals: absolute paths and full URLs.
_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{2,}(?:\?[A-Za-z0-9_\-.=&%]*)?)["'`]""")
_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9_\-.:]+/[A-Za-z0-9_\-./?=&%]*)["'`]""")
_FETCH_RE = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]+)["'`]""")

# Secret patterns: (type, compiled regex). Ordered specific → generic.
_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("stripe_secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("generic_secret", re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)"""
        r"""["']?\s*[:=]\s*["']([A-Za-z0-9\-_./+]{16,})["']""")),
]


# Template-interpolation syntaxes that leak into extracted strings from SPA
# bundles (Angular/React/Vue). ``${...}`` (JS template literals) is stripped so
# the real path survives; the others mean the string isn't a resolvable endpoint.
_UNRESOLVABLE = ("{{", "<%", "#{", "`")
_JS_INTERP_RE = re.compile(r"\$\{[^}]*\}")


def _clean_endpoint(v: str) -> str:
    """Normalise a raw extracted string to a usable path/URL, or '' to drop it.

    Strips JS ``${...}`` interpolations (``${this.host}/rest/x`` → ``/rest/x``),
    rejects other template syntaxes and protocol-relative externals, and keeps
    only clean absolute paths or http(s) URLs. This is what stops SPA
    template-literal artifacts from polluting the graph and crashing downstream
    URL construction.
    """
    v = v.strip()
    if not v or any(t in v for t in _UNRESOLVABLE):
        return ""
    v = _JS_INTERP_RE.sub("", v)
    if v.startswith("//"):          # protocol-relative external ref
        return ""
    if v.startswith("http"):
        return v
    v = re.sub(r"/{2,}", "/", v)     # collapse slashes left by stripped interps
    if not v.startswith("/") or v == "/":
        return ""
    return v


def extract_endpoints(text: str, *, same_origin: str = "") -> List[str]:
    """Return de-duplicated endpoint paths/URLs found in ``text``.

    When ``same_origin`` (a canonical origin) is given, absolute URLs off that
    origin are dropped, keeping the crawl in scope; paths are always kept.
    Template-literal artifacts are cleaned via :func:`_clean_endpoint`.
    """
    found: List[str] = []
    seen = set()

    def add(raw: str) -> None:
        v = _clean_endpoint(raw)
        if not v or v in seen:
            return
        if v.startswith("http"):
            if same_origin and not v.startswith(same_origin):
                return
        seen.add(v)
        found.append(v)

    for rx in (_FETCH_RE, _URL_RE, _PATH_RE):
        for m in rx.finditer(text):
            add(m.group(1))
    return found


def _redact(value: str) -> Dict[str, str]:
    return {
        "preview": (value[:4] + "…") if len(value) > 4 else "…",
        "length": str(len(value)),
        "fingerprint": hashlib.sha256(value.encode("utf-8")).hexdigest()[:12],
    }


def extract_secrets(text: str) -> List[Dict[str, str]]:
    """Return redacted secret findings — never the raw secret value."""
    out: List[Dict[str, str]] = []
    seen = set()
    for kind, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            value = m.group(len(m.groups())) if m.groups() else m.group(0)
            fp = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
            if (kind, fp) in seen:
                continue
            seen.add((kind, fp))
            out.append({"type": kind, **_redact(value)})
    return out


def script_srcs(html: str, *, base_origin: str = "") -> List[str]:
    """Extract ``<script src=...>`` URLs from an HTML document."""
    out: List[str] = []
    for m in re.finditer(r"""<script[^>]+src=["']([^"']+)["']""", html, re.I):
        out.append(m.group(1))
    return out


def source_map_url(js_text: str) -> str:
    """Return the ``sourceMappingURL`` referenced by a JS file, or ''."""
    m = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", js_text)
    return m.group(1).strip() if m else ""


__all__ = [
    "extract_endpoints", "extract_secrets", "script_srcs", "source_map_url",
]
