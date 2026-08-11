"""Enrich the catalog from the PortSwigger XSS cheat sheet.

PortSwigger's cheat sheet is the canonical, context-aware XSS corpus — tag/event
vectors and sanitiser bypasses that a flat payload list lacks. It ships as a JSON
document; this loader walks it for candidate vectors and runs each through the
shared soundness gate (:func:`core.payloads.loaders.adapt_xss`) so only
oracle-verifiable, non-destructive payloads enter the catalog. The fetch is
injectable (``fetch=``) so it is unit-testable offline; the default pulls the
cheat-sheet JSON over the egress-allowlisted HttpClient.
"""

from __future__ import annotations

import json
from typing import Callable, List, Optional

from core.payloads.entry import CTX_ANY, ORACLE_UNESCAPED, PayloadEntry
from core.payloads.loaders import adapt_xss

_DEFAULT_URL = ("https://portswigger.net/web-security/cross-site-scripting/"
                "cheat-sheet.json")


def _looks_like_vector(s: str) -> bool:
    low = s.lower()
    return "<" in s or "javascript:" in low or "srcdoc" in low or "onerror" in low


def _extract_payloads(text: str) -> List[str]:
    """Pull candidate payload strings from the cheat-sheet JSON (or a line list).

    The cheat sheet nests vectors under tags/events; rather than couple to one
    schema version, walk the whole structure and keep any string that looks like
    an HTML/JS vector. Falls back to newline-splitting for a plain list.
    """
    try:
        data = json.loads(text)
    except Exception:
        return [ln.strip() for ln in text.splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
    out: List[str] = []

    def walk(node) -> None:
        if isinstance(node, str):
            if _looks_like_vector(node):
                out.append(node)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return out


def _default_fetch() -> str:
    from core.http import default_client
    client = default_client(["portswigger.net"])
    return client.get_bytes(_DEFAULT_URL, max_bytes=4 * 1024 * 1024).decode(
        "utf-8", "replace")


def load_xss(*, fetch: Optional[Callable[[], str]] = None,
             limit: int = 300) -> List[PayloadEntry]:
    """Return oracle-verifiable XSS entries adapted from the PortSwigger cheat sheet."""
    try:
        text = (fetch or _default_fetch)()
    except Exception:
        return []
    out: List[PayloadEntry] = []
    seen = set()
    for raw in _extract_payloads(text):
        adapted = adapt_xss(raw)
        if not adapted or adapted in seen:
            continue
        seen.add(adapted)
        out.append(PayloadEntry(
            id=f"ps-xss-{len(out):04d}", vuln_class="xss", template=adapted,
            oracle=ORACLE_UNESCAPED, context=CTX_ANY, technique="portswigger-import",
            source="PortSwigger", tags=("dom", "imported")))
        if len(out) >= limit:
            break
    return out


__all__ = ["load_xss"]
