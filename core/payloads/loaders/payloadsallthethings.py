"""Enrich the catalog from PayloadsAllTheThings — with a soundness gate.

The key discipline for importing an external payload corpus into a *verify-first*
tool: a raw payload like ``<script>alert(1)</script>`` has no oracle signal, so
the runner could never confirm whether it fired or was merely reflected. This
loader therefore **adapts** each imported XSS payload to carry a sentinel
(``alert``/``prompt``/``console.log`` sinks are rewritten to
``window.__raptor_xss='{tok}'``) and **drops any payload it can't make
verifiable** — plus anything destructive. So the catalog grows without diluting
soundness: every imported entry still confirms mechanically.

Network fetch is injectable (``fetch=``) so this is unit-testable offline; the
default fetch pulls a raw payload list over the egress-allowlisted HttpClient.
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional

from core.payloads.entry import CTX_ANY, ORACLE_UNESCAPED, PayloadEntry

# A raw payload list in the repo (protocol-relative externals / one payload per line).
_DEFAULT_URL = ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/"
                "master/XSS%20Injection/Intruders/xss_alert.txt")

_SENTINEL = "window.__raptor_xss='{tok}'"

# Reject anything that could change state / destroy data (never sent).
_DESTRUCTIVE = re.compile(
    r"(?i)\b(rm\s+-rf|drop\s+table|delete\s+from|shutdown|format\s+|mkfs|"
    r"truncate|;\s*reboot|dd\s+if=)")

_SINK = re.compile(r"(?i)(alert|prompt|confirm|console\.log)\s*\([^)]*\)")


def _adapt(raw: str) -> Optional[str]:
    """Rewrite a raw XSS payload to set the sentinel, or None if unverifiable."""
    if not raw or len(raw) > 300 or _DESTRUCTIVE.search(raw):
        return None
    if not _SINK.search(raw):
        return None                       # no exec sink → can't confirm → drop
    return _SINK.sub(_SENTINEL, raw)


def _default_fetch() -> str:
    from core.http import default_client
    client = default_client(["raw.githubusercontent.com"])
    return client.get_bytes(_DEFAULT_URL, max_bytes=2 * 1024 * 1024).decode("utf-8", "replace")


def load_xss(*, fetch: Optional[Callable[[], str]] = None, limit: int = 300) -> List[PayloadEntry]:
    """Return oracle-verifiable XSS entries adapted from PayloadsAllTheThings."""
    try:
        text = (fetch or _default_fetch)()
    except Exception:
        return []
    out: List[PayloadEntry] = []
    seen = set()
    for i, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        adapted = _adapt(line)
        if not adapted or adapted in seen:
            continue
        seen.add(adapted)
        out.append(PayloadEntry(
            id=f"pat-xss-{len(out):04d}", vuln_class="xss", template=adapted,
            oracle=ORACLE_UNESCAPED, context=CTX_ANY, technique="pat-import",
            source="PayloadsAllTheThings", tags=("dom", "imported")))
        if len(out) >= limit:
            break
    return out


__all__ = ["load_xss"]
