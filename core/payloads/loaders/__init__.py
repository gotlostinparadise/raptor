"""External payload-corpus loaders + their shared soundness gate.

Importing a third-party payload list into a *verify-first* tool is only sound if
every imported vector stays oracle-confirmable. A raw ``<script>alert(1)</script>``
has no signal the runner can key on — reflected or inert, it looks the same. So
each XSS loader runs its payloads through :func:`adapt_xss`, which rewrites the
exec sink (``alert``/``prompt``/``confirm``/``console.log``) to the DOM sentinel
``window.__raptor_xss='{tok}'`` and **drops anything it can't make verifiable**
(no sink) or that is destructive. That is what lets PayloadsAllTheThings, the
PortSwigger cheat sheet, and any future corpus grow the catalog without diluting
soundness — every imported entry still confirms mechanically.
"""

from __future__ import annotations

import re
from typing import Optional

# The DOM-execution sentinel every adapted XSS vector must set (the oracle keys
# on a real browser evaluating it — execution, not reflection).
SENTINEL = "window.__raptor_xss='{tok}'"

# Reject anything that could change state / destroy data (never sent).
_DESTRUCTIVE = re.compile(
    r"(?i)\b(rm\s+-rf|drop\s+table|delete\s+from|shutdown|format\s+|mkfs|"
    r"truncate|;\s*reboot|dd\s+if=)")

# An executable sink we can rewrite to the sentinel.
_SINK = re.compile(r"(?i)(alert|prompt|confirm|console\.log)\s*\([^)]*\)")


def adapt_xss(raw: str) -> Optional[str]:
    """Rewrite a raw XSS payload to set the sentinel, or ``None`` if unverifiable.

    Drops payloads over 300 chars, destructive ones, and any with no executable
    sink to rewrite (which the DOM oracle could never confirm).
    """
    if not raw or len(raw) > 300 or _DESTRUCTIVE.search(raw):
        return None
    if not _SINK.search(raw):
        return None
    return _SINK.sub(SENTINEL, raw)


__all__ = ["SENTINEL", "adapt_xss"]
