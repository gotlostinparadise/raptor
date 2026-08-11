"""Reflection-context detection — where did our probe marker land?

PortSwigger's core lesson: an XSS payload must match the *context* the input
reflects into (HTML body vs an attribute vs a JS string vs a URI), or it won't
fire. So before choosing payloads we send a benign marker and classify where it
came back. The catalog is then queried for context-appropriate vectors, which is
both higher-signal and far cheaper than blasting every payload.

Heuristic but robust for the common cases; returns *all* contexts the marker
appears in (input can reflect in several places).
"""

from __future__ import annotations

import re
from typing import List

from core.payloads.entry import (
    CTX_ATTR_DOUBLE, CTX_ATTR_SINGLE, CTX_COMMENT, CTX_HTML_BODY, CTX_JS_STRING, CTX_URI,
)


def _classify(before: str) -> str:
    """Classify the context immediately preceding a marker occurrence."""
    # Inside an HTML comment?
    if before.rfind("<!--") > before.rfind("-->"):
        return CTX_COMMENT
    # Inside a <script> block?
    if before.rfind("<script") > before.rfind("</script"):
        return CTX_JS_STRING
    # Inside a tag (an unclosed '<' after the last '>')?
    last_lt, last_gt = before.rfind("<"), before.rfind(">")
    if last_lt > last_gt:
        tag = before[last_lt:]
        # a javascript:/href URI context inside the tag?
        if re.search(r'(?:href|src)\s*=\s*["\']?\s*[^"\']*$', tag, re.I) and "javascript" not in tag.lower():
            # attribute value that is a URL — but distinguish quote style below
            pass
        # unmatched quote inside the attribute value?
        dq = tag.count('"') % 2 == 1
        sq = tag.count("'") % 2 == 1
        if dq and not sq:
            return CTX_ATTR_DOUBLE
        if sq and not dq:
            return CTX_ATTR_SINGLE
        # inside a src/href attribute (URI context) with no open quote
        if re.search(r'(?:href|src)\s*=\s*$', tag, re.I) or re.search(r'(?:href|src)\s*=\s*["\'][^"\']*$', tag, re.I):
            return CTX_URI
        return CTX_ATTR_DOUBLE   # generic in-tag → treat as attribute breakout
    return CTX_HTML_BODY


def detect_context(response_text: str, marker: str) -> List[str]:
    """Return the distinct contexts ``marker`` reflects into (order-stable).

    Empty when the marker isn't reflected at all (nothing to test in-context;
    the caller falls back to context-agnostic payloads).
    """
    if not marker or marker not in (response_text or ""):
        return []
    out: List[str] = []
    for m in re.finditer(re.escape(marker), response_text):
        ctx = _classify(response_text[max(0, m.start() - 200):m.start()])
        if ctx not in out:
            out.append(ctx)
    return out


__all__ = ["detect_context"]
