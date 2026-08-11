"""Payload encoding / mutation for WAF evasion.

When a WAF blocks a payload, the same logical attack often slips through in a
different encoding. :func:`mutations` returns a set of encoded/mutated variants
of a payload; a caller (e.g. the injection runner under ``waf_evasion``) resends
each and keeps whichever the oracle still confirms. These are transforms, not new
attacks — the effect is unchanged, only the surface form differs.
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import quote

# SQL-ish keywords worth case-toggling / comment-splitting.
_KEYWORDS = re.compile(r"(?i)\b(union|select|from|where|and|or|insert|update|delete|script|alert|onerror)\b")


def _url_encode(p: str) -> str:
    return quote(p, safe="")


def _double_url_encode(p: str) -> str:
    return quote(quote(p, safe=""), safe="")


def _mixed_case(p: str) -> str:
    return _KEYWORDS.sub(lambda m: "".join(
        c.upper() if i % 2 else c.lower() for i, c in enumerate(m.group(0))), p)


def _comment_spaces(p: str) -> str:
    # SQL inline comments in place of spaces
    return p.replace(" ", "/**/")


def _null_byte(p: str) -> str:
    return p + "%00"


def _whitespace_alt(p: str) -> str:
    # tab / newline in place of spaces (parsers differ from WAF normalisers)
    return p.replace(" ", "\t")


def _keyword_split_comment(p: str) -> str:
    # UNION -> UN/**/ION style splitting inside keywords
    return _KEYWORDS.sub(lambda m: m.group(0)[:2] + "/**/" + m.group(0)[2:], p)


_TRANSFORMS = [
    _url_encode, _double_url_encode, _mixed_case, _comment_spaces,
    _null_byte, _whitespace_alt, _keyword_split_comment,
]


def mutations(payload: str) -> List[str]:
    """Return de-duplicated evasion variants of ``payload`` (original first)."""
    out: List[str] = [payload]
    seen = {payload}
    for fn in _TRANSFORMS:
        try:
            v = fn(payload)
        except Exception:
            continue
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


__all__ = ["mutations"]
