"""Response-body normalization for the authorization oracle.

Byte-exact hash equality misses real BOLA/IDOR breaks: two responses for the
*same* object routinely differ in **volatile** fields — a server timestamp, an
anti-CSRF token, a request-id, pagination counters — so their raw SHA-256 hashes
diverge even though the underlying object is identical. The authz diff then fails
to see that the attacker read the owner's object.

This module canonicalizes a body so that volatility falls away, turning the diff
from *byte-equality* into *object-equality*. It stays strictly **mechanical**:

  * JSON is parsed, volatile keys are dropped recursively, and the result is
    re-serialized with sorted keys — order and volatile noise no longer matter.
  * Non-JSON (HTML/text) has its volatile *shapes* stripped — anti-CSRF hidden
    inputs, ISO-8601 timestamps, common nonce/request-id patterns.

There is **no fuzzy similarity / length-ratio path**: a "close enough" match
would manufacture false breaks (two different objects rendered in the same
template look ~identical), and the invariant is that a `confirmed` finding never
rests on a guess. Normalization only *removes known noise*; it never declares two
differing objects equal. Fields that identify the object (``id``, resource
values) are deliberately **kept**, so two different objects still differ.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Tuple

# Keys whose values vary between two responses for the SAME object — time,
# nonces / anti-CSRF, request correlation, and pagination counters (never the
# object's own identity). Compared case-insensitively and ignoring _/- separators.
_VOLATILE_KEYS = frozenset({
    # time
    "timestamp", "time", "datetime", "createdat", "updatedat", "created", "updated",
    "createdon", "updatedon", "lastlogin", "lastseen", "lastmodified", "modified",
    "iat", "exp", "nbf", "servertime", "now",
    # nonces / anti-CSRF / correlation
    "csrf", "csrftoken", "xsrf", "xsrftoken", "nonce", "requestid", "correlationid",
    "traceid", "spanid", "etag", "requesttoken", "antiforgerytoken",
    # pagination / counters (position in a list, not object identity)
    "cursor", "nextcursor", "prevcursor", "page", "perpage", "pagesize", "offset",
})


def _key_norm(k: str) -> str:
    return re.sub(r"[_\-\s]", "", str(k)).lower()


def _strip_volatile(obj: Any) -> Any:
    """Recursively drop volatile keys from dicts; recurse into lists."""
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items()
                if _key_norm(k) not in _VOLATILE_KEYS}
    if isinstance(obj, list):
        return [_strip_volatile(v) for v in obj]
    return obj


# Volatile textual shapes for non-JSON bodies (HTML/plain).
_CSRF_INPUT_RE = re.compile(
    rb"""(<input[^>]*\bname\s*=\s*['"]?(?:user_token|csrf[_-]?token|authenticity_token|"""
    rb"""_csrf|__RequestVerificationToken|xsrf[_-]?token)['"]?[^>]*\bvalue\s*=\s*['"])"""
    rb"""[^'"]*(['"])""",
    re.IGNORECASE,
)
_ISO_TS_RE = re.compile(
    rb"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
_META_CSRF_RE = re.compile(
    rb"""(<meta[^>]*\bname\s*=\s*['"]?csrf-token['"]?[^>]*\bcontent\s*=\s*['"])[^'"]*(['"])""",
    re.IGNORECASE,
)


def _strip_volatile_text(body: bytes) -> bytes:
    out = _CSRF_INPUT_RE.sub(rb"\1\2", body)
    out = _META_CSRF_RE.sub(rb"\1\2", out)
    out = _ISO_TS_RE.sub(b"<ts>", out)
    return out


def _looks_json(body: bytes) -> bool:
    head = body.lstrip()[:1]
    return head in (b"{", b"[")


def normalize(body: bytes, content_type: str = "") -> bytes:
    """Return a canonical form of ``body`` with volatile noise removed.

    JSON → volatile keys dropped, keys sorted, re-serialized. Otherwise the raw
    body with volatile textual shapes masked. Never conflates distinct objects:
    identity-bearing fields are preserved.
    """
    body = body or b""
    ct = (content_type or "").lower()
    is_json = "json" in ct or (not ct and _looks_json(body)) or _looks_json(body)
    if is_json:
        try:
            parsed = json.loads(body.decode("utf-8", errors="strict"))
            return json.dumps(_strip_volatile(parsed), sort_keys=True,
                              separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass
    return _strip_volatile_text(body)


def norm_sha256(body: bytes, content_type: str = "") -> str:
    return hashlib.sha256(normalize(body, content_type)).hexdigest()


def bodies_match(a: bytes, a_ct: str, b: bytes, b_ct: str) -> Tuple[bool, str]:
    """Whether two bodies represent the same object; and how they matched.

    Returns ``(match, kind)`` where kind is ``"exact"`` (byte-identical),
    ``"normalized"`` (equal after volatile-noise removal), or ``"differ"``.
    """
    if a == b:
        return True, "exact"
    if normalize(a, a_ct) == normalize(b, b_ct):
        return True, "normalized"
    return False, "differ"


__all__ = ["normalize", "norm_sha256", "bodies_match"]
