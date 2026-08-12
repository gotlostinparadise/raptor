"""State oracle for brute-force protection — count failures, detect lockout.

Lockout/throttling shows up as either an HTTP 429, or a response whose body
carries a lockout/rate-limit/CAPTCHA signature that the steady-state failure does
not. If neither ever appears across N attempts, the target processed every failed
attempt the same way — no brute-force protection (the observation is the proof).
"""

from __future__ import annotations

from typing import Any, List, Optional

# Body markers a throttled/locked response tends to carry (case-insensitive).
DEFAULT_LOCKOUT_SIGNATURES = (
    "too many", "rate limit", "try again later", "temporarily locked",
    "account locked", "locked out", "slow down", "captcha", "throttled",
)


def _text(resp: Any) -> str:
    body = getattr(resp, "body", b"") or b""
    return (body.decode("utf-8", errors="replace") if isinstance(body, bytes)
            else str(body)).lower()


def is_lockout(resp: Any, signatures=DEFAULT_LOCKOUT_SIGNATURES) -> bool:
    """Whether one response indicates throttling / lockout (429 or a signature)."""
    if resp is None or isinstance(resp, Exception):
        return False
    status = getattr(resp, "status", 0) or 0
    if status == 429:
        return True
    text = _text(resp)
    return any(sig in text for sig in signatures)


def lockout_index(responses: List[Any],
                  signatures=DEFAULT_LOCKOUT_SIGNATURES) -> Optional[int]:
    """1-based index of the first attempt that was locked/throttled, else None."""
    for i, r in enumerate(responses, start=1):
        if is_lockout(r, signatures):
            return i
    return None


def no_protection(responses: List[Any], *, min_attempts: int = 10,
                  signatures=DEFAULT_LOCKOUT_SIGNATURES) -> bool:
    """True iff enough attempts were made and NONE was ever locked/throttled."""
    processed = [r for r in responses if r is not None and not isinstance(r, Exception)]
    if len(processed) < min_attempts:
        return False
    return lockout_index(processed, signatures) is None


__all__ = ["DEFAULT_LOCKOUT_SIGNATURES", "is_lockout", "lockout_index", "no_protection"]
