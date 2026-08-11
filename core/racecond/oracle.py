"""State oracle for business-logic / race findings.

The verdict is a count, not a judgement: if a limited operation (single-use
coupon, one withdrawal, a stock decrement) *succeeds more times than it should*
when fired concurrently, the limit is not atomic — a confirmed race. The oracle
just counts successful responses and compares against the operator-declared
expected maximum.
"""

from __future__ import annotations

from typing import Any, List, Optional


def _text(resp) -> str:
    body = getattr(resp, "body", b"") or b""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def is_success(resp, *, success_status: int = 200, signature: str = "") -> bool:
    """Whether one response counts as a successful operation.

    A response is a success when its status is 2xx (or exactly ``success_status``
    if a non-2xx success is declared) and, if a ``signature`` is given, that
    marker is present in the body. Exceptions (network failures) are not success.
    """
    if isinstance(resp, Exception) or resp is None:
        return False
    status = getattr(resp, "status", 0) or 0
    if success_status == 200:
        ok = 200 <= status < 300
    else:
        ok = status == success_status
    if not ok:
        return False
    if signature:
        return signature in _text(resp)
    return True


def count_successes(responses: List[Any], *, success_status: int = 200,
                    signature: str = "") -> int:
    return sum(1 for r in responses
               if is_success(r, success_status=success_status, signature=signature))


def race_detected(successes: int, expected_max: int) -> bool:
    """A race is confirmed when more operations succeeded than the declared max."""
    return successes > max(0, expected_max)


__all__ = ["is_success", "count_successes", "race_detected"]
