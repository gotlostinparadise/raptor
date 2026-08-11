"""Concurrency harness — fire N requests as close to simultaneously as possible.

A true single-packet attack aligns the final byte of many HTTP/2 streams so the
server processes them in one tick; without an HTTP/2 frame primitive we
approximate it with a thread barrier — every worker prepares its request, then
all release together on the barrier, minimising the window between sends. That is
enough to trip most TOCTOU races (double-spend, coupon reuse, limit bypass) in
practice, and the harness is transport-agnostic so tests drive it with a fake.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, List


def fire_concurrent(make_request: Callable[[int], Any], n: int, *,
                    timeout: float = 30.0) -> List[Any]:
    """Run ``make_request(i)`` for ``i`` in ``range(n)`` released simultaneously.

    Returns a list aligned to ``i`` of either the request result or the
    ``Exception`` it raised — the caller's oracle decides what counts as success.
    """
    if n <= 0:
        return []
    barrier = threading.Barrier(n)
    results: List[Any] = [None] * n

    def worker(i: int) -> None:
        try:
            barrier.wait(timeout=timeout)
        except threading.BrokenBarrierError:
            pass
        try:
            results[i] = make_request(i)
        except Exception as exc:  # captured, not raised — one failure ≠ abort
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)
    return results


__all__ = ["fire_concurrent"]
