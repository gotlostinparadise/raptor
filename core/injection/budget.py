"""Request budget + target-health guard for the injection runner (T1).

Two small primitives the runner enforces at every request-counter chokepoint,
so an LLM-orchestrated run can be bounded and a crashed target can be detected:

* :class:`RequestBudget` — a hard cap on how many HTTP requests one injection
  run may send. When the cap is reached the next guarded send raises
  :class:`BudgetExhausted`, which the runner catches to stop the phase and log
  what was skipped. A budget may *reduce* coverage, but never *silently*.

* :class:`HostHealth` — a connection-error circuit breaker that reuses the exact
  mechanism of :class:`core.http.urllib_backend._HostCircuitBreaker`
  (``record_failure`` / ``is_open`` / ``record_success`` with a sliding window +
  cooldown), but is fed **only connection-level failures**. The session engine
  swallows a refused/timed-out connection and hands the runner a
  ``Response`` with ``status == 0`` (see ``core/session/engine.py``); a real HTTP
  response — *including a 5xx* — always carries a non-zero status. So keying the
  breaker on ``status == 0`` opens it on a dead target but never on a 5xx, which
  is frequently the oracle's own signal (error-based SQLi). When the circuit is
  open the next guarded send raises :class:`CircuitOpen` and the run aborts
  instead of hammering a host that stopped answering.

Both are opt-in: a runner constructed without them behaves exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit


class InjectionHalt(Exception):
    """Base for conditions that stop a whole injection phase (not one point).

    The runner catches this distinctly from a per-point error: a per-point
    exception is logged and the loop continues; an :class:`InjectionHalt` breaks
    the loop so nothing else is sent.
    """


class BudgetExhausted(InjectionHalt):
    """The request budget for this run has been spent."""


class CircuitOpen(InjectionHalt):
    """The target stopped answering (connection refused / timeout)."""


@dataclass
class RequestBudget:
    """A hard cap on the requests an injection run may send.

    ``limit is None`` means unbounded — the historical behaviour. ``charge()``
    is called once per request *before* it is sent, so the cap is exact: a
    limit of ``N`` permits exactly ``N`` sends, and the ``N+1``-th raises.
    """

    limit: Optional[int] = None
    sent: int = 0

    def would_exceed(self) -> bool:
        return self.limit is not None and self.sent >= self.limit

    def charge(self) -> None:
        """Account one request; raise :class:`BudgetExhausted` at the cap."""
        if self.would_exceed():
            raise BudgetExhausted(
                f"request budget exhausted ({self.sent}/{self.limit} sent)")
        self.sent += 1

    @property
    def remaining(self) -> Optional[int]:
        if self.limit is None:
            return None
        return max(0, self.limit - self.sent)


@dataclass
class HostHealth:
    """Connection-error circuit breaker for one injection target.

    Wraps :class:`core.http.urllib_backend._HostCircuitBreaker` and feeds it
    only connection-level failures (``Response.status == 0``). ``threshold``
    consecutive failures inside ``window`` seconds open the circuit for
    ``cooldown`` seconds; a real response (any non-zero status) resets it.
    """

    host: str
    port: int
    threshold: int = 3
    window: float = 30.0
    cooldown: float = 3600.0
    _breaker: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        from core.http.urllib_backend import _HostCircuitBreaker
        self._breaker = _HostCircuitBreaker(
            threshold=self.threshold, window=self.window, cooldown=self.cooldown)

    def check(self) -> None:
        """Raise :class:`CircuitOpen` if the target is currently deemed down."""
        is_open, remaining = self._breaker.is_open(self.host, self.port)
        if is_open:
            raise CircuitOpen(
                f"target {self.host}:{self.port} unreachable — circuit open "
                f"({remaining:.0f}s cooldown remaining); aborting so we don't "
                f"hammer a dead host")

    def observe(self, status: int) -> None:
        """Feed one response status into the breaker.

        ``status == 0`` is the session engine's connection-refused/timeout
        signature → a failure. Anything else (2xx/3xx/4xx/**5xx**) is the target
        answering → a success that resets the failure history.
        """
        if status == 0:
            self._breaker.record_failure(self.host, self.port)
        else:
            self._breaker.record_success(self.host, self.port)

    @classmethod
    def for_url(cls, base_url: str, **kw: Any) -> "HostHealth":
        parts = urlsplit(base_url)
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return cls(host=host, port=port, **kw)


__all__ = [
    "InjectionHalt", "BudgetExhausted", "CircuitOpen",
    "RequestBudget", "HostHealth",
]
