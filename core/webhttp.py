"""Shared HTTP client for the web-pentest commands.

The `core.http` clients are tuned for *polite metadata fetching*: an https-only
egress path and a per-host circuit breaker that opens after a couple of 5xx to
back off a struggling host. Both are wrong for a pentest:

  - a target speaks http and non-standard ports, and
  - a 5xx is usually the *signal* (an error-based SQLi, a crash) — backing off on
    it fail-fasts the very responses the oracle needs.

:func:`pentest_client` returns the right client for a target: the
egress-allowlisted ``EgressClient`` for https:443 (scoped to the target host),
the unrestricted ``UrllibClient`` for http / non-443 — and **circuit-breaking
disabled** either way, so target errors are surfaced as data. This is the single
factory every web-pentest runner uses (replacing per-module ``_client_for``
copies).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def _disabled_breaker():
    # A breaker whose threshold is effectively unreachable — never opens.
    from core.http.urllib_backend import _HostCircuitBreaker
    return _HostCircuitBreaker(threshold=10 ** 9, window=1.0, cooldown=0.0)


def pentest_client(base_url: str) -> Any:
    """The HTTP client appropriate for pentesting ``base_url`` (breaker disabled).

    https on 443 → egress-allowlisted ``EgressClient`` (scoped to the host);
    http or any non-443 port → unrestricted ``UrllibClient`` (a single
    operator-declared, authorized target; redirect-following is disabled by the
    callers). Circuit-breaking is disabled so target 5xx/429 reach the oracle.
    """
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    if parts.scheme == "https" and parts.port in (None, 443) and host:
        from core.http import default_client
        client = default_client([host])
        # EgressClient's constructor doesn't accept a breaker; disable in place.
        try:
            client._circuit_breaker = _disabled_breaker()
        except Exception:
            pass
        return client
    from core.http.urllib_backend import UrllibClient
    return UrllibClient(circuit_breaker=_disabled_breaker())


__all__ = ["pentest_client"]
