"""Brute-force / rate-limit weakness detection (M4 S5).

Fires N failed authentication attempts and checks whether the target ever
throttles or locks out. A run of N identically-processed failures with no
lockout/rate-limit response is a confirmed absence of brute-force protection
(:data:`core.webgraph.model.PROOF_STATE_ORACLE`, CWE-307) — a counting oracle,
like the race detector: the finding is the observed count, not a judgement, and
the tested threshold N is recorded so the claim is exactly "no lockout within N".
"""

from __future__ import annotations

from core.bruteforce.oracle import lockout_index, no_protection

__all__ = ["lockout_index", "no_protection"]
