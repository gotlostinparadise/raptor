"""Boundary-hardening tests for the /race state oracle (core.racecond.oracle).

The oracle's whole job is the confirm/deny decision at the limit boundary:
a limited operation that succeeds MORE times than its declared max is a
confirmed TOCTOU race; at-or-below the limit it is not. These tests feed the
oracle synthetic response sets built via the real ``resp`` fixture and pin the
verdict + count contract directly — no real races, no threads, no network.

Complements test_racecond.py (which drives the runner end-to-end); here we pin
the pure oracle branches: the ``>`` comparator, the 2xx/success-status gate, the
body-signature discriminator, exception handling, and the expected_max clamp.
"""

import pytest

from core.racecond import oracle
from core.session.tests.fakes import resp

_REDEEMED = b'{"status":"redeemed","discount":10}'


# ─────────────────────────── the limit boundary ───────────────────────────

@pytest.mark.parametrize("n", [2, 3, 5, 10])
def test_at_limit_n_successes_is_not_a_race(n):
    """Exactly-at-limit: N successes for a limit of N is expected behaviour,
    NOT a race. Pins ``>`` (strict) rather than ``>=`` for N>1 (the N=1 case
    lives in test_racecond.py)."""
    responses = [resp(200, body=_REDEEMED) for _ in range(n)]
    assert oracle.count_successes(responses, signature="redeemed") == n
    assert oracle.race_detected(n, expected_max=n) is False


@pytest.mark.parametrize("n", [1, 2, 3, 5, 20])
def test_one_over_limit_is_a_race(n):
    """Limit+1: the minimal violation. N+1 successes for a limit of N means the
    limit was not atomic — a confirmed race. Pins the boundary just above the
    limit (not merely the wide 3-vs-1 gap in the existing suite)."""
    responses = [resp(200, body=_REDEEMED) for _ in range(n + 1)]
    successes = oracle.count_successes(responses, signature="redeemed")
    assert successes == n + 1
    assert oracle.race_detected(successes, expected_max=n) is True


# ─────────────────────────── all-fail / zero success ───────────────────────

def test_zero_successes_all_fail_is_never_a_finding():
    """All-fail: every racer was rejected (403/409/429/5xx) — the limit held.
    Zero successes is never a finding, even against a zero-tolerance limit."""
    responses = [resp(403), resp(409), resp(429), resp(500), resp(503)]
    assert oracle.count_successes(responses) == 0
    assert oracle.race_detected(0, expected_max=1) is False
    assert oracle.race_detected(0, expected_max=0) is False


# ─────────────────────────── mixed responses ───────────────────────────────

def test_mixed_responses_counted_by_success_only():
    """Mixed set: only 2xx count. 201/204 are successes (whole 2xx range);
    429/409/5xx are the losing racers and must not inflate the count. Then the
    same count straddles the boundary: 3 > 2 (race) but 3 !> 3 (no race)."""
    responses = [resp(200), resp(429), resp(201), resp(409),
                 resp(204), resp(500), resp(502)]
    assert oracle.count_successes(responses) == 3           # 200, 201, 204
    assert oracle.race_detected(3, expected_max=2) is True
    assert oracle.race_detected(3, expected_max=3) is False


# ─────────────────────── idempotent reads ≠ extra successes ────────────────

def test_idempotent_reads_are_not_extra_successes():
    """A false-positive trap: N identical 200 reads (same balance, no mutation)
    is NOT N wins. A status-only oracle would over-count and cry race; the
    body-signature gate is the discriminator that keeps it a non-finding."""
    reads = [resp(200, body=b'{"balance":100}') for _ in range(10)]

    # Status-only view WOULD misfire — this is the failure the signature prevents.
    naive = oracle.count_successes(reads)
    assert naive == 10
    assert oracle.race_detected(naive, expected_max=1) is True

    # With the mutation marker required, none of the reads is a success → no race.
    gated = oracle.count_successes(reads, signature="redeemed")
    assert gated == 0
    assert oracle.race_detected(gated, expected_max=1) is False


# ─────────────────────── success-signal discrimination ─────────────────────

def test_exception_and_none_results_are_not_successes():
    """The harness stores a raised request as the Exception itself (and unfilled
    slots as None). Neither is a success — a crashed/aborted racer must never be
    counted as an extra win that fabricates a race."""
    assert oracle.is_success(RuntimeError("connection reset")) is False
    assert oracle.is_success(None) is False

    mixed = [resp(200, body=_REDEEMED), RuntimeError("net"), None,
             resp(200, body=_REDEEMED)]
    successes = oracle.count_successes(mixed, signature="redeemed")
    assert successes == 2                                    # only the two real wins
    assert oracle.race_detected(successes, expected_max=1) is True


def test_non_2xx_success_status_is_exact_match():
    """When the operator declares a non-2xx success_status, the gate switches
    from the 2xx range to an EXACT match: only that status counts, and an
    ordinary 200 no longer does."""
    assert oracle.is_success(resp(201), success_status=201) is True
    assert oracle.is_success(resp(200), success_status=201) is False
    assert oracle.is_success(resp(202), success_status=201) is False

    responses = [resp(201), resp(200), resp(201), resp(204)]
    # only the two 201s count under the declared success status
    assert oracle.count_successes(responses, success_status=201) == 2


def test_signature_requires_both_status_and_marker():
    """A success needs BOTH a passing status AND the marker in the body. A 200
    rejection body ('already used') is not a win; a 5xx that happens to echo the
    marker is not a win either (status gate runs first)."""
    assert oracle.is_success(resp(200, body=b"redeemed"), signature="redeemed") is True
    assert oracle.is_success(resp(200, body=b"already used"), signature="redeemed") is False
    assert oracle.is_success(resp(500, body=b"redeemed"), signature="redeemed") is False


# ─────────────────────────── expected_max clamp ────────────────────────────

def test_expected_max_zero_and_negative_are_clamped():
    """A zero-tolerance limit (expected_max=0) makes a single success a race,
    and a garbage negative limit clamps to 0 rather than suppressing — a
    negative threshold can never hide a real extra success."""
    assert oracle.race_detected(1, expected_max=0) is True
    assert oracle.race_detected(0, expected_max=0) is False
    assert oracle.race_detected(1, expected_max=-3) is True   # max(0, -3) == 0
    assert oracle.race_detected(0, expected_max=-3) is False
