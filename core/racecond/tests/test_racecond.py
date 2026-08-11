"""Tests for core.racecond — harness, oracle, and the runner."""

import threading

import pytest

from core.labeled_attempts.view import Oracle, collect_outcomes
from core.racecond import oracle
from core.racecond.config import from_dict
from core.racecond.harness import fire_concurrent
from core.racecond.runner import run_race
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized fixture"


# ─────────────────────────── harness + oracle ───────────────────────────

def test_fire_concurrent_runs_all_and_aligns_results():
    out = fire_concurrent(lambda i: i * 2, 8)
    assert out == [0, 2, 4, 6, 8, 10, 12, 14]


def test_fire_concurrent_captures_exceptions():
    def boom(i):
        if i == 2:
            raise RuntimeError("x")
        return i
    out = fire_concurrent(boom, 4)
    assert isinstance(out[2], RuntimeError) and out[0] == 0


def test_oracle_counts_and_detects():
    responses = [resp(200), resp(200), resp(403), resp(200)]
    assert oracle.count_successes(responses) == 3
    assert oracle.race_detected(3, expected_max=1)
    assert not oracle.race_detected(1, expected_max=1)


def test_oracle_signature_gate():
    responses = [resp(200, body=b"redeemed"), resp(200, body=b"already used")]
    assert oracle.count_successes(responses, signature="redeemed") == 1


# ─────────────────────────── runner ───────────────────────────

def _cfg(expected_max=1, concurrency=10):
    return from_dict({
        "base_url": "https://shop.test", "authorization": _AUTH,
        "tests": [{"id": "RACE-1", "method": "POST", "path": "/coupon/redeem",
                   "body": "code=SAVE10", "concurrency": concurrency,
                   "expected_max": expected_max, "success_signature": "redeemed"}],
    })


def _vulnerable_coupon():
    """No locking: every concurrent redeem 'succeeds' (the race)."""
    def h(method, url, headers, body):
        return resp(200, body=b'{"status":"redeemed","discount":10}')
    return lambda hosts: FakeClient(h)


def _atomic_coupon():
    """Locked: only the first redeem succeeds; the rest are already-used."""
    lock = threading.Lock()
    state = {"used": False}

    def h(method, url, headers, body):
        with lock:
            if state["used"]:
                return resp(409, body=b'{"status":"already used"}')
            state["used"] = True
            return resp(200, body=b'{"status":"redeemed"}')
    return lambda hosts: FakeClient(h)


def test_dry_run_sends_nothing(tmp_path):
    run = run_race(_cfg(), out_dir=tmp_path, active=False)
    assert run.requests_sent == 0 and run.findings[0].get("planned")


def test_active_gate(tmp_path):
    cfg = _cfg(); cfg.authorization = ""
    with pytest.raises(ValueError):
        run_race(cfg, out_dir=tmp_path, active=True, client_factory=_vulnerable_coupon())


def test_race_confirmed_on_vulnerable_coupon(tmp_path):
    run = run_race(_cfg(concurrency=10), out_dir=tmp_path, active=True,
                   client_factory=_vulnerable_coupon(), producing_model="t")
    assert run.violations and run.violations[0]["id"] == "RACE-1"
    assert run.violations[0]["successes"] > 1
    outs = collect_outcomes(tmp_path, project_root=tmp_path)
    assert any(o.oracle == Oracle.WEB for o in outs)


def test_200_with_error_body_without_signature_is_suspected(tmp_path):
    # regression: an ATOMIC app that returns 200 {"error":"already used"} for the
    # losers must NOT be a confirmed race when no success_signature is set —
    # 2xx alone doesn't prove success. Report suspected, no verified outcome.
    lock = threading.Lock()
    state = {"used": False}

    def h(method, url, headers, body):
        with lock:
            if state["used"]:
                return resp(200, body=b'{"error":"already used"}')  # 200, not a success
            state["used"] = True
            return resp(200, body=b'{"status":"redeemed"}')

    cfg = from_dict({
        "base_url": "https://shop.test", "authorization": _AUTH,
        "tests": [{"id": "RACE-1", "method": "POST", "path": "/coupon/redeem",
                   "concurrency": 8, "expected_max": 1}],  # NO success_signature
    })
    run = run_race(cfg, out_dir=tmp_path, active=True,
                   client_factory=lambda h2: FakeClient(h))
    # apparent violation (all 200) but NOT confirmed → no verified outcome
    assert run.findings[0]["violation"] and run.findings[0]["confirmed"] is False
    outs = [o for o in collect_outcomes(tmp_path, project_root=tmp_path)
            if o.oracle == Oracle.WEB]
    assert outs == []


def test_no_race_on_atomic_coupon(tmp_path):
    run = run_race(_cfg(concurrency=10), out_dir=tmp_path, active=True,
                   client_factory=_atomic_coupon())
    assert run.violations == []
    # exactly one success is expected behaviour
    assert run.findings[0]["successes"] == 1


def test_concurrency_capped(tmp_path):
    cfg = _cfg(concurrency=1000)
    cfg.max_concurrency = 5
    run = run_race(cfg, out_dir=tmp_path, active=True, client_factory=_vulnerable_coupon())
    assert run.requests_sent == 5
