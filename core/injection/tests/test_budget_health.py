"""Tests for T1 request budget + host-health guard, both as primitives and
wired through ``run_injection`` (the crash-fix: bound the sweep, abort on a dead
target — while never backing off on a 5xx, which is often the oracle's signal).
"""

import pytest

from core.injection.budget import (
    BudgetExhausted, CircuitOpen, HostHealth, RequestBudget,
)
from core.injection.config import from_dict
from core.injection.runner import run_injection
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized test fixture"


# ── primitives ───────────────────────────────────────────────────────

def test_request_budget_permits_exactly_limit_then_raises():
    b = RequestBudget(limit=3)
    b.charge(); b.charge(); b.charge()
    assert b.sent == 3 and b.remaining == 0
    with pytest.raises(BudgetExhausted):
        b.charge()


def test_unbounded_budget_never_raises():
    b = RequestBudget(limit=None)
    for _ in range(50):
        b.charge()
    assert b.remaining is None


def test_health_opens_on_connection_refused_not_on_5xx():
    h = HostHealth.for_url("http://t:8080", threshold=3, window=60, cooldown=60)
    # a 5xx is a real response (the oracle's signal) — must NOT open the circuit.
    for _ in range(10):
        h.observe(500)
    h.check()                                    # still closed → no raise
    # three connection failures (status 0) inside the window open it.
    h.observe(0); h.observe(0); h.observe(0)
    with pytest.raises(CircuitOpen):
        h.check()


def test_health_success_resets_failure_history():
    h = HostHealth.for_url("http://t", threshold=3, window=60, cooldown=60)
    h.observe(0); h.observe(0)                    # 2 failures (below threshold)
    h.observe(200)                                # a real response resets
    h.observe(0); h.observe(0)                    # 2 more — still below threshold
    h.check()                                     # never reached 3 in a row → closed


# ── wired through run_injection ──────────────────────────────────────

def _cfg(classes, **extra):
    data = {
        "base_url": "https://app.test", "authorization": _AUTH,
        "points": [{"method": "GET", "path": "/item", "param": "q",
                    "location": "query"}],
        "classes": classes,
    }
    data.update(extra)
    return from_dict(data)


def _static_app(seen=None):
    def h(method, url, headers, body):
        if seen is not None:
            seen.append(url)
        return resp(200, body=b"static page")
    return lambda hosts: FakeClient(h)


def _dead_app():
    # status 0 = the session engine's connection-refused/timeout signature.
    return lambda hosts: FakeClient(lambda *a: resp(0, body=b""))


def test_request_budget_bounds_the_run():
    seen = []
    cfg = _cfg(["ssti", "sqli", "cmdi", "path_traversal"], request_budget=3)
    run = run_injection(cfg, out_dir=_tmp(), active=True,
                        client_factory=_static_app(seen))
    assert run.requests_sent == 3
    assert len(seen) == 3
    assert any("halted" in w and "budget" in w for w in run.warnings)
    assert run.triage is not None                # budget set ⇒ triaged


def test_health_aborts_on_dead_target_without_hammering():
    cfg = _cfg(["sqli", "cmdi", "xss"], triage=True)   # triage on ⇒ health engaged
    run = run_injection(cfg, out_dir=_tmp(), active=True,
                        client_factory=_dead_app())
    # opens after the default 3 connection failures, then fail-fasts the rest.
    assert run.requests_sent == 3
    assert any("unreachable" in w or "circuit open" in w for w in run.warnings)


def test_no_triage_no_budget_is_unchanged_full_sweep():
    cfg = _cfg(["sqli"])                          # no model, no budget, no triage
    run = run_injection(cfg, out_dir=_tmp(), active=True,
                        client_factory=_static_app())
    assert run.triage is None                     # full-sweep path, no plan
    assert run.requests_sent > 0


def test_dry_run_emits_triaged_plan_without_sending():
    cfg = _cfg(["sqli", "xss", "path_traversal"], triage=True)
    run = run_injection(cfg, out_dir=_tmp(), active=False)
    assert run.requests_sent == 0
    assert run.triage is not None
    assert run.findings and run.findings[0].get("planned")


def test_config_request_budget_round_trips_from_dict():
    cfg = from_dict({"base_url": "https://x", "request_budget": 42, "triage": True})
    assert cfg.request_budget == 42 and cfg.triage is True


# ── helper ───────────────────────────────────────────────────────────

def _tmp():
    import tempfile
    return tempfile.mkdtemp()
