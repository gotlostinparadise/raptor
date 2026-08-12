"""Tests for core.bruteforce — the no-lockout counting oracle + runner."""

import json
from pathlib import Path

from core.bruteforce.config import from_dict
from core.bruteforce.oracle import is_lockout, lockout_index, no_protection
from core.bruteforce.runner import run_bruteforce
from core.session.tests.fakes import FakeClient, resp


# ─────────────────────────── oracle ───────────────────────────

def test_is_lockout_429_and_signature():
    assert is_lockout(resp(429))
    assert is_lockout(resp(200, body=b"Too Many requests, slow down"))
    assert not is_lockout(resp(401, body=b'{"error":"invalid credentials"}'))


def test_no_protection_all_failures_no_lockout():
    responses = [resp(401, body=b"invalid") for _ in range(12)]
    assert no_protection(responses, min_attempts=10)
    assert lockout_index(responses) is None


def test_protection_when_lockout_appears():
    responses = [resp(401) for _ in range(5)] + [resp(429) for _ in range(7)]
    assert not no_protection(responses, min_attempts=10)
    assert lockout_index(responses) == 6


def test_no_protection_requires_min_attempts():
    responses = [resp(401) for _ in range(5)]
    assert not no_protection(responses, min_attempts=10)   # too few to conclude


# ─────────────────────────── runner ───────────────────────────

def _cfg(**kw):
    base = {"base_url": "https://app.test", "authorization": "lab",
            "login_url": "/login", "body": "user=admin&pass=wrong", "attempts": 12}
    base.update(kw)
    return from_dict(base)


def test_runner_confirms_no_protection(tmp_path):
    # app always returns 401 invalid — never locks out
    calls = [0]

    def h(method, url, headers, body):
        calls[0] += 1
        return resp(401, body=b'{"error":"invalid"}')

    run = run_bruteforce(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=lambda hosts: FakeClient(h))
    assert run.attempts_made == 12
    assert any(f.get("proof") == "state_oracle" for f in run.findings)
    rows = [json.loads(l) for l in (Path(tmp_path) / "normalized" / "vulns.jsonl").read_text().splitlines() if l.strip()]
    assert any(r["vuln_class"] == "no_bruteforce_protection" for r in rows)


def test_runner_no_finding_when_locked_out(tmp_path):
    def h(method, url, headers, body):
        n = h.n = getattr(h, "n", 0) + 1
        return resp(429) if n > 4 else resp(401)

    run = run_bruteforce(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=lambda hosts: FakeClient(h))
    assert [f for f in run.findings if f.get("proof")] == []
    assert run.lockout_at == 5


def test_dry_run_sends_nothing(tmp_path):
    run = run_bruteforce(_cfg(), out_dir=tmp_path, active=False)
    assert run.requests_sent == 0
