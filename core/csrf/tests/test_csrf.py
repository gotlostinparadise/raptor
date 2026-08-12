"""Tests for core.csrf — token strip + token-absence state oracle."""

import json
from pathlib import Path

from core.csrf.config import from_dict
from core.csrf.runner import run_csrf
from core.csrf.strip import strip_token
from core.session.tests.fakes import FakeClient, resp


def test_strip_token_form_and_json():
    assert strip_token("a=1&user_token=XYZ&b=2", "user_token") == "a=1&b=2"
    out = strip_token('{"a":1,"user_token":"XYZ","b":2}', "user_token", "json")
    assert "user_token" not in out and '"a":1' in out
    # absent field → unchanged
    assert strip_token("a=1", "user_token") == "a=1"


def _cfg(**kw):
    base = {"base_url": "http://dvwa.test", "authorization": "lab",
            "path": "/change", "body": "pw=new&user_token=TOK&Change=Change",
            "token_field": "user_token", "success_signature": "changed"}
    base.update(kw)
    return from_dict(base)


def test_csrf_confirmed_when_token_not_required(tmp_path):
    # vulnerable app: performs the change regardless of the token
    def h(method, url, headers, body):
        return resp(200, body=b"password changed")   # always succeeds

    run = run_csrf(_cfg(), out_dir=tmp_path, active=True,
                   client_factory=lambda hosts: FakeClient(h))
    assert run.baseline_ok and run.token_absent_ok
    assert any(f.get("proof") == "state_oracle" for f in run.findings)
    rows = [json.loads(l) for l in (Path(tmp_path) / "normalized" / "vulns.jsonl").read_text().splitlines() if l.strip()]
    assert any(r["vuln_class"] == "csrf" for r in rows)


def test_csrf_no_finding_when_token_enforced(tmp_path):
    # secure app: rejects the token-less request
    def h(method, url, headers, body):
        if b"user_token=TOK" in (body or b""):
            return resp(200, body=b"password changed")
        return resp(403, body=b"CSRF token missing")

    run = run_csrf(_cfg(), out_dir=tmp_path, active=True,
                   client_factory=lambda hosts: FakeClient(h))
    assert run.baseline_ok and not run.token_absent_ok
    assert [f for f in run.findings if f.get("proof")] == []


def test_csrf_inconclusive_when_baseline_fails(tmp_path):
    def h(method, url, headers, body):
        return resp(500)
    run = run_csrf(_cfg(), out_dir=tmp_path, active=True,
                   client_factory=lambda hosts: FakeClient(h))
    assert not run.baseline_ok
    assert [f for f in run.findings if f.get("proof")] == []


def test_dry_run_sends_nothing(tmp_path):
    run = run_csrf(_cfg(), out_dir=tmp_path, active=False)
    assert run.requests_sent == 0
