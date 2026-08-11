"""Tests for core.clientside.runner — probes + confirmation against fake servers."""

import pytest

from core.clientside.config import from_dict
from core.clientside.runner import MARKER_HOST, run_clientside
from core.labeled_attempts.view import Oracle, collect_outcomes
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized fixture"


def _cfg(**kw):
    base = {"base_url": "https://app.test", "authorization": _AUTH}
    base.update(kw)
    return from_dict(base)


def test_dry_run_sends_nothing(tmp_path):
    run = run_clientside(_cfg(), out_dir=tmp_path, active=False)
    assert run.requests_sent == 0 and run.findings[0].get("planned")


def test_active_gate(tmp_path):
    cfg = _cfg(); cfg.authorization = ""
    with pytest.raises(ValueError):
        run_clientside(cfg, out_dir=tmp_path, active=True,
                       client_factory=lambda h: FakeClient(lambda *a: resp(200)))


def _vulnerable_server():
    """CORS reflects any origin w/ creds; no CSP/XFO; insecure cookie; open redirect."""
    def h(method, url, headers, body):
        origin = headers.get("Origin")
        if MARKER_HOST in url:                      # redirect probe
            return resp(302, Location=f"//{MARKER_HOST}/", url=url)
        hdrs = {"Set-Cookie": "session=abc; Path=/"}
        if origin:
            hdrs["Access-Control-Allow-Origin"] = origin
            hdrs["Access-Control-Allow-Credentials"] = "true"
        return resp(200, body=b"<html></html>", **hdrs)
    return lambda hosts: FakeClient(h)


def _hardened_server():
    def h(method, url, headers, body):
        if MARKER_HOST in url:
            return resp(200, body=b"blocked")       # no redirect
        return resp(200, body=b"ok",
                    **{"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
                       "X-Frame-Options": "DENY",
                       "Set-Cookie": "s=1; Secure; HttpOnly; SameSite=Strict"})
    return lambda hosts: FakeClient(h)


def test_vulnerable_server_flags_everything(tmp_path):
    run = run_clientside(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=_vulnerable_server(), producing_model="t")
    classes = {f["class"] for f in run.findings}
    assert "cors_origin_reflection" in classes
    assert "csp_missing" in classes
    assert "clickjacking" in classes
    assert "cookie_flags" in classes
    assert "open_redirect" in classes
    # proofs surfaced
    outs = collect_outcomes(tmp_path, project_root=tmp_path)
    assert any(o.oracle == Oracle.WEB for o in outs)


def test_hardened_server_is_clean(tmp_path):
    run = run_clientside(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=_hardened_server())
    assert run.findings == []


def test_absence_findings_stay_out_of_verified_pool(tmp_path):
    # Q2 soundness: the vulnerable server yields 5 finding classes, but only the
    # two reflected/behavioural proofs (CORS origin reflection, open redirect)
    # are tool-produced proofs. CSP/clickjacking/cookie absence are header
    # observations — reported, but NOT reflected_marker-confirmed into the pool.
    run = run_clientside(_cfg(), out_dir=tmp_path, active=True,
                         client_factory=_vulnerable_server(), producing_model="t")
    classes = {f["class"] for f in run.findings}
    assert {"csp_missing", "clickjacking", "cookie_flags"} <= classes   # still reported
    web = [o for o in collect_outcomes(tmp_path, project_root=tmp_path)
           if o.oracle == Oracle.WEB]
    assert len(web) == 2                                # only reflection + redirect
    assert {o.cwe_id for o in web} == {"CWE-942", "CWE-601"}
