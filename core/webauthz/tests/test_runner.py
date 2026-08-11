"""Tests for core.webauthz.runner — the oracle engine + authorization gate."""

import re

import pytest

from core.labeled_attempts.view import Oracle, OutcomeStatus, collect_outcomes
from core.session.tests.fakes import FakeClient, resp
from core.webauthz import config as C
from core.webauthz.runner import run_authz

# A test WITH a negative control (order 9999 the owner doesn't own) — needed to
# prove the endpoint is object-specific, so a body-match is a real BOLA.
_CFG = {
    "base_url": "https://api.x.com",
    "authorization": "engagement ACME-2026; written approval on file",
    "identities": [
        {"name": "user_a", "login": {"type": "bearer", "token_env": "UA"}},
        {"name": "user_b", "login": {"type": "bearer", "token_env": "UB"}},
    ],
    "tests": [
        {"id": "AZ-1", "method": "GET", "path": "/api/orders/1001",
         "owner": "user_a", "class": "bola", "owasp": "API1",
         "others": ["user_b", "anonymous"], "control_path": "/api/orders/9999"},
    ],
}
_ENV = {"UA": "T_A", "UB": "T_B"}


def _order_id(url):
    m = re.search(r"/orders/(\d+)", url)
    return m.group(1) if m else "0"


def _broken_client(_hosts):
    """Object-specific but with NO ownership check: any authed identity reads any
    object → a real BOLA (and the control object returns different data)."""
    def handler(method, url, headers, body):
        if headers.get("Authorization"):
            oid = _order_id(url)
            return resp(200, body=f'{{"order":{oid},"data":"secret-{oid}"}}'.encode())
        return resp(401)
    return FakeClient(handler)


def _constant_client(_hosts):
    """Returns a CONSTANT body for everyone/every object — NOT a BOLA."""
    def handler(method, url, headers, body):
        if headers.get("Authorization"):
            return resp(200, body=b'{"status":"ok"}')
        return resp(401)
    return FakeClient(handler)


def _secure_client(_hosts):
    def handler(method, url, headers, body):
        auth = headers.get("Authorization", "")
        oid = _order_id(url)
        if not auth:
            return resp(401)
        if auth == "Bearer T_A" and oid == "1001":
            return resp(200, body=b'{"order":1001}')
        return resp(403, body=b'{"error":"forbidden"}')
    return FakeClient(handler)


def test_dry_run_sends_nothing_and_plans(tmp_path):
    calls = []

    def factory(_h):
        return FakeClient(lambda *a: calls.append(a) or resp(200))

    run = run_authz(C.from_dict(_CFG), out_dir=tmp_path, active=False,
                    client_factory=factory)
    assert run.active is False and run.tests_run == 0 and calls == []
    assert run.tests_planned == 1
    # surface graph still built (endpoints + identities), no requests sent
    assert (tmp_path / "graph" / "web.json").exists()
    assert run.node_count >= 3  # >=2 identities + >=1 endpoint


def test_active_without_authorization_refused(tmp_path):
    cfg = C.from_dict({**_CFG, "authorization": ""})
    with pytest.raises(ValueError):
        run_authz(cfg, out_dir=tmp_path, active=True, client_factory=_broken_client,
                  env=_ENV)


def test_active_with_passive_profile_refused(tmp_path):
    with pytest.raises(ValueError):
        run_authz(C.from_dict(_CFG), out_dir=tmp_path, active=True,
                  profile="passive", client_factory=_broken_client, env=_ENV)


def test_active_confirms_bola_and_writes_proof(tmp_path):
    run = run_authz(C.from_dict(_CFG), out_dir=tmp_path, active=True,
                    client_factory=_broken_client, env=_ENV, producing_model="test")
    assert run.tests_run == 1
    viols = run.violations
    assert len(viols) == 1 and viols[0]["id"] == "AZ-1"
    assert viols[0]["confirmed"] is True    # object-specific via control
    assert "user_b" in viols[0]["offending"] and "anonymous" not in viols[0]["offending"]

    # verified outcome surfaced through the real aggregator
    outs = [o for o in collect_outcomes(tmp_path, project_root=tmp_path)
            if o.oracle == Oracle.WEB]
    assert any(o.finding_id == "AZ-1" and o.status == OutcomeStatus.VERIFIED
               for o in outs)


def test_constant_response_endpoint_is_not_a_bola(tmp_path):
    # regression: an endpoint returning a constant body for every object must
    # NOT be flagged — the control matches the owner's body → suppressed.
    run = run_authz(C.from_dict(_CFG), out_dir=tmp_path, active=True,
                    client_factory=_constant_client, env=_ENV)
    assert run.violations == []
    outs = [o for o in collect_outcomes(tmp_path, project_root=tmp_path)
            if o.oracle == Oracle.WEB]
    assert outs == []


def test_no_control_path_is_suspected_not_verified(tmp_path):
    # regression: without a control_path a body-match is SUSPECTED, not a
    # verified outcome (can't prove object-specificity).
    cfg = C.from_dict({**_CFG, "tests": [{**_CFG["tests"][0], "control_path": ""}]})
    run = run_authz(cfg, out_dir=tmp_path, active=True,
                    client_factory=_broken_client, env=_ENV)
    assert run.violations and run.violations[0]["confirmed"] is False
    outs = [o for o in collect_outcomes(tmp_path, project_root=tmp_path)
            if o.oracle == Oracle.WEB]
    assert outs == []                       # suspected → no verified outcome


def test_active_secure_app_no_violation(tmp_path):
    run = run_authz(C.from_dict(_CFG), out_dir=tmp_path, active=True,
                    client_factory=_secure_client, env=_ENV)
    assert run.tests_run == 1 and run.violations == []


def test_missing_owner_credential_warns_but_runs(tmp_path):
    run = run_authz(C.from_dict(_CFG), out_dir=tmp_path, active=True,
                    client_factory=_secure_client, env={"UA": "T_A"})  # UB missing
    assert any("user_b" in w for w in run.warnings)
