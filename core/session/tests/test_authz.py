"""Tests for core.session.authz — verdict → web-graph records (proof link)."""

import pytest

from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.authz import request_records, verdict_records, vuln_record
from core.session.replay import RequestTemplate, authorization_diff
from core.session.tests.fakes import FakeClient, resp
from core.webgraph import model as M
from core.webgraph.builder import build_graph

_BODY = b'{"order":1}'
_EID = "GET /api/orders/{id}"


def _broken_engine():
    def handler(method, url, headers, body):
        if headers.get("Authorization") or headers.get("Cookie"):
            return resp(200, body=_BODY)
        return resp(401)
    eng = SessionEngine(FakeClient(handler))
    for n in ("user_a", "user_b"):
        i = Identity(name=n); i.set_bearer(f"T_{n}"); i.authenticated = True
        eng.add_identity(i)
    return eng


def _verdict():
    eng = _broken_engine()
    return authorization_diff(
        eng, RequestTemplate("GET", "https://x.com/api/orders/1", label=_EID),
        owner="user_a")


def test_request_records_one_per_observation():
    rows = request_records(_verdict(), _EID)
    idents = {r["identity"] for r in rows}
    assert {"user_a", "user_b", "anonymous"} <= idents
    assert all(r["endpoint_id"] == _EID for r in rows)


def test_vuln_record_is_confirmed_with_authz_proof():
    row = vuln_record(_verdict(), _EID, vuln_id="AZ-1")
    assert row["status"] == M.STATUS_CONFIRMED
    assert row["proof_kind"] == M.PROOF_AUTHZ_DIFF
    assert "user_b" in row["identity"]
    assert row["evidence"]["owner"] == "user_a"


def test_vuln_record_refuses_non_violation():
    v = _verdict()
    v.violation = False
    with pytest.raises(ValueError):
        vuln_record(v, _EID, vuln_id="AZ-1")


def test_verdict_records_feed_the_web_graph_end_to_end():
    recs = verdict_records(_verdict(), _EID, vuln_id="AZ-1")
    # feed straight into the app-layer graph builder
    g = build_graph(recs)
    assert ("vuln", "AZ-1") in g.nodes
    assert g.nodes[("vuln", "AZ-1")]["attrs"]["proof_kind"] == M.PROOF_AUTHZ_DIFF
    assert (("endpoint", _EID), ("vuln", "AZ-1"), M.REL_VULNERABLE_TO) in g.edges
    # per-identity evidence rides on accessible_as edges
    assert (("identity", "user_b"), ("endpoint", _EID), M.REL_ACCESSIBLE_AS) in g.edges
