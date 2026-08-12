"""R3 — auto-seed the access-control matrix from the mapped graph surface."""
from __future__ import annotations

import json

from core.webauthz.template import (
    _looks_object_scoped, endpoints_from_graph,
    tests_from_graph as build_authz_tests,   # aliased: `tests_*` collides with pytest collection
)


def test_looks_object_scoped_heuristic():
    assert _looks_object_scoped("/users/1")
    assert _looks_object_scoped("/api/orders/42/items")
    assert _looks_object_scoped("/profile?user_id=7")
    assert _looks_object_scoped("/rest/basket/{id}")
    assert _looks_object_scoped("/a/550e8400-e29b-41d4-a716-446655440000")
    assert not _looks_object_scoped("/login.php")
    assert not _looks_object_scoped("/vulnerabilities/xss_r/")


def test_endpoints_from_graph_infers_object_scoped(tmp_path):
    ndir = tmp_path / "normalized"
    ndir.mkdir()
    (ndir / "endpoints.jsonl").write_text("\n".join(json.dumps(r) for r in [
        {"method": "GET", "path": "/user?id=1", "url": "http://lab/user?id=1"},
        {"method": "GET", "path": "/about"},
        {"method": "GET", "path": "/admin/panel", "privileged": True},
    ]) + "\n", encoding="utf-8")
    eps = endpoints_from_graph(ndir)
    by_path = {e["path"]: e for e in eps}
    assert by_path["/user?id=1"]["object_scoped"] is True      # inferred from ?id=
    assert by_path["/about"]["object_scoped"] is False
    assert by_path["/admin/panel"]["privileged"] is True       # preserved


def test_endpoints_from_graph_missing_file(tmp_path):
    assert endpoints_from_graph(tmp_path / "nope") == []


def test_tests_from_graph_uses_operator_identities():
    identities = [
        {"name": "alice", "role": "user"},
        {"name": "root", "role": "admin"},
    ]
    endpoints = [
        {"method": "GET", "path": "/user?id=1", "object_scoped": True},
        {"method": "GET", "path": "/admin/panel", "privileged": True},
    ]
    tests = build_authz_tests(endpoints, identities)
    bola = [t for t in tests if t["class"] == "bola"][0]
    bfla = [t for t in tests if t["class"] == "bfla"][0]
    # BOLA owner is the non-admin; others include the admin + anonymous
    assert bola["owner"] == "alice"
    assert set(bola["others"]) == {"root", "anonymous"}
    assert bola["control_path"] == "/user?id=1"
    # BFLA owner is the admin-role identity
    assert bfla["owner"] == "root"
    assert "alice" in bfla["others"] and "anonymous" in bfla["others"]


def test_tests_from_graph_no_identities_is_empty():
    assert build_authz_tests([{"path": "/x", "object_scoped": True}], []) == []
