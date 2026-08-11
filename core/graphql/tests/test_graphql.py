"""Tests for core.graphql — introspection + batching, with fake servers."""

import json

import pytest

from core.graphql import checks
from core.graphql.config import from_dict
from core.graphql.introspection import operations, schema_from_response
from core.graphql.runner import run_graphql
from core.labeled_attempts.view import Oracle, collect_outcomes
from core.session.tests.fakes import FakeClient, resp

_SCHEMA = {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "users", "args": [{"name": "id"}]},
            {"name": "products", "args": []},
        ]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "deleteUser", "args": [{"name": "id"}]},
        ]},
    ],
}

_AUTH = "authorized fixture"


def _cfg(**kw):
    base = {"base_url": "https://api.test", "path": "/graphql", "authorization": _AUTH}
    base.update(kw)
    return from_dict(base)


def test_schema_parse_and_operations():
    body = json.dumps({"data": {"__schema": _SCHEMA}}).encode()
    schema = schema_from_response(resp(200, body=body))
    assert checks.introspection_enabled(schema)
    ops = operations(schema)
    names = {o.name for o in ops}
    assert {"users", "products", "deleteUser"} <= names


def test_alias_query_and_batching_oracle():
    q = checks.alias_query("products", 10)
    assert q.count("products") == 10
    resolved = {f"a{i}": [] for i in range(10)}
    assert checks.batching_accepted(resp(200, body=json.dumps({"data": resolved}).encode()), 10)
    # a complexity error is NOT acceptance
    assert not checks.batching_accepted(
        resp(200, body=json.dumps({"errors": [{"message": "too complex"}]}).encode()), 10)


def test_active_gate(tmp_path):
    cfg = _cfg(authorization="")
    with pytest.raises(ValueError):
        run_graphql(cfg, out_dir=tmp_path, active=True,
                    client_factory=lambda h: FakeClient(lambda *a: resp(200)))


def test_dry_run_sends_nothing(tmp_path):
    run = run_graphql(_cfg(), out_dir=tmp_path, active=False)
    assert run.active is False and run.findings and run.findings[0].get("planned")


def _introspecting_server(schema=_SCHEMA, batching=True):
    def h(method, url, headers, body):
        doc = json.loads(body)["query"]
        if "__schema" in doc:
            return resp(200, body=json.dumps({"data": {"__schema": schema}}).encode())
        if doc.strip().startswith("query {") and "a0:" in doc:
            n = doc.count("a") - doc.count("args")  # rough alias count
            if batching:
                return resp(200, body=json.dumps(
                    {"data": {f"a{i}": [] for i in range(n)}}).encode())
            return resp(200, body=json.dumps({"errors": [{"message": "limit"}]}).encode())
        return resp(200, body=b'{"data":{}}')
    return lambda hosts: FakeClient(h)


def test_introspection_open_confirmed_and_proof(tmp_path):
    run = run_graphql(_cfg(), out_dir=tmp_path, active=True,
                      client_factory=_introspecting_server(), producing_model="t")
    assert run.introspection_open and run.operation_count >= 3
    assert any(f["class"] == "graphql_introspection" for f in run.findings)
    outs = collect_outcomes(tmp_path, project_root=tmp_path)
    assert any(o.oracle == Oracle.WEB for o in outs)


def test_batching_dos_confirmed_when_resource_tests_on(tmp_path):
    run = run_graphql(_cfg(resource_tests=True, dos_field="products", dos_aliases=20),
                      out_dir=tmp_path, active=True,
                      client_factory=_introspecting_server(batching=True))
    assert any(f["class"] == "graphql_batching_dos" for f in run.findings)


def test_batching_not_run_without_resource_flag(tmp_path):
    run = run_graphql(_cfg(dos_field="products"), out_dir=tmp_path, active=True,
                      client_factory=_introspecting_server(batching=True))
    assert all(f["class"] != "graphql_batching_dos" for f in run.findings)


def test_closed_introspection_no_finding(tmp_path):
    def h(method, url, headers, body):
        return resp(400, body=b'{"errors":[{"message":"introspection disabled"}]}')
    run = run_graphql(_cfg(), out_dir=tmp_path, active=True,
                      client_factory=lambda hosts: FakeClient(h))
    assert not run.introspection_open and run.findings == []
