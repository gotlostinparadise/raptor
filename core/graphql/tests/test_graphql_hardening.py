"""Oracle-boundary hardening for core.graphql.

These pin the *negative* and *boundary* verdicts of the two GraphQL oracles
(introspection-open detection + alias/batching amplification) — the branches a
positive-path-only suite leaves unguarded. No network, no sleeps; the runner is
driven with the same FakeClient stub the existing suite uses.
"""

import json

from core.graphql import checks
from core.graphql.config import from_dict
from core.graphql.introspection import schema_from_response
from core.graphql.runner import run_graphql
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized fixture"

_MIN_SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [{"name": "Query", "kind": "OBJECT",
               "fields": [{"name": "products", "args": []}]}],
}


def _cfg(**kw):
    base = {"base_url": "https://api.test", "path": "/graphql", "authorization": _AUTH}
    base.update(kw)
    return from_dict(base)


def _batch_resp(keys):
    """A 2xx response resolving ``keys`` aliases (a0..a{keys-1})."""
    return resp(200, body=json.dumps({"data": {f"a{i}": [] for i in range(keys)}}).encode())


# --- introspection_enabled: the DISABLED / degenerate schema is NOT a finding ---

def test_introspection_disabled_schema_is_no_finding():
    # None (introspection errored / no schema recovered) and empties are negative.
    assert checks.introspection_enabled(None) is False
    assert checks.introspection_enabled({}) is False
    # A schema object that came back but is degenerate (empty type list, no
    # queryType) must NOT be read as "introspection open".
    assert checks.introspection_enabled({"types": []}) is False


def test_introspection_enabled_requires_types_or_querytype():
    # The predicate is (types OR queryType) — a schema carrying ONLY a
    # mutationType satisfies neither and is not a finding.
    assert checks.introspection_enabled({"mutationType": {"name": "Mutation"}}) is False
    # Either arm alone is sufficient to confirm.
    assert checks.introspection_enabled({"queryType": {"name": "Query"}}) is True
    assert checks.introspection_enabled({"types": [{"name": "X"}]}) is True


# --- batching_accepted: amplification threshold is max(2, n // 2) ---

def test_batching_threshold_boundary_large_n():
    # n=10 -> threshold = max(2, 5) = 5. Below-majority is rejection, not amplification.
    assert checks.batching_accepted(_batch_resp(4), 10) is False   # just below
    assert checks.batching_accepted(_batch_resp(5), 10) is True    # at threshold
    assert checks.batching_accepted(_batch_resp(6), 10) is True    # above


def test_batching_threshold_floor_of_two():
    # Small n: the max(2, ...) floor dominates (n=2 -> max(2, 1) = 2).
    assert checks.batching_accepted(_batch_resp(1), 2) is False    # 1 resolved < floor
    assert checks.batching_accepted(_batch_resp(2), 2) is True     # meets floor


def test_batching_rejects_non2xx_partial_and_malformed():
    # Non-2xx never counts as acceptance even with a full data body.
    assert checks.batching_accepted(_batch_resp(10), 10) is True   # sanity: 2xx accepts
    r500 = resp(500, body=json.dumps({"data": {f"a{i}": [] for i in range(10)}}).encode())
    assert checks.batching_accepted(r500, 10) is False
    # Body that is not JSON -> no false positive.
    assert checks.batching_accepted(resp(200, body=b"<not json>"), 10) is False
    # data present but not an object (null / list / top-level list) -> rejected.
    assert checks.batching_accepted(resp(200, body=b'{"data": null}'), 10) is False
    assert checks.batching_accepted(resp(200, body=b'{"data": [1,2,3]}'), 10) is False
    assert checks.batching_accepted(resp(200, body=b'[1,2]'), 10) is False


# --- schema_from_response: malformed / partial bodies parse to None (no FP) ---

def test_malformed_introspection_response_no_false_positive():
    # Garbage body, a non-dict __schema, and an errors-only body all yield None,
    # which introspection_enabled must treat as "not open".
    for r in (
        resp(200, body=b"<html>not json</html>"),
        resp(200, body=json.dumps({"data": {"__schema": "nope"}}).encode()),
        resp(200, body=json.dumps({"errors": [{"message": "introspection disabled"}]}).encode()),
    ):
        schema = schema_from_response(r)
        assert schema is None
        assert checks.introspection_enabled(schema) is False


# --- runner-level negatives: a 2xx-with-errors and an errored request emit no finding ---

def test_runner_200_with_errors_is_no_finding(tmp_path):
    # Introspection blocked but the endpoint answers 2xx with a GraphQL error
    # (distinct from the existing 400 case). No schema -> no finding.
    def h(method, url, headers, body):
        return resp(200, body=b'{"errors":[{"message":"introspection is not allowed"}]}')

    run = run_graphql(_cfg(), out_dir=tmp_path, active=True,
                      client_factory=lambda hosts: FakeClient(h))
    assert run.introspection_open is False
    assert run.findings == []


def test_runner_introspection_error_records_warning_no_finding(tmp_path):
    # A raising transport must be swallowed into a warning, not a crash, and must
    # NOT manufacture a finding.
    def h(method, url, headers, body):
        raise RuntimeError("connection reset")

    run = run_graphql(_cfg(), out_dir=tmp_path, active=True,
                      client_factory=lambda hosts: FakeClient(h))
    assert run.introspection_open is False
    assert run.findings == []
    assert any("introspection failed" in w for w in run.warnings)


# --- status contract: a fired oracle emits CONFIRMED + reflected_marker ---

def test_confirmed_finding_status_and_proof_contract(tmp_path):
    # VulnRecord's default is suspected/PROOF_NONE; the runner overrides to
    # confirmed/reflected_marker ONLY because the oracle verdict fired.
    def h(method, url, headers, body):
        return resp(200, body=json.dumps({"data": {"__schema": _MIN_SCHEMA}}).encode())

    run = run_graphql(_cfg(), out_dir=tmp_path, active=True,
                      client_factory=lambda hosts: FakeClient(h))
    assert run.introspection_open is True

    rows = [json.loads(line) for line in
            (tmp_path / "normalized" / "vulns.jsonl").read_text().splitlines() if line.strip()]
    intro = [r for r in rows if r["vuln_class"] == "graphql_introspection"]
    assert len(intro) == 1
    assert intro[0]["status"] == "confirmed"
    assert intro[0]["proof_kind"] == "reflected_marker"
