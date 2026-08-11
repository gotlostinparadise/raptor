"""Tests for core.webgraph.model — record schema + graph vocabulary."""

import pytest

from core.webgraph import model as M


def test_record_kinds_registry_matches_classes():
    assert set(M.RECORD_KINDS) == set(M.RECORD_TYPES)
    for kind, cls in M.RECORD_TYPES.items():
        assert cls.KIND == kind


def test_node_types_align_with_graph_palette():
    from core.webgraph.graph import TYPES
    assert set(M.NODE_TYPES) == set(TYPES)


def test_to_row_drops_classvar_kind_and_is_json_serialisable():
    import json
    rec = M.EndpointRecord(method="get", path="/a/{id}", origin="https://x.com",
                           owasp_focus=["API1"])
    row = rec.to_row()
    assert "KIND" not in row
    assert row["method"] == "get" and row["owasp_focus"] == ["API1"]
    json.dumps(row)  # must not raise


def test_vuln_record_defaults_to_suspected_no_proof():
    v = M.VulnRecord(id="V1", vuln_class="bola", endpoint_id="GET /a/{id}")
    assert v.status == M.STATUS_SUSPECTED
    assert v.proof_kind == M.PROOF_NONE
    assert v.evidence == {}


def test_request_record_carries_evidence_fields():
    r = M.RequestRecord(endpoint_id="GET /a/{id}", identity="user_b",
                        status=200, resp_len=1234, allowed=True)
    row = r.to_row()
    assert row["identity"] == "user_b" and row["allowed"] is True


def test_param_locations_enumerated():
    assert M.LOC_QUERY in M.PARAM_LOCATIONS
    assert set(M.PARAM_LOCATIONS) == {
        M.LOC_QUERY, M.LOC_PATH, M.LOC_BODY, M.LOC_HEADER, M.LOC_COOKIE
    }


def test_normalized_filename():
    assert M.normalized_filename("endpoints") == "endpoints.jsonl"
