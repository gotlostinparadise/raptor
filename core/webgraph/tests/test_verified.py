"""Tests for core.webgraph.verified — confirmed findings → verified-outcomes."""

import pytest

from core.labeled_attempts.view import Oracle, OutcomeStatus, collect_outcomes
from core.oast.interaction import Interaction, PROTO_DNS
from core.oast.outcome import vuln_record as oast_vuln
from core.webgraph import model as M
from core.webgraph.verified import labeled_attempt_from_vuln, record_confirmed


def _authz_vuln():
    return M.VulnRecord(
        id="AZ-1", vuln_class="bola", endpoint_id="GET /api/orders/{id}",
        identity="user_b", severity="high", owasp="API1",
        status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_AUTHZ_DIFF,
        evidence={"owner": "user_a", "offending": ["user_b"]},
        source="session",
    ).to_row()


def test_labeled_attempt_maps_class_to_cwe_and_evidence_type():
    la = labeled_attempt_from_vuln(_authz_vuln(), target_url="https://x.com/api/orders/1")
    assert la.cwe == "CWE-639"
    assert la.web_evidence.evidence_type == "authz_diff"
    assert la.web_evidence.target_url == "https://x.com/api/orders/1"
    assert la.outcome == "success" and la.reproducible is False


def test_suspected_finding_refused():
    row = _authz_vuln()
    row["status"] = M.STATUS_SUSPECTED
    with pytest.raises(ValueError):
        labeled_attempt_from_vuln(row)


def test_confirmed_without_proof_refused():
    row = _authz_vuln()
    row["proof_kind"] = M.PROOF_NONE
    with pytest.raises(ValueError):
        labeled_attempt_from_vuln(row)


def test_record_confirmed_surfaces_via_collect_outcomes(tmp_path):
    rows = [_authz_vuln()]
    # an OAST-confirmed blind SSRF too
    hits = [Interaction(token="t1", protocol=PROTO_DNS, host="t1.oast.test")]
    rows.append(oast_vuln(hits, vuln_id="OAST-1", vuln_class="blind_ssrf",
                          endpoint_id="POST /fetch", owasp="API7"))

    paths = record_confirmed(rows, project_dir=tmp_path, producing_model="test")
    assert len(paths) == 2

    outcomes = collect_outcomes(tmp_path, project_root=tmp_path)
    web = [o for o in outcomes if o.oracle == Oracle.WEB]
    ids = {o.finding_id for o in web}
    assert {"AZ-1", "OAST-1"} <= ids
    assert all(o.status == OutcomeStatus.VERIFIED for o in web)
    assert all(o.reproducible is False for o in web)


def test_all_web_vuln_classes_have_a_real_cwe():
    # Guard: every vuln_class the web commands can emit as a CONFIRMED finding
    # must map to a real CWE (not the CWE-0 fallback), so verified outcomes carry
    # a meaningful classification.
    from core.webgraph.verified import _CWE_BY_CLASS, _DEFAULT_CWE
    emitted = {
        # injection
        "ssti", "cmdi", "sqli", "nosqli", "path_traversal", "ssrf",
        "ssrf_metadata".replace("ssrf_metadata", "ssrf"),
        "cmdi_blind", "sqli_oob", "xxe",
        # authz
        "bola", "bfla", "property_level",
        # clientside
        "cors_origin_reflection", "csp_missing", "clickjacking", "cookie_flags",
        "open_redirect",
        # discovery
        "exposed_secret", "exposed_file", "source_map_exposed",
        # graphql
        "graphql_introspection", "graphql_batching_dos",
        # race
        "race_condition", "business_logic", "limit_bypass",
    }
    unmapped = [c for c in emitted if _CWE_BY_CLASS.get(c, _DEFAULT_CWE) == _DEFAULT_CWE]
    assert unmapped == [], f"vuln classes fall to default CWE: {unmapped}"


def test_record_confirmed_skips_unconfirmed(tmp_path):
    row = _authz_vuln()
    row["status"] = M.STATUS_SUSPECTED
    assert record_confirmed([row], project_dir=tmp_path) == []


# ── exploit-case auto-accrual (experience layer) ──────────────────────────────

def test_record_confirmed_accrues_proto_case(tmp_path, monkeypatch):
    """Every confirmed+proven row mints one proto exploit-case at this seam."""
    calls = []
    monkeypatch.setattr("core.sage.hooks.store_exploit_case",
                        lambda **kw: (calls.append(kw), True)[1])
    paths = record_confirmed([_authz_vuln()], project_dir=tmp_path,
                             target_urls={"GET /api/orders/{id}": "https://x.com/api/orders/2"})
    assert len(paths) == 1          # verified outcome still written
    assert len(calls) == 1          # and a case accrued
    kw = calls[0]
    assert kw["proof_kind"] == M.PROOF_AUTHZ_DIFF
    assert kw["vuln_class"] == "bola"
    assert kw["cwe"] == "CWE-639"
    assert kw["technique_id"] == "idor-bola-replay"   # methodology cross-ref
    assert kw["distilled"] is False                   # proto, needs enrichment
    assert len(kw["signature"]) >= 20
    assert "authz_diff" in kw["case_body"]
    assert "https://x.com/api/orders/2" in kw["signature"]


def test_accrual_disabled_by_env(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("core.sage.hooks.store_exploit_case",
                        lambda **kw: calls.append(kw))
    monkeypatch.setenv("RAPTOR_EXPLOIT_CASE_ACCRUAL", "0")
    record_confirmed([_authz_vuln()], project_dir=tmp_path)
    assert calls == []


def test_accrual_failure_never_breaks_record_confirmed(tmp_path, monkeypatch):
    """A SAGE/accrual error must not lose the verified outcome."""
    def boom(**kw):
        raise RuntimeError("sage down")
    monkeypatch.setattr("core.sage.hooks.store_exploit_case", boom)
    paths = record_confirmed([_authz_vuln()], project_dir=tmp_path)
    assert len(paths) == 1


def test_unconfirmed_not_accrued(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("core.sage.hooks.store_exploit_case",
                        lambda **kw: calls.append(kw))
    row = _authz_vuln()
    row["status"] = M.STATUS_SUSPECTED
    record_confirmed([row], project_dir=tmp_path)
    assert calls == []
