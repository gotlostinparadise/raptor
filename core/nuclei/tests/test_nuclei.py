"""Tests for core.nuclei — tech→CVE correlation, JSONL parse, runner."""

import json

import pytest

from core.nuclei import techcve, wrapper
from core.nuclei.config import from_dict
from core.nuclei.runner import run_nuclei_scan
from core.labeled_attempts.view import Oracle, collect_outcomes


# ─────────────────────────── techcve ───────────────────────────

def test_split_tech():
    assert techcve.split_tech("nginx/1.18.0") == ("nginx", "1.18.0")
    assert techcve.split_tech("jQuery 3.4") == ("jquery", "3.4")
    assert techcve.split_tech("WordPress") == ("wordpress", "")


def test_correlate_version_gated():
    # openssl 1.0.1 is Heartbleed-affected; 1.1.1 is not
    assert techcve.correlate(["OpenSSL/1.0.1"])
    assert techcve.correlate(["OpenSSL/1.1.1"]) == []
    # struts has no version gate -> presence alone matches
    assert techcve.correlate(["struts"])


def test_correlate_matches_names_with_embedded_digits():
    # regression: log4j (digit in name) must still correlate from a real jar name
    hits = techcve.correlate(["log4j-core-2.17.1.jar"])
    assert any(h["cve"] == "CVE-2021-44228" for h in hits)
    # and from a bare "log4j" with no version, the ["2."] constraint blocks it
    # (no parseable version → can't substantiate) — honest suspected-only
    assert techcve.correlate(["log4j"]) == []


def test_correlate_component_wise_version_no_bleed():
    # "1.3" prefix must NOT match "1.30" (dotted-prefix bleed regression)
    assert techcve.correlate(["nginx/1.30"]) == []
    assert techcve.correlate(["nginx/1.3.1"])            # 1.3.x is affected


def test_tech_from_graph():
    g = {"nodes": [
        {"type": "tech", "id": "tech:nginx", "label": "nginx"},
        {"type": "service", "tech": ["PHP/7.4", "OpenSSL/1.0.1"]},
    ]}
    techs = techcve.tech_from_graph(g)
    assert "nginx" in techs and "PHP/7.4" in techs


# ─────────────────────────── wrapper parse ───────────────────────────

def test_parse_nuclei_jsonl():
    jsonl = "\n".join([
        json.dumps({"template-id": "CVE-2021-44228", "type": "http",
                    "matched-at": "https://x/api",
                    "info": {"name": "Log4Shell", "severity": "critical",
                             "classification": {"cve-id": ["cve-2021-44228"]}}}),
        "not json",
        json.dumps({"template-id": "tech-detect", "info": {"name": "nginx", "severity": "info"}}),
    ])
    out = wrapper.parse_results(jsonl)
    assert len(out) == 2
    assert out[0]["severity"] == "critical" and out[0]["cve"] == ["CVE-2021-44228"]


def test_build_command_is_list_form():
    cmd = wrapper.build_command("https://x", "/out.jsonl", tags=["cve"], severity=["high"])
    assert cmd[0] == "nuclei" and "-jsonl" in cmd and "-tags" in cmd


# ─────────────────────────── runner ───────────────────────────

def test_techcve_runs_in_dry_run(tmp_path):
    graph = tmp_path / "recon.json"
    graph.write_text(json.dumps({"nodes": [{"type": "tech", "label": "struts"}]}))
    run = run_nuclei_scan(from_dict({"recon_graph": str(graph), "target": ""}),
                          out_dir=tmp_path, active=False)
    assert run.suspected and run.suspected[0]["cve"] == "CVE-2017-5638"
    assert run.confirmed == []  # suspected are indicators, not confirmed


def test_active_gate(tmp_path):
    with pytest.raises(ValueError):
        run_nuclei_scan(from_dict({"target": "https://x", "authorization": ""}),
                        out_dir=tmp_path, active=True)


def test_nuclei_confirmed_becomes_verified_outcome(tmp_path):
    def fake_run(target, output_path, *, proxy_hosts, tags=None):
        return json.dumps({"template-id": "CVE-2021-41773", "matched-at": target,
                           "info": {"name": "Apache traversal", "severity": "high"}})

    # force availability + inject the run fn
    from core.nuclei import wrapper as W
    orig = W.available
    W.available = lambda: True
    try:
        run = run_nuclei_scan(
            from_dict({"target": "https://x.test", "authorization": "ok"}),
            out_dir=tmp_path, active=True, run_nuclei_fn=fake_run, producing_model="t")
    finally:
        W.available = orig
    assert run.confirmed and run.confirmed[0]["template"] == "CVE-2021-41773"
    outs = collect_outcomes(tmp_path, project_root=tmp_path)
    assert any(o.oracle == Oracle.WEB for o in outs)


def test_missing_nuclei_degrades_gracefully(tmp_path):
    from core.nuclei import wrapper as W
    orig = W.available
    W.available = lambda: False
    try:
        run = run_nuclei_scan(
            from_dict({"target": "https://x.test", "authorization": "ok"}),
            out_dir=tmp_path, active=True)
    finally:
        W.available = orig
    assert run.confirmed == []
    assert any("nuclei not installed" in w for w in run.warnings)
