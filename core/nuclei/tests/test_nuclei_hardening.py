"""Hardening tests for core.nuclei — pins uncovered oracle/parser branches.

The load-bearing correctness surface here is the *verdict* code: the offline
tech→CVE version matcher (`techcve.correlate`) and the nuclei JSONL parser
(`wrapper.parse_results`). The most dangerous bug class is a version matcher
that flags a PATCHED release as vulnerable (false positive) or misses a
vulnerable one, so the boundary tests exercise both sides of a real patch line.

These are complementary to ``test_nuclei.py`` — they deliberately use different
technologies / JSONL shapes so no existing assertion is duplicated. Each test
pins a REAL contract, and asserts the persisted VulnRecord status/proof where the
suspected-vs-confirmed discipline actually lives.

No network, no ``nuclei`` binary, no sleeps: the parser and the offline
correlator are exercised directly, and the one active path uses the runner's
``run_nuclei_fn`` injection seam with ``wrapper.available`` monkeypatched.
"""

import json

import pytest

from core.nuclei import techcve, wrapper
from core.nuclei.config import from_dict
from core.nuclei.runner import run_nuclei_scan
from core.webgraph import model as M
from core.webgraph.orchestrator import load_records


# ─────────────── version-range boundary (core correctness) ───────────────

def test_version_boundary_jquery_patched_not_flagged():
    """jQuery CVE-2020-11022 patch boundary: 3.4.1 (vulnerable) is flagged,
    3.5.1 (the fixed release) is NOT. Guards the false-positive-on-patched case."""
    vuln = techcve.correlate(["jQuery/3.4.1"])
    assert any(h["cve"] == "CVE-2020-11022" for h in vuln)
    # 3.5.x is the fix; the ["...","3.4"] affected list must not bleed onto it.
    assert techcve.correlate(["jQuery/3.5.1"]) == []
    assert techcve.correlate(["jQuery/3.5.0"]) == []


def test_version_boundary_apache_exact_triple():
    """Apache CVE-2021-41773 uses exact triple-component affected versions
    (2.4.49 / 2.4.50). 2.4.49 is flagged; both the pre-vuln (2.4.48) and the
    fixed (2.4.51) neighbours are NOT — the matcher is not fuzzy on the patch."""
    assert any(h["cve"] == "CVE-2021-41773" for h in techcve.correlate(["Apache/2.4.49"]))
    assert any(h["cve"] == "CVE-2021-41773" for h in techcve.correlate(["Apache/2.4.50"]))
    assert techcve.correlate(["Apache/2.4.48"]) == []   # pre-vulnerable
    assert techcve.correlate(["Apache/2.4.51"]) == []   # patched


def test_no_version_gate_advisory_ignores_version():
    """An advisory with an empty ``affected`` list (Spring4Shell) is presence-only:
    a specific version present must NOT accidentally narrow/suppress it."""
    hits = techcve.correlate(["spring/5.3.18"])
    assert any(h["cve"] == "CVE-2022-22965" for h in hits)
    # version parsed and carried through, but did not gate the match
    assert all(h["version"] == "5.3.18" for h in hits if h["cve"] == "CVE-2022-22965")


# ─────────────────────── CVE correlation negatives ───────────────────────

def test_unknown_tech_yields_no_finding():
    """A fingerprint whose name matches no CVE-table key → no suspected finding
    (the substring gate rejects it before any version logic runs)."""
    assert techcve.correlate(["redis/6.2.1"]) == []
    assert techcve.correlate(["nodejs/18.16.0", "postgres/14.2"]) == []


def test_empty_tech_list_yields_no_finding():
    """No fingerprints → no findings (empty-iterable path, not a crash)."""
    assert techcve.correlate([]) == []


# ───────────────────── nuclei JSONL parsing edge cases ─────────────────────

def test_parse_empty_output_is_empty():
    """Empty / whitespace-only nuclei output parses to an empty list, no crash
    (this is the graceful path when nuclei matched nothing)."""
    assert wrapper.parse_results("") == []
    assert wrapper.parse_results("   \n \t\n  ") == []
    assert wrapper.parse_results(None) == []  # type: ignore[arg-type]


def test_parse_severity_lowercased_and_fallback():
    """Severity mapping: upper-cased severities are normalised down; an
    out-of-enum severity and a missing ``info`` block both fall back to 'info'."""
    jsonl = "\n".join([
        json.dumps({"template-id": "a", "info": {"name": "Up", "severity": "HIGH"}}),
        json.dumps({"template-id": "b", "info": {"name": "Bad", "severity": "totally-bogus"}}),
        json.dumps({"template-id": "c"}),  # no info block at all
    ])
    out = wrapper.parse_results(jsonl)
    assert [r["severity"] for r in out] == ["high", "info", "info"]
    assert out[2]["name"] == "" and out[2]["tags"] == []


def test_parse_scalar_cve_and_id_host_fallbacks():
    """A malformed row is skipped, then the alternate field spellings resolve:
    scalar ``cve-id`` string is wrapped+upper-cased, ``templateID`` supplies the
    id, and ``host`` supplies matched_at when ``matched-at`` is absent."""
    jsonl = "\n".join([
        "{ this is not json",
        json.dumps({"templateID": "tid-1", "host": "h.example",
                    "info": {"name": "S", "severity": "medium",
                             "classification": {"cve-id": "cve-2020-0001"}}}),
    ])
    out = wrapper.parse_results(jsonl)
    assert len(out) == 1                      # malformed row dropped, not fatal
    row = out[0]
    assert row["template_id"] == "tid-1"      # templateID fallback
    assert row["matched_at"] == "h.example"   # host fallback for matched-at
    assert row["cve"] == ["CVE-2020-0001"]    # scalar → list, upper-cased


# ───────────────── suspected-vs-confirmed status contract ─────────────────

def test_techcve_record_is_suspected_without_proof(tmp_path):
    """Contract: a tech→CVE correlation is SUSPECTED and carries no proof. The
    persisted VulnRecord must have status=suspected, proof_kind='' (PROOF_NONE),
    and never appear as a confirmed finding."""
    graph = tmp_path / "recon.json"
    graph.write_text(json.dumps({"nodes": [{"type": "tech", "label": "struts"}]}))
    run = run_nuclei_scan(from_dict({"recon_graph": str(graph), "target": ""}),
                          out_dir=tmp_path, active=False)
    rows = load_records(tmp_path / "normalized")["vulns"]
    assert len(rows) == 1
    rec = rows[0]
    assert rec["status"] == M.STATUS_SUSPECTED
    assert rec["proof_kind"] == M.PROOF_NONE == ""
    assert rec["vuln_class"] == "known_cve"
    assert run.confirmed == []                # suspected indicators are never confirmed


def test_nuclei_match_record_is_confirmed_with_proof(tmp_path, monkeypatch):
    """Contract: a nuclei template match is CONFIRMED and carries a tool proof.
    The persisted VulnRecord must have status=confirmed and
    proof_kind=reflected_marker — the opposite discipline from tech→CVE."""
    def fake_run(target, output_path, *, proxy_hosts, tags=None):
        return json.dumps({"template-id": "CVE-2021-41773", "matched-at": target,
                           "info": {"name": "Apache traversal", "severity": "high"}})

    monkeypatch.setattr(wrapper, "available", lambda: True)
    run = run_nuclei_scan(
        from_dict({"target": "https://x.test", "authorization": "ok"}),
        out_dir=tmp_path, active=True, run_nuclei_fn=fake_run, producing_model="t")

    rows = load_records(tmp_path / "normalized")["vulns"]
    assert len(rows) == 1
    rec = rows[0]
    assert rec["status"] == M.STATUS_CONFIRMED
    assert rec["proof_kind"] == M.PROOF_REFLECTED_MARKER
    assert rec["vuln_class"].startswith("nuclei:")
    assert run.confirmed and run.confirmed[0]["template"] == "CVE-2021-41773"


# ─────────────────────── safe-by-default active gate ───────────────────────

def test_active_passive_profile_refused(tmp_path):
    """The 'passive' profile can never authorize an active nuclei run — a
    distinct gate from the empty-authorization refusal already covered."""
    with pytest.raises(ValueError):
        run_nuclei_scan(from_dict({"target": "https://x", "authorization": "ok"}),
                        out_dir=tmp_path, active=True, profile="passive")
