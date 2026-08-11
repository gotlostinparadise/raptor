"""Offline tests for the recon triage pass (no LLM, no network)."""

from __future__ import annotations

import json

import pytest

from core.recon import triage
from core.recon.triage import (
    Candidate, _merge_order, extract_candidates, heuristic_score, llm_rerank,
    run_triage,
)


def _graph():
    """A small recon graph: a boring CDN asset, an interesting admin host, and an
    exposed-origin staging API behind an edge."""
    return {
        "nodes": [
            {"id": "root:example.com", "type": "root", "label": "example.com"},
            {"id": "subdomain:cdn-asset-42.example.com", "type": "subdomain",
             "label": "cdn-asset-42.example.com", "resolves": True},
            {"id": "subdomain:admin.example.com", "type": "subdomain",
             "label": "admin.example.com", "resolves": True},
            {"id": "subdomain:staging-api.example.com", "type": "subdomain",
             "label": "staging-api.example.com", "resolves": True},
            {"id": "service:https://admin.example.com", "type": "service",
             "server": "nginx", "tech": ["Jenkins"], "port": 8080},
            {"id": "service:https://staging-api.example.com", "type": "service",
             "server": "gunicorn", "tech": ["Flask"]},
            {"id": "ip:203.0.113.9", "type": "ip", "edge_kind": "waf",
             "edge_name": "DDoS-Guard"},
        ],
        "edges": [
            {"source": "subdomain:admin.example.com",
             "target": "service:https://admin.example.com", "rel": "serves"},
            {"source": "subdomain:staging-api.example.com",
             "target": "service:https://staging-api.example.com", "rel": "serves"},
            # staging-api resolves to an edge IP -> behind_edge
            {"source": "subdomain:staging-api.example.com",
             "target": "ip:203.0.113.9", "rel": "resolves_to"},
            # and an exposed-origin edge points at it
            {"source": "ip:198.51.100.5",
             "target": "subdomain:staging-api.example.com", "rel": "exposed_origin"},
        ],
    }


def test_extract_and_features():
    cands = {c.name: c for c in extract_candidates(_graph())}
    assert set(cands) == {
        "example.com", "cdn-asset-42.example.com", "admin.example.com",
        "staging-api.example.com",
    }
    admin = cands["admin.example.com"]
    assert admin.has_http and "Jenkins" in admin.tech and 8080 in admin.ports
    sapi = cands["staging-api.example.com"]
    assert sapi.exposed_origin and sapi.behind_edge


def test_heuristic_ranking_orders_interesting_first():
    cands = extract_candidates(_graph())
    cands.sort(key=lambda c: (-c.score, c.name))
    names = [c.name for c in cands]
    # admin (jenkins tech + admin token + non-std port) and staging-api
    # (exposed-origin + api/staging tokens) rank above the CDN asset + apex
    assert names.index("admin.example.com") < names.index("cdn-asset-42.example.com")
    assert names.index("staging-api.example.com") < names.index("cdn-asset-42.example.com")
    assert cands[0].score > 0


def test_scoring_signals():
    c = Candidate(id="s:a", kind="subdomain", name="admin-jenkins.example.com",
                  has_http=True, exposed_origin=True, ports=[8080], tech=["Jenkins"])
    score, reasons = heuristic_score(c)
    joined = " ".join(reasons)
    assert "name:admin" in joined
    assert "name:jenkins" in joined
    assert "exposed-origin" in joined
    assert "tech:jenkins" in joined
    assert score >= 8   # admin(3)+jenkins-token(3)+exposed(3)+http(1)+port(1)+tech(2)


def test_llm_rerank_drops_invented_keeps_omitted():
    cands = extract_candidates(_graph())
    cands.sort(key=lambda c: (-c.score, c.name))
    ids = [c.id for c in cands]

    def fake_ask(prompt, schema, system, model):
        # reverse the mechanical order, invent a bogus id, omit the last real one
        reordered = list(reversed(ids[:-1])) + ["subdomain:HALLUCINATED.example.com"]
        return {
            "ranked": [{"id": i, "rationale": f"why {i}"} for i in reordered],
            "narrative": "test narrative",
        }

    ordered, rationales, narrative = llm_rerank(cands, "fake-model", ask=fake_ask)
    assert "subdomain:HALLUCINATED.example.com" in ordered   # llm may return it...
    merged = _merge_order(cands, ordered)
    merged_ids = [c.id for c in merged]
    # ...but the merge drops the invented id and keeps every real one exactly once
    assert "subdomain:HALLUCINATED.example.com" not in merged_ids
    assert sorted(merged_ids) == sorted(ids)
    assert len(merged_ids) == len(set(merged_ids)) == len(ids)
    assert narrative == "test narrative"


def test_llm_failure_falls_back_to_empty():
    def boom(*a, **k):
        raise RuntimeError("model down")
    ordered, rationales, narrative = llm_rerank(
        extract_candidates(_graph()), "m", ask=boom)
    assert ordered == [] and rationales == {} and narrative == ""


def test_run_triage_heuristic_writes_artifacts(tmp_path):
    (tmp_path / "graph").mkdir()
    (tmp_path / "graph" / "recon.json").write_text(json.dumps(_graph()))
    summary = run_triage(tmp_path)
    assert summary["generated_by"] == "heuristic"
    assert summary["model"] is None
    assert summary["target_count"] == 4
    assert summary["targets"][0]["rank"] == 1
    assert (tmp_path / "triage.json").exists()
    md = (tmp_path / "triage.md").read_text()
    assert "Recon triage" in md and "admin.example.com" in md


def test_run_triage_with_model_reorders_and_narrates(tmp_path):
    (tmp_path / "graph").mkdir()
    (tmp_path / "graph" / "recon.json").write_text(json.dumps(_graph()))

    def fake_ask(prompt, schema, system, model):
        # force the CDN asset to the top to prove the model ordering wins
        return {"ranked": [{"id": "subdomain:cdn-asset-42.example.com",
                            "rationale": "model says look here"}],
                "narrative": "surface looks small"}

    summary = run_triage(tmp_path, model="fake-model", ask=fake_ask)
    assert summary["generated_by"] == "llm+heuristic:fake-model"
    assert summary["narrative"] == "surface looks small"
    assert summary["targets"][0]["name"] == "cdn-asset-42.example.com"
    assert summary["targets"][0]["rationale"] == "model says look here"
    # every original target still present (omitted ones appended)
    assert summary["target_count"] == 4


def test_missing_graph_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_triage(tmp_path)
