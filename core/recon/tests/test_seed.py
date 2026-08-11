"""Offline tests for /recon-seed scope proposal (layer 1) — no model, no network."""

from __future__ import annotations

import json

import pytest

from core.recon import seed_cli
from core.recon.seed import ScopeProposal, propose_scope


def test_propose_scope_parses_and_normalises():
    def fake_ask(prompt, schema, system, model):
        return {"candidates": [
            {"domain": "Acme-IO.com", "kind": "apex", "confidence": "high",
             "rationale": "primary brand TLD variant"},
            {"domain": "acquired-startup.com", "kind": "brand",
             "confidence": "medium", "rationale": "2023 acquisition"},
            {"domain": "acme-io.com"},   # dup after normalise -> dropped
            {"domain": ""},              # empty -> dropped
            "not-a-dict",                # ignored
        ]}
    p = propose_scope("Acme", ["acme.com"], "m", ask=fake_ask)
    domains = [c.domain for c in p.candidates]
    assert domains == ["acme-io.com", "acquired-startup.com"]   # normalised + deduped
    assert p.candidates[0].confidence == "high"
    assert "PROPOSAL ONLY" in p.note        # the operator-gate reminder


def test_propose_scope_failure_is_empty():
    def boom(*a, **k):
        raise RuntimeError("down")
    p = propose_scope("Acme", [], "m", ask=boom)
    assert p.candidates == []
    assert isinstance(p, ScopeProposal)


def test_seed_cli_writes_proposal(tmp_path, monkeypatch):
    # monkeypatch the proposer so the CLI runs offline (no real model)
    def fake_propose(org, seeds, model, ask=None):
        from core.recon.seed import ScopeCandidate
        return ScopeProposal(org=org, seeds=list(seeds), model=model,
                             candidates=[ScopeCandidate(domain="acme.io", kind="apex",
                                                        confidence="high",
                                                        rationale="brand variant")])
    monkeypatch.setattr(seed_cli, "propose_scope", fake_propose)
    rc = seed_cli.main(["--out-dir", str(tmp_path), "--org", "Acme",
                        "--seed", "acme.com", "--model", "m"])
    assert rc == 0
    data = json.loads((tmp_path / "scope-proposal.json").read_text())
    assert data["org"] == "Acme"
    assert data["candidates"][0]["domain"] == "acme.io"
    assert "PROPOSAL ONLY" in data["note"]   # gate reminder persisted


def test_seed_cli_requires_org_and_model(tmp_path):
    with pytest.raises(SystemExit):
        seed_cli.main(["--out-dir", str(tmp_path)])   # missing --org/--model
