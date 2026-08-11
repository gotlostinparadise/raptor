"""Offline tests for LLM permutation seeding (layer 3) — no model, no network."""

from __future__ import annotations

import json

import pytest

from core.recon import bruteforce as bf_mod
from core.recon.permute import llm_candidates
from core.recon.source import Assets, PROFILES, RunContext
from core.recon.toolrunner import ToolResult


def _ctx(tmp_path, *, names=(), roots=("example.com",), profile="home"):
    raw, norm = tmp_path / "raw", tmp_path / "normalized"
    raw.mkdir(parents=True, exist_ok=True)
    norm.mkdir(parents=True, exist_ok=True)
    return RunContext(roots=tuple(roots), assets=Assets(names=set(names)),
                      profile=PROFILES[profile], raw_dir=raw, normalized_dir=norm,
                      env={"PATH": "/usr/bin"}, credentials={})


# ─────────────────────────── llm_candidates ───────────────────────────

def test_llm_candidates_scope_and_expansion():
    def fake_ask(prompt, schema, system, model):
        return {"candidates": [
            "admin.example.com",     # in-scope FQDN -> kept
            "api-prod",              # bare label -> expanded under roots
            "evil.other.com",        # out-of-scope FQDN -> dropped
            "",                      # empty -> skipped
        ]}
    res = llm_candidates(["example.com"], ["api.example.com"], "m", ask=fake_ask)
    assert "admin.example.com" in res
    assert "api-prod.example.com" in res
    assert not any("other.com" in r for r in res)


def test_llm_candidates_failure_returns_empty():
    def boom(*a, **k):
        raise RuntimeError("model down")
    assert llm_candidates(["example.com"], [], "m", ask=boom) == []
    # {} response (no candidates) -> empty, no crash
    assert llm_candidates(["example.com"], [], "m", ask=lambda *a, **k: {}) == []


def test_llm_candidates_bounded():
    def fake_ask(prompt, schema, system, model):
        return {"candidates": [f"h{i}.example.com" for i in range(100)]}
    assert len(llm_candidates(["example.com"], [], "m", cap=10, ask=fake_ask)) == 10


# ─────────────────────────── bruteforce integration ───────────────────────────

def test_bruteforce_uses_llm_candidates_verified_by_dnsx(tmp_path):
    def fake_ask(prompt, schema, system, model):
        return {"candidates": ["admin-prod.example.com"]}

    def fake_dnsx(cmd, **kw):
        # dnsx "resolves" the LLM-proposed candidate
        return ToolResult(stdout=json.dumps(
            {"host": "admin-prod.example.com", "a": ["203.0.113.5"],
             "status_code": "NOERROR"}) + "\n")

    src = bf_mod.BruteforceSource(llm_model="m", ask=fake_ask, runner=fake_dnsx)
    ctx = _ctx(tmp_path, names={"api-prod.example.com"})
    r = src.run(ctx)
    # the LLM candidate reached the candidate file...
    cand = (tmp_path / "raw" / "bruteforce-candidates.txt").read_text()
    assert "admin-prod.example.com" in cand
    # ...and, because dnsx resolved it, it became records
    assert any(rec["name"] == "admin-prod.example.com" for rec in r.records["dns"])
    assert any(rec["name"] == "admin-prod.example.com" for rec in r.records["subdomains"])
    assert "203.0.113.5" in r.discovered.ips


def test_bruteforce_available_with_model_but_no_wordlist(tmp_path, monkeypatch):
    monkeypatch.setattr(bf_mod, "tool_available", lambda b: True)
    # model, no wordlist -> available (dnsx verifies the LLM candidates)
    assert bf_mod.BruteforceSource(llm_model="m").available(_ctx(tmp_path)) is True
    # neither wordlist nor model -> not available
    monkeypatch.delenv("RAPTOR_DNS_WORDLIST", raising=False)
    monkeypatch.delenv("RAPTOR_BRUTE_MODEL", raising=False)
    assert bf_mod.BruteforceSource().available(_ctx(tmp_path)) is False


def test_bruteforce_no_model_no_wordlist_is_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("RAPTOR_DNS_WORDLIST", raising=False)
    monkeypatch.delenv("RAPTOR_BRUTE_MODEL", raising=False)
    r = bf_mod.BruteforceSource(runner=lambda *a, **k: ToolResult()).run(_ctx(tmp_path))
    assert r.records == {}
