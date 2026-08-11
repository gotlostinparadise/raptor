"""Offline tests for adaptive orchestration (layer 5) — no model, no network."""

from __future__ import annotations

from core.recon.model import SubdomainRecord
from core.recon.orchestrator import run_recon
from core.recon.source import Source, SourceResult
from core.recon.strategist import StrategyDecision, next_actions


# ─────────────────────────── next_actions ───────────────────────────

def test_next_actions_intersects_with_available():
    def fake_ask(prompt, schema, system, model):
        return {"run": ["dnsx", "invented_src"], "skip": ["naabu"],
                "reason": "focus DNS"}
    d = next_actions({"names": 5}, ["dnsx", "naabu", "httpx"], "m", ask=fake_ask)
    assert d.run == ["dnsx"]          # invented source dropped
    assert d.skip == ["naabu"]
    assert d.reason == "focus DNS"


def test_skip_set_run_is_allowlist():
    d = StrategyDecision(run=["dnsx"], skip=["naabu"])
    # run non-empty -> everything available except dnsx is skipped
    assert d.skip_set(["dnsx", "naabu", "httpx"]) == {"naabu", "httpx"}


def test_skip_set_skip_only():
    d = StrategyDecision(run=[], skip=["naabu"])
    assert d.skip_set(["dnsx", "naabu", "httpx"]) == {"naabu"}


def test_next_actions_failure_is_empty():
    d = next_actions({}, ["dnsx"], "m", ask=lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    assert d.run == [] and d.skip == []


# ─────────────────────────── orchestrator integration ───────────────────────────

class _Grower(Source):
    """Adds one new name in rounds 1 and 2, nothing after — keeps the loop alive."""
    name = "t_grower"
    consumes = ("roots",)
    produces = ("subdomains",)
    active = False

    def run(self, ctx):
        r = SourceResult(source=self.name)
        for i in (1, 2):
            sub = f"h{i}.example.com"
            if sub not in ctx.assets.names:
                r.add(SubdomainRecord(name=sub, root="example.com", sources=["t"]))
                r.discovered.names.add(sub)
                break
        return r


class _Counter(Source):
    """Records how many rounds it ran — the source the strategist prunes."""
    name = "t_counter"
    produces = ("subdomains",)
    active = False

    def __init__(self):
        self.runs = 0

    def run(self, ctx):
        self.runs += 1
        return SourceResult(source=self.name)


def test_strategist_prunes_a_source_after_round_one(tmp_path):
    grower, counter = _Grower(), _Counter()

    def strategist_ask(prompt, schema, system, model):
        return {"skip": ["t_counter"], "reason": "t_counter adds nothing"}

    run_recon(["example.com"], tmp_path, sources=[grower, counter], profile="passive",
              strategy_model="m", strategist_ask=strategist_ask)
    # grower keeps the loop alive for rounds 1 & 2; counter is skipped after round 1
    assert counter.runs == 1


def test_no_strategy_model_runs_every_round(tmp_path):
    grower, counter = _Grower(), _Counter()
    run_recon(["example.com"], tmp_path, sources=[grower, counter], profile="passive")
    # without a strategist, counter runs every round the loop executes (1, 2, 3)
    assert counter.runs == 3


def test_strategy_notes_recorded(tmp_path):
    grower, counter = _Grower(), _Counter()

    def strategist_ask(prompt, schema, system, model):
        return {"skip": ["t_counter"], "reason": "prune counter"}

    summary = run_recon(["example.com"], tmp_path, sources=[grower, counter],
                        profile="passive", strategy_model="m",
                        strategist_ask=strategist_ask)
    assert any("prune counter" in s for s in summary.strategy)
