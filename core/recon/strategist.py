"""Adaptive orchestration (recon intelligence layer 5).

Today the discovery loop runs every available source each round until the asset
set stops growing. A *strategist* makes that loop adaptive: given the current
graph state and which mechanical sources are available, it decides which to run
next and which to skip — e.g. a live DNS wildcard → skip ``bruteforce``; a
DDoS-Guard edge → prioritise ``exposed_origin``; a spec endpoint → the operator
should pivot to ``/webgraph``.

The **verify-gate is structural**: the strategist can only *select among
already-registered sources* (its choices are intersected with the available set),
so it can never invent a source or a finding — the sources it selects are the
same mechanical, oracle-backed sources as ever. No model / any failure ⇒ an empty
decision ⇒ the loop's default "run everything available" behaviour, unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from core.recon.llm import ask_structured

_SYSTEM = (
    "You steer an AUTHORIZED reconnaissance run. Given the current graph state "
    "and the list of mechanical sources available this round, choose which to "
    "run next and which to skip. You may ONLY select from the listed source "
    "names — you cannot invent a source or a finding. Skip sources that won't "
    "help given the state (e.g. bruteforce against a wildcard domain); prioritise "
    "sources the state makes promising (e.g. exposed-origin when an edge/WAF is "
    "present)."
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "run": {"type": "array", "items": {"type": "string"}},
        "skip": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
    },
}


@dataclass
class StrategyDecision:
    """Next-round source selection — always a subset of what's available."""

    run: List[str] = field(default_factory=list)
    skip: List[str] = field(default_factory=list)
    reason: str = ""

    def skip_set(self, available: Sequence[str]) -> set:
        """Sources to skip next round: explicit skips ∪ (available − run).

        If ``run`` is non-empty it is treated as an allow-list (everything else
        available is skipped); otherwise only the explicit ``skip`` applies.
        """
        avail = set(available)
        out = set(self.skip) & avail
        if self.run:
            out |= {s for s in avail if s not in set(self.run)}
        return out


def _build_prompt(summary: Dict[str, Any], available: Sequence[str]) -> str:
    lines = [f"{k}: {v}" for k, v in summary.items()]
    return (
        "Current recon graph state:\n" + "\n".join(lines) +
        f"\n\nSources available this round: {', '.join(available)}\n\n"
        "Choose `run` (sources worth running next) and/or `skip` (sources to "
        "skip), plus a one-line `reason`. Use only the available source names."
    )


def next_actions(
    summary: Dict[str, Any],
    available: Sequence[str],
    model: str,
    ask: Optional[Callable[..., Dict[str, Any]]] = None,
) -> StrategyDecision:
    """Ask the model which available sources to run/skip next; intersect with
    ``available`` so the decision can never reference an unknown source."""
    result = ask_structured(_build_prompt(summary, available), _SCHEMA, _SYSTEM,
                            model, ask=ask)
    avail = set(available)
    run = [s for s in (result.get("run") or []) if s in avail]
    skip = [s for s in (result.get("skip") or []) if s in avail]
    return StrategyDecision(run=run, skip=skip, reason=str(result.get("reason") or ""))


__all__ = ["StrategyDecision", "next_actions"]
