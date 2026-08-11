"""Scope / acquisition proposal (recon intelligence layer 1).

The fuzziest, highest-leverage recon step: *what is even in scope?* — which apex
domains, brands, and ASNs plausibly belong to the target org, including
acquisitions a wordlist would never find. This is where an LLM's world-knowledge
earns its place.

The **verify-gate here is the operator**, not a tool: scope is a legal /
authorization matter, so a proposed root is NEVER auto-enumerated. This module
only produces a reviewable :class:`ScopeProposal`; a human confirms candidates
and feeds the confirmed ones to ``/recon`` (``--scope-file`` / ``--save-scope``).
Every candidate carries a confidence + rationale so the operator can judge it.

Pure proposal (no network): uses :func:`core.recon.llm.ask_structured` with the
standard injectable ``ask=`` seam. A future enhancement can annotate each
candidate with a mechanical signal (CT-log presence via ``crtsh``) to inform the
operator — but the human stays the gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from core.recon.llm import ask_structured
from core.recon.scope import normalise_name

_SYSTEM = (
    "You propose reconnaissance SCOPE candidates for an AUTHORIZED engagement. "
    "Suggest apex domains, brands, and ASNs that plausibly belong to the target "
    "organisation — including likely acquisitions and regional variants. A human "
    "operator CONFIRMS every candidate before any scanning; never state ownership "
    "as fact — give a confidence and a short rationale so they can judge it."
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "kind": {"type": "string"},        # apex | brand | asn
                    "confidence": {"type": "string"},  # low | medium | high
                    "rationale": {"type": "string"},
                },
                "required": ["domain"],
            },
        },
    },
    "required": ["candidates"],
}


@dataclass
class ScopeCandidate:
    domain: str
    kind: str = "apex"
    confidence: str = ""
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"domain": self.domain, "kind": self.kind,
                "confidence": self.confidence, "rationale": self.rationale}


@dataclass
class ScopeProposal:
    org: str
    seeds: List[str]
    model: Optional[str]
    candidates: List[ScopeCandidate] = field(default_factory=list)
    note: str = (
        "PROPOSAL ONLY — not scope. Review each candidate and confirm ownership / "
        "authorization before scanning; feed only confirmed roots to /recon."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {"org": self.org, "seeds": self.seeds, "model": self.model,
                "note": self.note,
                "candidates": [c.to_dict() for c in self.candidates]}


def _build_prompt(org: str, seeds: Sequence[str]) -> str:
    return (
        f"Target organisation: {org}\n"
        f"Known seeds (domains/brands already in scope): "
        f"{', '.join(seeds) or '(none given)'}\n\n"
        "Propose additional in-scope-*candidate* apex domains, brands, and ASNs "
        "that plausibly belong to this org (including acquisitions and regional "
        "variants). For each: `domain`, `kind` (apex|brand|asn), `confidence` "
        "(low|medium|high), and a one-line `rationale`."
    )


def propose_scope(
    org: str,
    seeds: Sequence[str],
    model: str,
    ask: Optional[Callable[..., Dict[str, Any]]] = None,
) -> ScopeProposal:
    """Propose scope candidates (operator-confirmed downstream). Never scans."""
    result = ask_structured(_build_prompt(org, seeds), _SCHEMA, _SYSTEM, model, ask=ask)
    seen = set()
    cands: List[ScopeCandidate] = []
    for c in (result.get("candidates") or []):
        if not isinstance(c, dict):
            continue
        domain = normalise_name(str(c.get("domain") or ""))
        if not domain or domain in seen:
            continue
        seen.add(domain)
        cands.append(ScopeCandidate(
            domain=domain, kind=str(c.get("kind") or "apex"),
            confidence=str(c.get("confidence") or ""),
            rationale=str(c.get("rationale") or ""),
        ))
    return ScopeProposal(org=org, seeds=list(seeds), model=model, candidates=cands)


__all__ = ["ScopeCandidate", "ScopeProposal", "propose_scope"]
