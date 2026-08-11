"""The LLM proposer — adaptive payload *selection*, never verdicts.

This is the "LLM proposes, tool verifies" seam made real at runtime. Given the
reflection context and a response excerpt, an LLM ranks the catalog's candidate
payloads by how likely each is to fire — an *ordering*, nothing more. The
mechanical oracle in the runner is still the only thing that confirms a finding,
so a wrong proposal merely wastes a request; the LLM cannot make a false finding
stick. It also cannot smuggle in an unverifiable payload: the return is a set of
catalog ids, and any id it invents is ignored, any it omits is appended — so
coverage is preserved and only the *order* is adapted.

Degrades to mechanical context-selection when no model is configured or the call
fails (so it works in CI and offline).
"""

from __future__ import annotations

from typing import List, Optional

from core.payloads.entry import PayloadEntry
from core.payloads.store import PayloadStore

_SYSTEM = (
    "You help order attack payloads for an authorized security test. You ONLY "
    "choose which payloads to try first; a separate mechanical oracle decides "
    "whether any actually worked. Never assert that something is vulnerable — "
    "just rank the candidates by likelihood given the reflection context."
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "ordered_payload_ids": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
    },
    "required": ["ordered_payload_ids"],
}


def _llm_rank(candidates: List[PayloadEntry], vuln_class: str,
              contexts, response_excerpt: str, model: str) -> List[str]:
    from core.llm.client import LLMClient
    client = LLMClient()
    mc = client.config.config_for_model(model)
    catalogue = "\n".join(
        f"- {e.id} [{e.context}/{e.technique or e.oracle}]: {e.template}"
        for e in candidates)
    prompt = (
        f"Vulnerability class under test: {vuln_class}.\n"
        f"Reflection context(s) where our marker landed: {contexts or 'unknown'}.\n"
        f"Response excerpt (truncated):\n{(response_excerpt or '')[:800]}\n\n"
        f"Candidate payloads (id [context/technique]: template):\n{catalogue}\n\n"
        f"Return ordered_payload_ids: the candidate ids most likely to fire in "
        f"this context, best first. Use only ids from the list."
    )
    resp = client.generate_structured(prompt, _SCHEMA, system_prompt=_SYSTEM,
                                      model_config=mc)
    result = getattr(resp, "result", None) or {}
    return list(result.get("ordered_payload_ids", []))


def propose(
    store: PayloadStore,
    vuln_class: str,
    *,
    context_hints: Optional[List[str]] = None,
    response_excerpt: str = "",
    model: Optional[str] = None,
    include_destructive: bool = False,
    target: str = "",
    feedback: Optional[str] = None,
) -> List[PayloadEntry]:
    """Return catalog entries to try, ordered best-first.

    Ordering combines two signals, in order of strength:

    1. **Flywheel** — vectors that a mechanical oracle has *confirmed* before
       (from the append-only feedback log) float to the front. Empirical proof a
       payload fires against a real stack beats any prediction.
    2. **LLM adaptation** — within that, an LLM ranks by the reflection context
       (a model must be configured; degrades to the store's context-first order).

    Both are *ordering only* — the full candidate set is always returned and the
    mechanical oracle in the runner remains the sole verdict, so neither signal
    can make a false finding stick. ``target`` scopes the flywheel to one host's
    history; ``feedback`` overrides the log path (tests / isolation).
    """
    candidates = store.select(vuln_class, contexts=context_hints,
                              include_destructive=include_destructive)
    if not candidates:
        return candidates

    ordered = list(candidates)
    if model:
        try:
            ordered_ids = _llm_rank(candidates, vuln_class, context_hints,
                                    response_excerpt, model)
            by_id = {e.id: e for e in candidates}
            ordered = [by_id[i] for i in ordered_ids if i in by_id]
            for e in candidates:        # preserve full coverage; only order changed
                if e not in ordered:
                    ordered.append(e)
        except Exception:
            ordered = list(candidates)

    # Flywheel boost: stably promote payloads confirmed before for this class.
    # sorted() is stable, so ties keep the LLM/mechanical order above; entries
    # with no confirmation history keep their place (count defaults to 0).
    from core.payloads.feedback import confirmed_counts
    counts = confirmed_counts(vuln_class, target=target, path=feedback)
    if counts:
        ordered = sorted(ordered, key=lambda e: -counts.get(e.id, 0))
    return ordered


__all__ = ["propose"]
