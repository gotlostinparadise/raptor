"""Shared LLM seam for the recon intelligence layers.

The single place recon talks to an LLM. Every intelligence layer — triage,
permutation seeding, scope proposal, the orchestration strategist — is a
*proposal* gated by a mechanical or operator verifier, so this helper only needs
to do three things:

  * make one structured call through the shared, metered LLM stack;
  * **degrade to ``{}`` on any failure** (never raise), so a caller with no model
    configured — or a flaky call — falls straight back to its mechanical
    behaviour and the engine never breaks because of the LLM;
  * expose an injectable ``ask=`` seam so every layer's tests run fully offline
    with a canned response.

Extracted from the original ``core.recon.triage`` pass; that verify-gate
discipline is the whole design (see ``docs/recon-intelligence.md``).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional


def _default_ask(prompt: str, schema: Dict[str, Any], system: str, model: str) -> Dict[str, Any]:
    """Real structured LLM call through the shared stack (metered/cached/scorecarded)."""
    from core.llm.client import LLMClient
    client = LLMClient()
    mc = client.config.config_for_model(model)
    resp = client.generate_structured(prompt, schema, system_prompt=system,
                                      model_config=mc)
    return getattr(resp, "result", None) or {}


def ask_structured(
    prompt: str,
    schema: Dict[str, Any],
    system: str,
    model: str,
    ask: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """One structured LLM call → a validated dict, or ``{}`` on any failure.

    ``ask`` is the offline-test injection seam (a fake ``(prompt, schema, system,
    model) -> dict``); it defaults to the real LLM call. Returning ``{}`` rather
    than raising is what lets every recon layer fall back to its mechanical path.
    """
    fn = ask or _default_ask
    try:
        result = fn(prompt, schema, system, model)
    except Exception:
        return {}
    return result if isinstance(result, dict) else {}


__all__ = ["ask_structured"]
