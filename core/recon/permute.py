"""LLM permutation seeding for the bruteforce source (recon intelligence layer 3).

A generic wordlist bruteforces the same names on every target. This proposes
*target-specific* candidates from the naming conventions actually observed on the
org's live hosts — seeing ``api-prod`` / ``web-staging`` suggests ``admin-prod`` /
``db-staging``. The mechanical **verify-gate is ``dnsx``** in
:mod:`core.recon.bruteforce`: a hallucinated name simply does not resolve and
never enters the graph, so the LLM can only *add* candidates, never a finding.

All the discipline lives in :func:`core.recon.llm.ask_structured` — propose-only,
injectable ``ask=`` for offline tests, ``{}`` on failure (⇒ no LLM candidates,
the wordlist bruteforce is unchanged).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from core.recon.llm import ask_structured
from core.recon.scope import in_scope, normalise_name

_SYSTEM = (
    "You expand a subdomain-bruteforce candidate list for an AUTHORIZED security "
    "test. From the naming conventions visible in the known live hosts, propose "
    "plausible ADDITIONAL hostnames under the in-scope roots. A separate DNS "
    "resolver decides which actually exist — you only guess. Return fully "
    "qualified names under the given roots; never invent new roots."
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "candidates": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["candidates"],
}


def _build_prompt(roots: Sequence[str], known_hosts: Sequence[str], cap: int) -> str:
    sample = list(known_hosts)[:200]
    return (
        f"In-scope roots: {', '.join(roots)}\n"
        f"Known live hosts (naming conventions to extrapolate from):\n"
        + ("\n".join(f"- {h}" for h in sample) or "- (none yet)")
        + f"\n\nPropose up to {cap} additional fully-qualified hostnames under the "
        f"roots above that fit the observed conventions and are worth resolving. "
        f"Return them in `candidates`."
    )


def llm_candidates(
    roots: Sequence[str],
    known_hosts: Sequence[str],
    model: str,
    *,
    cap: int = 300,
    ask: Optional[Callable[..., Dict[str, Any]]] = None,
) -> List[str]:
    """Target-specific bruteforce candidates from an LLM, scope-filtered + bounded.

    Accepts either in-scope FQDNs (used as-is) or bare labels (expanded under each
    root). Out-of-scope FQDNs are dropped. Deterministic order, deduplicated.
    """
    if not roots:
        return []
    result = ask_structured(_build_prompt(roots, known_hosts, cap), _SCHEMA,
                            _SYSTEM, model, ask=ask)
    out: List[str] = []
    seen = set()

    def _add(name: str) -> None:
        if name and name not in seen and len(out) < cap:
            seen.add(name)
            out.append(name)

    for raw in (result.get("candidates") or []):
        n = normalise_name(str(raw))
        if not n:
            continue
        if in_scope(n, roots):
            _add(n)
        elif "." not in n:                     # bare label → expand under roots
            for root in roots:
                _add(f"{n}.{normalise_name(root)}")
        # else: an out-of-scope FQDN — dropped
        if len(out) >= cap:
            break
    return out


__all__ = ["llm_candidates"]
