"""Payload catalog — RAPTOR's enrichable, oracle-tagged payload knowledge store.

The data layer for the "LLM proposes, tool verifies" hybrid: a growing set of
attack payloads, each tagged with its vulnerability class, reflection context,
the mechanical oracle that confirms it, and whether it is destructive (destructive
payloads are never sent). An LLM proposer (:mod:`core.payloads.proposer`) ranks
context-appropriate candidates; the runner's mechanical oracle remains the only
thing that confirms a finding — so adaptive payload *selection* never becomes
adaptive (hallucinated) *confirmation*.

Pieces:
  - :mod:`core.payloads.entry` — the slotted, oracle-tagged :class:`PayloadEntry`.
  - :mod:`core.payloads.seed` — the bundled curated starter set.
  - :mod:`core.payloads.store` — query by class + context.
  - :mod:`core.payloads.context` — detect where a probe marker reflected.
  - :mod:`core.payloads.proposer` — LLM ranking with a mechanical fallback.
  - :mod:`core.payloads.loaders` — enrich from PayloadsAllTheThings / PortSwigger.
  - :mod:`core.payloads.feedback` — remember payloads that produced a proof.
"""

from core.payloads.context import detect_context
from core.payloads.entry import PayloadEntry
from core.payloads.feedback import record_confirmed
from core.payloads.proposer import propose
from core.payloads.store import PayloadStore, default_store

__all__ = [
    "PayloadEntry", "PayloadStore", "default_store", "propose",
    "detect_context", "record_confirmed",
]
