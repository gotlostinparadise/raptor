"""Feedback loop — record which catalog payloads produced a verified finding.

The enrichment flywheel: when a mechanical oracle confirms a payload, that
(payload, class, target-tech) tuple is worth remembering — it's a vector known to
work against a real stack, and a future proposer (LLM or mechanical) can promote
it. Written as append-only JSONL so it composes with the rest of RAPTOR's
evidence trail; a SAGE hook can ingest it for cross-run memory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


def feedback_path(explicit: Optional[str] = None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("RAPTOR_PAYLOAD_FEEDBACK")
    if env:
        return Path(env)
    return Path.home() / ".raptor" / "payload-feedback.jsonl"


def record_confirmed(
    entry_id: str, vuln_class: str, *, technique: str = "", target: str = "",
    timestamp: str = "", path: Optional[str] = None,
) -> None:
    """Append a confirmed-payload record. Best-effort; never raises."""
    try:
        p = feedback_path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        row = {"entry_id": entry_id, "vuln_class": vuln_class,
               "technique": technique, "target": target, "timestamp": timestamp}
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    except Exception:
        pass


__all__ = ["feedback_path", "record_confirmed"]
