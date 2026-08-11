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
from typing import Dict, Optional


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
    """Append a confirmed-payload record. Best-effort; never raises.

    Also mirrors the confirmation into SAGE (cross-run memory) when available —
    a no-op when the sidecar is absent. The JSONL write is the source of truth
    for :func:`confirmed_counts`; SAGE is the durable, queryable copy.
    """
    try:
        p = feedback_path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        row = {"entry_id": entry_id, "vuln_class": vuln_class,
               "technique": technique, "target": target, "timestamp": timestamp}
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    except Exception:
        pass
    _persist_to_sage(entry_id, vuln_class, technique, target)


def confirmed_counts(
    vuln_class: str, *, target: str = "", path: Optional[str] = None,
) -> Dict[str, int]:
    """How many times each catalog entry was confirmed for ``vuln_class``.

    Reads the append-only feedback log. When ``target`` is given, only rows for
    that exact target count (target-tech-specific boost); otherwise all targets
    contribute. Returns ``{entry_id: count}`` — the proposer uses it to promote
    vectors known to work. Best-effort; ``{}`` on any error or missing log.
    """
    counts: Dict[str, int] = {}
    try:
        p = feedback_path(path)
        if not p.exists():
            return counts
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("vuln_class") != vuln_class:
                continue
            if target and row.get("target") != target:
                continue
            eid = row.get("entry_id")
            if eid:
                counts[eid] = counts.get(eid, 0) + 1
    except Exception:
        pass
    return counts


def _persist_to_sage(entry_id: str, vuln_class: str, technique: str,
                     target: str) -> None:
    """Best-effort SAGE memory of a confirmed payload.

    Opt-in via ``RAPTOR_PAYLOAD_SAGE`` — writing to durable, shared cross-run
    memory is a side effect we keep off by default (so tests/CI/casual runs never
    pollute SAGE); set the flag on a real engagement to build the flywheel. No-op
    when the flag is unset or the sidecar is absent. The local JSONL log (source
    of truth for :func:`confirmed_counts`) is always written regardless.
    """
    if not os.environ.get("RAPTOR_PAYLOAD_SAGE"):
        return
    try:
        from core.sage.client import SageClient
        client = SageClient()
        if not client.is_available():
            return
        tgt = f" against {target}" if target else ""
        tech = f" ({technique})" if technique else ""
        content = (
            f"Confirmed {vuln_class} payload '{entry_id}'{tech}{tgt}: this catalog "
            f"vector produced an oracle-verified finding, so a future proposer "
            f"should try it early for {vuln_class} on similar stacks."
        )
        client.propose(content=content, memory_type="observation",
                       domain_tag="raptor-methodology",
                       tags=[vuln_class, technique or "confirmed", "payload"])
    except Exception:
        pass


__all__ = ["feedback_path", "record_confirmed", "confirmed_counts"]
