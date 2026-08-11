"""Adapter: authorization verdicts → web-graph records (the proof link).

Keeps :mod:`core.session.replay` free of any graph dependency while giving
Phase-B drivers a one-call bridge from an :class:`~core.session.replay.AuthzVerdict`
to the :mod:`core.webgraph.model` records that land in the app-layer graph:

  - one :class:`~core.webgraph.model.RequestRecord` per identity observed (the
    captured evidence, riding onto the ``accessible_as`` edge), and
  - a :class:`~core.webgraph.model.VulnRecord` when the verdict is a violation,
    marked ``confirmed`` with :data:`~core.webgraph.model.PROOF_AUTHZ_DIFF` —
    because a tool (the diff), not the LLM, established it.

The same verdict feeds :mod:`core.labeled_attempts` for the verified-outcomes
surface (A5); this adapter is deliberately the single translation point.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.session.replay import AuthzVerdict
from core.webgraph import model as M


def request_records(verdict: AuthzVerdict, endpoint_id: str, *, source: str = "session") -> List[Dict[str, Any]]:
    """One :class:`RequestRecord` row per observation in the verdict."""
    rows = []
    for obs in verdict.observations:
        rows.append(M.RequestRecord(
            endpoint_id=endpoint_id, identity=obs.identity,
            status=obs.status, resp_len=obs.resp_len,
            body_sha256=obs.body_sha256, allowed=obs.allowed,
            source=source,
        ).to_row())
    return rows


def vuln_record(
    verdict: AuthzVerdict, endpoint_id: str, *,
    vuln_id: str, source: str = "session", severity: str = "high",
    vuln_class: str = "bola", owasp: str = "API1", confirmed: bool = True,
) -> Dict[str, Any]:
    """Build the :class:`VulnRecord` for a violating verdict.

    Raises ``ValueError`` if the verdict is not a violation. ``confirmed=False``
    (no negative control proving the response is object-specific) records it as
    SUSPECTED with no proof — a constant/public response can body-match across
    identities without being a real BOLA.
    """
    if not verdict.violation:
        raise ValueError("verdict is not a violation; no proof to record")
    base = verdict.observation(verdict.owner)
    return M.VulnRecord(
        id=vuln_id, vuln_class=vuln_class, endpoint_id=endpoint_id,
        identity=",".join(verdict.offending), severity=severity, owasp=owasp,
        status=M.STATUS_CONFIRMED if confirmed else M.STATUS_SUSPECTED,
        proof_kind=M.PROOF_AUTHZ_DIFF if confirmed else M.PROOF_NONE,
        evidence={
            "object_specific": confirmed,
            "owner": verdict.owner,
            "offending": verdict.offending,
            "owner_body_sha256": base.body_sha256 if base else "",
            "observations": [
                {"identity": o.identity, "status": o.status,
                 "resp_len": o.resp_len, "allowed": o.allowed}
                for o in verdict.observations
            ],
        },
        source=source,
    ).to_row()


def verdict_records(
    verdict: AuthzVerdict, endpoint_id: str, *, vuln_id: str = "",
    source: str = "session", confirmed: bool = True,
) -> Dict[str, List[Dict[str, Any]]]:
    """All records for a verdict as a records-by-kind map, ready for the graph.

    Includes the per-identity requests always, and the vuln only on a violation.
    ``confirmed`` gates whether the vuln is a verified finding or only suspected
    (see :func:`vuln_record`).
    """
    out: Dict[str, List[Dict[str, Any]]] = {
        M.RequestRecord.KIND: request_records(verdict, endpoint_id, source=source),
    }
    if verdict.violation:
        vid = vuln_id or f"AUTHZ-{endpoint_id}"
        out[M.VulnRecord.KIND] = [
            vuln_record(verdict, endpoint_id, vuln_id=vid, source=source,
                        confirmed=confirmed)
        ]
    return out


__all__ = ["request_records", "vuln_record", "verdict_records"]
