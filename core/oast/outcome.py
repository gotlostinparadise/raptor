"""Adapter: a correlated OAST interaction → web-graph proof record.

The out-of-band callback *is* the verdict for a blind vulnerability — no LLM
judgement, no heuristic. This turns one or more correlated
:class:`~core.oast.interaction.Interaction` s into a confirmed
:class:`~core.webgraph.model.VulnRecord` carrying
:data:`~core.webgraph.model.PROOF_OAST_CALLBACK`, mirroring
:mod:`core.session.authz` for the authorization oracle. The same evidence feeds
the verified-outcomes surface (A5).
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.oast.interaction import Interaction
from core.webgraph import model as M


def vuln_record(
    interactions: List[Interaction],
    *,
    vuln_id: str,
    vuln_class: str,
    endpoint_id: str,
    owasp: str = "",
    severity: str = "high",
    param: str = "",
    source: str = "oast",
) -> Dict[str, Any]:
    """Build a confirmed VulnRecord from at least one correlated interaction.

    Raises ``ValueError`` on an empty interaction list — no callback, no proof.
    """
    if not interactions:
        raise ValueError("no interactions; a blind finding needs a callback to confirm")
    return M.VulnRecord(
        id=vuln_id, vuln_class=vuln_class, endpoint_id=endpoint_id,
        param=param, severity=severity, owasp=owasp,
        status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_OAST_CALLBACK,
        evidence={
            "callback_count": len(interactions),
            "protocols": sorted({i.protocol for i in interactions if i.protocol}),
            "interactions": [
                {"protocol": i.protocol, "host": i.host,
                 "remote_addr": i.remote_addr, "timestamp": i.timestamp}
                for i in interactions
            ],
        },
        source=source,
    ).to_row()


__all__ = ["vuln_record"]
