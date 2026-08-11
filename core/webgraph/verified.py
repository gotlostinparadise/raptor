"""Bridge: confirmed web-graph findings → the verified-outcomes surface (A5).

A web/API finding is only worth surfacing as *verified* when a tool produced a
proof — the authorization diff (:mod:`core.session`), the OAST callback
(:mod:`core.oast`), or a reflected marker. Those land on a
:class:`~core.webgraph.model.VulnRecord` as ``status="confirmed"`` +
``proof_kind``. This module projects such a record onto the framework's existing
proof substrate — a :class:`~core.labeled_attempts.types.LabeledAttempt` carrying
:class:`~core.labeled_attempts.types.WebEvidence` — and persists it to the run's
pool, so ``libexec/raptor-verified-outcomes`` surfaces web proofs alongside
fuzzer/sandbox/codeql ones with no new aggregation path.

The ``Oracle.WEB`` outcome + the ``web_evidence`` adapter already exist in
:mod:`core.labeled_attempts.view`; this is the missing producer half. It is a
one-way dependency (webgraph → labeled_attempts) kept in its own module so the
core graph never imports the outcomes stack.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from core.labeled_attempts.store import write as _store_write
from core.labeled_attempts.types import LabeledAttempt, WebEvidence
from core.webgraph import model as M

# vuln_class → CWE. Covers the classes A2/A3 (and Phase B) produce; unknown
# classes fall back to a non-empty sentinel (the schema requires a CWE).
_CWE_BY_CLASS: Dict[str, str] = {
    "bola": "CWE-639", "idor": "CWE-639", "bfla": "CWE-285",
    "mass_assignment": "CWE-915", "property_level": "CWE-915",
    "ssrf": "CWE-918", "blind_ssrf": "CWE-918",
    "rce": "CWE-78", "blind_rce": "CWE-78", "cmdi": "CWE-78", "cmdi_blind": "CWE-78",
    "xxe": "CWE-611", "sqli": "CWE-89", "blind_sqli": "CWE-89", "sqli_oob": "CWE-89",
    "path_traversal": "CWE-22",
    "nosqli": "CWE-943", "ssti": "CWE-1336", "xss": "CWE-79",
    "deserialization": "CWE-502", "open_redirect": "CWE-601",
    # client-side / config classes
    "cors_origin_reflection": "CWE-942", "cors_wildcard_with_credentials": "CWE-942",
    "cors_null_origin": "CWE-942", "csp_missing": "CWE-693",
    "csp_unsafe_inline": "CWE-693", "csp_unsafe_eval": "CWE-693",
    "csp_wildcard_script_source": "CWE-693", "csp_no_object_src": "CWE-693",
    "clickjacking": "CWE-1021", "cookie_flags": "CWE-614",
    # graphql
    "graphql_introspection": "CWE-200", "graphql_batching_dos": "CWE-770",
    # content discovery
    "exposed_secret": "CWE-798", "exposed_file": "CWE-538",
    "source_map_exposed": "CWE-540",
    # business logic / race
    "race_condition": "CWE-362", "business_logic": "CWE-840",
    "limit_bypass": "CWE-770",
}
_DEFAULT_CWE = "CWE-0"

# proof_kind → a human evidence_type tag stored on the WebEvidence.
_EVIDENCE_TYPE: Dict[str, str] = {
    M.PROOF_AUTHZ_DIFF: "authz_diff",
    M.PROOF_OAST_CALLBACK: "oast_callback",
    M.PROOF_REFLECTED_MARKER: "reflected_marker",
    M.PROOF_STATE_ORACLE: "state_oracle",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _signature(vuln_class: str, endpoint_id: str, param: str) -> str:
    raw = f"{vuln_class}|{endpoint_id}|{param}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def labeled_attempt_from_vuln(
    row: Mapping[str, Any], *, target_url: str = "", producing_model: str = "",
) -> LabeledAttempt:
    """Project a confirmed :class:`VulnRecord` row onto a :class:`LabeledAttempt`.

    Raises ``ValueError`` unless the row is ``confirmed`` and carries a
    ``proof_kind`` — an unproven finding must never become a verified outcome.
    """
    if row.get("status") != M.STATUS_CONFIRMED:
        raise ValueError("only confirmed findings become verified outcomes")
    proof = row.get("proof_kind") or ""
    if not proof:
        raise ValueError("confirmed finding lacks a proof_kind")

    vc = row.get("vuln_class") or "web"
    eid = row.get("endpoint_id") or ""
    param = row.get("param") or ""
    web_evidence = WebEvidence(
        target_url=target_url or eid,
        http_request={"endpoint_id": eid, "identity": row.get("identity") or "",
                      "param": param},
        response_evidence=dict(row.get("evidence") or {}),
        evidence_type=_EVIDENCE_TYPE.get(proof, proof),
        timestamp_iso=_now_iso(),
    )
    return LabeledAttempt(
        finding_id=str(row.get("id") or _signature(vc, eid, param)),
        finding_signature=_signature(vc, eid, param),
        cwe=_CWE_BY_CLASS.get(vc, _DEFAULT_CWE),
        outcome="success",
        web_evidence=web_evidence,
        reproducible=False,  # live-target, point-in-time
        producing_model=producing_model,
        tools_used=(row.get("source") or "webgraph",),
        timestamp=_now_iso(),
    )


def record_confirmed(
    vuln_rows,
    *,
    project_dir,
    target_urls: Optional[Mapping[str, str]] = None,
    producing_model: str = "",
    also_global: bool = False,
) -> List[Path]:
    """Persist every confirmed, proven finding as a verified web outcome.

    ``vuln_rows`` is an iterable of :class:`VulnRecord` rows (dicts). Non-confirmed
    rows are skipped. Returns the paths written. After this, the run's
    ``libexec/raptor-verified-outcomes`` surfaces them as ``Oracle.WEB`` VERIFIED.
    """
    target_urls = target_urls or {}
    paths: List[Path] = []
    for row in vuln_rows:
        if row.get("status") != M.STATUS_CONFIRMED:
            continue
        la = labeled_attempt_from_vuln(
            row, target_url=target_urls.get(row.get("endpoint_id") or "", ""),
            producing_model=producing_model,
        )
        paths += _store_write(la, project_dir=Path(project_dir),
                              also_global=also_global)
    return paths


__all__ = ["labeled_attempt_from_vuln", "record_confirmed"]
