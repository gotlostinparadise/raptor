"""Seed a `/webauthz` config from a mechanical API inventory / authz matrix.

`/api` Phase 0 already produces ``api-inventory.json`` (endpoints tagged
``object_scoped`` / ``privileged``) and a seed ``authz-matrix.json``. This turns
that mechanical ground truth into a ready-to-fill ``authz-config.json`` — one
BOLA test per object-scoped endpoint, one BFLA test per privileged one — so the
operator only fills in real object ids, credential env-var names, and the
authorization attestation, rather than hand-writing the whole file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping

_DEFAULT_IDENTITIES = [
    {"name": "user_a", "role": "user", "login": {"type": "bearer", "token_env": "USER_A_TOKEN"}},
    {"name": "user_b", "role": "user", "login": {"type": "bearer", "token_env": "USER_B_TOKEN"}},
    {"name": "admin", "role": "admin", "login": {"type": "bearer", "token_env": "ADMIN_TOKEN"}},
]


def _tests_from_endpoints(endpoints: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    tests: List[Dict[str, Any]] = []
    idx = 1
    for ep in endpoints:
        method, path = ep.get("method", "GET"), ep.get("path", "")
        if not path:
            continue
        if ep.get("object_scoped"):
            tests.append({
                "id": f"AZ-{idx:04d}", "method": method, "path": path,
                "owner": "user_a", "class": "bola", "owasp": "API1",
                "others": ["user_b", "anonymous"], "control_path": path,
                "_note": "set `path` to user_a's REAL object id, and `control_path` "
                         "to a DIFFERENT object user_a does NOT own (proves the "
                         "endpoint is object-specific; without it the finding is "
                         "only suspected, not confirmed)",
            })
            idx += 1
        elif ep.get("privileged"):
            tests.append({
                "id": f"AZ-{idx:04d}", "method": method, "path": path,
                "owner": "admin", "class": "bfla", "owasp": "API5",
                "privileged": True, "others": ["user_a", "anonymous"],
                "_note": "low-privilege identities must be DENIED this endpoint",
            })
            idx += 1
    return tests


def template_from_inventory(doc: Mapping[str, Any], *, base_url: str = "") -> Dict[str, Any]:
    """Build a template config dict from an ``api-inventory.json`` (or matrix).

    Accepts either an inventory (``{"endpoints": [...]}``) or an authz matrix
    (``{"tests": [{endpoint_id, method, path, test_type, ...}]}``).
    """
    if "endpoints" in doc:
        endpoints = list(doc.get("endpoints") or [])
    elif "tests" in doc:
        # Map matrix rows to endpoint-shaped dicts.
        endpoints = [
            {"method": r.get("method", "GET"), "path": r.get("path", ""),
             "object_scoped": r.get("test_type") in ("BOLA", "property-level"),
             "privileged": r.get("test_type") == "BFLA"}
            for r in (doc.get("tests") or [])
        ]
    else:
        endpoints = []
    return {
        "base_url": base_url or doc.get("base_url", ""),
        "authorization": "",   # REQUIRED before --active (mechanical gate)
        "csrf_cookie": None,
        "csrf_header": None,
        "identities": [dict(i) for i in _DEFAULT_IDENTITIES],
        "tests": _tests_from_endpoints(endpoints),
    }


def _looks_object_scoped(path: str) -> bool:
    """Heuristic object-scoping for surfaces that didn't tag it (a plain HTTP
    crawl doesn't): an endpoint is object-scoped when its path/query carries an
    object id — a numeric segment (``/users/1``), a UUID, a templated ``{id}``,
    or an ``*id*`` query param (``?id=``, ``?user_id=``)."""
    p = path or ""
    if re.search(r"/\d+(?:/|$)", p):
        return True
    if re.search(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-", p):
        return True
    if re.search(r"\{[^}]+\}", p):
        return True
    if re.search(r"[?&][^=&]*id[^=&]*=", p, re.IGNORECASE):
        return True
    return False


def endpoints_from_graph(normalized_dir: Any) -> List[Dict[str, Any]]:
    """Read endpoint rows from a webgraph run's ``normalized/endpoints.jsonl``,
    inferring ``object_scoped`` via :func:`_looks_object_scoped` when the mapping
    source left it unset. Returns ``[]`` when the file is absent."""
    ep_file = Path(normalized_dir) / "endpoints.jsonl"
    out: List[Dict[str, Any]] = []
    if not ep_file.exists():
        return out
    for line in ep_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        path = row.get("path", "")
        out.append({
            "method": row.get("method", "GET"), "path": path,
            "object_scoped": bool(row.get("object_scoped")) or _looks_object_scoped(path),
            "privileged": bool(row.get("privileged")), "url": row.get("url", ""),
        })
    return out


def tests_from_graph(
    endpoints: List[Mapping[str, Any]], identities: List[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Derive BOLA/BFLA authz tests from mapped endpoints using the operator's
    *actual* identities (unlike :func:`template_from_inventory`, which stamps the
    fixed ``_DEFAULT_IDENTITIES``). Owner is a non-admin identity for BOLA and an
    admin-role identity for BFLA; ``others`` is every other identity + anonymous.

    NB: a confirmed break needs concrete, per-identity-distinct object ids —
    without them ``authz_diff`` may only reach ``suspected``. Concrete-id
    enumeration is the deeper follow-up (roadmap S1)."""
    names = [i.get("name") for i in identities if i.get("name")]
    if not names:
        return []
    admin = next((i["name"] for i in identities
                  if (i.get("role") or "").lower() in ("admin", "administrator")), None)
    non_admin = [n for n in names if n != admin]
    owner = non_admin[0] if non_admin else names[0]
    priv_owner = admin or names[0]
    tests: List[Dict[str, Any]] = []
    idx = 1
    for ep in endpoints:
        method, path = ep.get("method", "GET"), ep.get("path", "")
        if not path:
            continue
        if ep.get("object_scoped"):
            tests.append({
                "id": f"AZ-{idx:04d}", "method": method, "path": path,
                "owner": owner, "class": "bola", "owasp": "API1",
                "others": [n for n in names if n != owner] + ["anonymous"],
                "control_path": path,
            })
            idx += 1
        elif ep.get("privileged"):
            tests.append({
                "id": f"AZ-{idx:04d}", "method": method, "path": path,
                "owner": priv_owner, "class": "bfla", "owasp": "API5",
                "privileged": True,
                "others": [n for n in names if n != priv_owner] + ["anonymous"],
            })
            idx += 1
    return tests


__all__ = [
    "template_from_inventory", "endpoints_from_graph", "tests_from_graph",
    "_looks_object_scoped",
]
