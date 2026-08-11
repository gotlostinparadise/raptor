"""Seed a `/webauthz` config from a mechanical API inventory / authz matrix.

`/api` Phase 0 already produces ``api-inventory.json`` (endpoints tagged
``object_scoped`` / ``privileged``) and a seed ``authz-matrix.json``. This turns
that mechanical ground truth into a ready-to-fill ``authz-config.json`` — one
BOLA test per object-scoped endpoint, one BFLA test per privileged one — so the
operator only fills in real object ids, credential env-var names, and the
authorization attestation, rather than hand-writing the whole file.
"""

from __future__ import annotations

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


__all__ = ["template_from_inventory"]
