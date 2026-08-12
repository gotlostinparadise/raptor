"""GraphQL introspection — query, send, parse.

Introspection is where GraphQL testing starts: a single query returns the whole
schema (types, query/mutation fields, their arguments). We reuse
:mod:`core.apitest.inventory`'s GraphQL parser to turn an introspection result
into normalised operations, so the schema an API declares statically and the one
recovered live land on the same shape.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# A compact introspection query — enough for operation + argument discovery
# without pulling the full type graph (which many servers cap).
INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } "
    "types { name kind fields { name args { name } } } } }"
)


@dataclass
class Operation:
    kind: str                      # QUERY | MUTATION
    name: str
    args: List[str] = field(default_factory=list)


def post_graphql(client, url: str, query: str, *, variables: Optional[dict] = None,
                 headers: Optional[dict] = None, identity: str = "tester"):
    """POST a GraphQL document; return the raw :class:`core.http.Response`.

    ``client`` may be a :class:`core.http.HttpClient` or a
    :class:`core.session.engine.SessionEngine`-like object exposing ``request``.
    ``identity`` names the session identity to send as when ``client`` is an
    engine (a reused, logged-in engine's identity is not necessarily ``tester``).
    """
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    # Session engine takes an identity first; a plain client does not.
    try:
        return client.request("POST", url, body=body, headers=h, follow_redirects=False)
    except TypeError:
        return client.request(identity, "POST", url, body=body, headers=h)


def schema_from_response(resp) -> Optional[Dict[str, Any]]:
    """Extract ``__schema`` from a GraphQL response, or None."""
    body = getattr(resp, "body", b"") or b""
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None
    schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
    return schema if isinstance(schema, dict) else None


def operations(schema: Dict[str, Any]) -> List[Operation]:
    """Parse a ``__schema`` object into a list of :class:`Operation`.

    Delegates to the same GraphQL parser `/api` Phase 0 uses.
    """
    from core.apitest.inventory import build_inventory
    inv = build_inventory({"__schema": schema})
    out: List[Operation] = []
    for ep in inv.get("endpoints", []):
        out.append(Operation(kind=ep.get("method", "QUERY"),
                             name=ep.get("operation_id", ""),
                             args=list(ep.get("query_params") or [])))
    return out


__all__ = [
    "INTROSPECTION_QUERY", "Operation", "post_graphql", "schema_from_response",
    "operations",
]
