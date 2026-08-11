"""GraphQL-specific check helpers (the mechanical parts).

- Introspection-enabled: a production endpoint that returns its full schema is a
  configuration weakness (information disclosure). The evidence is the schema
  itself.
- Alias / batching amplification: one HTTP request carrying N aliases of the same
  (potentially expensive) field multiplies server work — a DoS amplifier. The
  evidence is that the server *resolved* all aliases instead of rejecting the
  document on complexity/alias limits.
"""

from __future__ import annotations

import json
from typing import Optional


def introspection_enabled(schema: Optional[dict]) -> bool:
    """True when a schema was returned (introspection is open)."""
    return bool(schema and (schema.get("types") or schema.get("queryType")))


def alias_query(field: str, n: int = 50) -> str:
    """Build a single query aliasing ``field`` ``n`` times (batching amplifier)."""
    aliases = " ".join(f"a{i}: {field}" for i in range(n))
    return "query { " + aliases + " }"


def batching_accepted(resp, n: int) -> bool:
    """True when the server resolved the aliased query (no complexity limit).

    Confirmed when the response is 2xx, carries a ``data`` object, has no
    top-level ``errors``, and returns at least a majority of the requested
    aliases — i.e. the amplification was honoured rather than rejected.
    """
    if not (200 <= (getattr(resp, "status", 0) or 0) < 300):
        return False
    body = getattr(resp, "body", b"") or b""
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return False
    if not isinstance(data, dict) or data.get("errors"):
        return False
    d = data.get("data")
    if not isinstance(d, dict):
        return False
    return len(d) >= max(2, n // 2)


def looks_like_graphql(resp) -> bool:
    """Heuristic: does this response look like a GraphQL endpoint's reply?"""
    body = getattr(resp, "body", b"") or b""
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return False
    return isinstance(data, dict) and ("data" in data or "errors" in data)


__all__ = [
    "introspection_enabled", "alias_query", "batching_accepted", "looks_like_graphql",
]
