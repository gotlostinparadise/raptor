"""Remove an anti-CSRF token field from a request body (form or JSON)."""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode


def strip_token(body: str, token_field: str, content_type: str = "form") -> str:
    """Return ``body`` with ``token_field`` removed (form-urlencoded or JSON)."""
    if not body:
        return body
    if content_type == "json":
        try:
            data = json.loads(body)
        except ValueError:
            return body
        if isinstance(data, dict):
            data.pop(token_field, None)
        return json.dumps(data, separators=(",", ":"))
    pairs = [(k, v) for k, v in parse_qsl(body, keep_blank_values=True)
             if k != token_field]
    return urlencode(pairs)


__all__ = ["strip_token"]
