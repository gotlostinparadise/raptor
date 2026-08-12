"""Configuration for `/sessionid` — weak/predictable session-token analysis."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping


@dataclass
class SessionIdConfig:
    base_url: str
    authorization: str = ""
    #: Endpoint that issues a fresh token per hit (a login or a session-start page).
    collect_url: str = "/"
    method: str = "GET"
    count: int = 6                     # how many tokens to sample
    body: str = ""                     # optional request body (e.g. login creds)
    content_type: str = "form"         # form | json (for body)
    #: Where to read the token from the response: a Set-Cookie name, or a dotted
    #: JSON path (e.g. "authentication.token"). One of the two.
    cookie_name: str = ""
    token_path: str = ""
    #: Pre-observed tokens (skips collection — analysis runs offline / dry-run).
    tokens: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)


def from_dict(data: Mapping[str, Any]) -> SessionIdConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("sessionid config requires a base_url")
    return SessionIdConfig(
        base_url=base_url, authorization=data.get("authorization", ""),
        collect_url=data.get("collect_url", "/"), method=data.get("method", "GET"),
        count=int(data.get("count", 6)), body=data.get("body", ""),
        content_type=data.get("content_type", "form"),
        cookie_name=data.get("cookie_name", ""), token_path=data.get("token_path", ""),
        tokens=list(data.get("tokens") or []),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> SessionIdConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["SessionIdConfig", "from_dict", "load_config"]
