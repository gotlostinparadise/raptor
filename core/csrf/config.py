"""Configuration for `/csrf` — anti-CSRF-token-absence testing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping


@dataclass
class CsrfConfig:
    base_url: str
    authorization: str = ""
    path: str = "/"                    # the state-changing endpoint
    method: str = "POST"
    body: str = ""                     # a WORKING request body incl. the token field
    content_type: str = "form"         # form | json
    token_field: str = "user_token"    # the anti-CSRF token field to remove
    success_status: int = 200          # what a successful state change returns
    success_signature: str = ""        # marker in a successful response (recommended)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)


def from_dict(data: Mapping[str, Any]) -> CsrfConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("csrf config requires a base_url")
    return CsrfConfig(
        base_url=base_url, authorization=data.get("authorization", ""),
        path=data.get("path", "/"), method=data.get("method", "POST"),
        body=data.get("body", ""), content_type=data.get("content_type", "form"),
        token_field=data.get("token_field", "user_token"),
        success_status=int(data.get("success_status", 200)),
        success_signature=data.get("success_signature", ""),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> CsrfConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["CsrfConfig", "from_dict", "load_config"]
