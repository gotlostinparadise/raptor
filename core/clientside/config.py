"""Configuration for `/clientside` (CORS/CSP/clickjacking/cookies/open-redirect)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Mapping

_DEFAULT_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "next", "return", "returnUrl",
    "dest", "destination", "continue", "r", "u",
]


@dataclass
class ClientSideConfig:
    base_url: str
    authorization: str = ""
    paths: List[str] = field(default_factory=lambda: ["/"])
    redirect_params: List[str] = field(default_factory=lambda: list(_DEFAULT_REDIRECT_PARAMS))
    token_env: str = ""


def from_dict(data: Mapping[str, Any]) -> ClientSideConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("clientside config requires a base_url")
    return ClientSideConfig(
        base_url=base_url, authorization=data.get("authorization", ""),
        paths=list(data.get("paths") or ["/"]),
        redirect_params=list(data.get("redirect_params") or _DEFAULT_REDIRECT_PARAMS),
        token_env=data.get("token_env", ""),
    )


def load_config(path: Path) -> ClientSideConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["ClientSideConfig", "from_dict", "load_config"]
