"""Configuration for `/jwt` — JWT forgery testing against one protected endpoint."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping


@dataclass
class JwtConfig:
    base_url: str
    authorization: str = ""
    #: The endpoint that requires a valid token (where forgeries are tested).
    protected_path: str = "/"
    method: str = "GET"
    #: A known-valid token to analyse + forge from (or read one from ``token_env``).
    token: str = ""
    token_env: str = ""
    #: How the token rides on the request. ``Authorization: Bearer <t>`` by default.
    header_name: str = "Authorization"
    scheme: str = "Bearer"
    #: Claim escalations applied to every forgery (e.g. {"role": "admin"}).
    tamper: Dict[str, Any] = field(default_factory=dict)
    #: Extra weak-secret candidates, merged ahead of the built-in list.
    secrets: List[str] = field(default_factory=list)
    # Shared authenticated session (see core.session.attach) — cookies/headers
    # ride alongside the tested token (e.g. an app that also sets a session cookie).
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.protected_path}"


def from_dict(data: Mapping[str, Any]) -> JwtConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("jwt config requires a base_url")
    return JwtConfig(
        base_url=base_url, authorization=data.get("authorization", ""),
        protected_path=data.get("protected_path", "/"),
        method=data.get("method", "GET"),
        token=data.get("token", ""), token_env=data.get("token_env", ""),
        header_name=data.get("header_name", "Authorization"),
        scheme=data.get("scheme", "Bearer"),
        tamper=dict(data.get("tamper") or {}),
        secrets=list(data.get("secrets") or []),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> JwtConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["JwtConfig", "from_dict", "load_config"]
