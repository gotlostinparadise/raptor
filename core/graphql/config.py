"""Configuration for `/graphql` testing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping


@dataclass
class GraphQLConfig:
    base_url: str
    path: str = "/graphql"
    authorization: str = ""
    resource_tests: bool = False     # gate alias/batching DoS (resource-class)
    token_env: str = ""
    dos_field: str = ""              # field to alias; default: first query field
    dos_aliases: int = 100
    # Shared authenticated session (see core.session.attach).
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.path}"


def from_dict(data: Mapping[str, Any]) -> GraphQLConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("graphql config requires a base_url")
    return GraphQLConfig(
        base_url=base_url, path=data.get("path", "/graphql"),
        authorization=data.get("authorization", ""),
        resource_tests=bool(data.get("resource_tests", False)),
        token_env=data.get("token_env", ""), dos_field=data.get("dos_field", ""),
        dos_aliases=int(data.get("dos_aliases", 100)),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> GraphQLConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["GraphQLConfig", "from_dict", "load_config"]
