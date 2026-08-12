"""Configuration for `/discover`."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping


@dataclass
class DiscoveryConfig:
    base_url: str
    authorization: str = ""
    probe_exposed: bool = True
    # Shared authenticated session (see core.session.attach).
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)


def from_dict(data: Mapping[str, Any]) -> DiscoveryConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("discovery config requires a base_url")
    return DiscoveryConfig(
        base_url=base_url, authorization=data.get("authorization", ""),
        probe_exposed=bool(data.get("probe_exposed", True)),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> DiscoveryConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["DiscoveryConfig", "from_dict", "load_config"]
