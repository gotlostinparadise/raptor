"""Configuration for `/nuclei`."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Mapping, Optional


@dataclass
class NucleiConfig:
    target: str = ""                       # URL for nuclei to scan
    authorization: str = ""
    recon_graph: str = ""                  # path to a recon.json / web.json for tech→CVE
    tags: List[str] = field(default_factory=list)
    severity: List[str] = field(default_factory=lambda: ["medium", "high", "critical"])


def from_dict(data: Mapping[str, Any]) -> NucleiConfig:
    cfg = NucleiConfig(
        target=(data.get("target") or "").rstrip("/"),
        authorization=data.get("authorization", ""),
        recon_graph=data.get("recon_graph", ""),
        tags=list(data.get("tags") or []),
        severity=list(data.get("severity") or ["medium", "high", "critical"]),
    )
    if not cfg.target and not cfg.recon_graph:
        raise ValueError("nuclei config requires a target or a recon_graph")
    return cfg


def load_config(path: Path) -> NucleiConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["NucleiConfig", "from_dict", "load_config"]
