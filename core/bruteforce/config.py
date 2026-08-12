"""Configuration for `/bruteforce` — brute-force / rate-limit weakness testing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping


@dataclass
class BruteforceConfig:
    base_url: str
    authorization: str = ""
    login_url: str = "/login"          # the auth endpoint to hammer
    method: str = "POST"
    attempts: int = 12                 # failed attempts to fire
    min_attempts: int = 10             # confirm "no lockout" only at/above this
    body: str = ""                     # a FAILING credential payload (wrong password)
    content_type: str = "form"         # form | json
    lockout_signatures: List[str] = field(default_factory=list)  # extra body markers
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)


def from_dict(data: Mapping[str, Any]) -> BruteforceConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("bruteforce config requires a base_url")
    return BruteforceConfig(
        base_url=base_url, authorization=data.get("authorization", ""),
        login_url=data.get("login_url", "/login"), method=data.get("method", "POST"),
        attempts=int(data.get("attempts", 12)), min_attempts=int(data.get("min_attempts", 10)),
        body=data.get("body", ""), content_type=data.get("content_type", "form"),
        lockout_signatures=list(data.get("lockout_signatures") or []),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> BruteforceConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["BruteforceConfig", "from_dict", "load_config"]
