"""Configuration for `/race` (business-logic / race-condition testing)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping


@dataclass
class RaceTest:
    id: str
    method: str
    path: str
    body: str = ""
    content_type: str = "form"        # form | json
    headers: Dict[str, str] = field(default_factory=dict)
    concurrency: int = 20             # how many simultaneous requests
    expected_max: int = 1            # how many should succeed (limit)
    success_status: int = 200
    success_signature: str = ""      # optional body marker for success
    vuln_class: str = "race_condition"
    owasp: str = "API6"

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class RaceConfig:
    base_url: str
    tests: List[RaceTest] = field(default_factory=list)
    authorization: str = ""
    token_env: str = ""
    max_concurrency: int = 50        # hard cap to avoid accidental load
    # Shared authenticated session (see core.session.attach). A static snapshot
    # (auth headers + Cookie) is attached to each concurrent request — race
    # deliberately avoids per-identity session state (shared-jar racing).
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)


def _test_from(d: Mapping[str, Any]) -> RaceTest:
    if not (d.get("id") and d.get("method") and d.get("path")):
        raise ValueError(f"race test missing id/method/path: {d!r}")
    return RaceTest(
        id=d["id"], method=d["method"], path=d["path"], body=d.get("body", ""),
        content_type=d.get("content_type", "form"), headers=dict(d.get("headers") or {}),
        concurrency=int(d.get("concurrency", 20)),
        expected_max=int(d.get("expected_max", 1)),
        success_status=int(d.get("success_status", 200)),
        success_signature=d.get("success_signature", ""),
        vuln_class=d.get("class") or d.get("vuln_class") or "race_condition",
        owasp=d.get("owasp", "API6"),
    )


def from_dict(data: Mapping[str, Any]) -> RaceConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("race config requires a base_url")
    return RaceConfig(
        base_url=base_url, tests=[_test_from(t) for t in (data.get("tests") or [])],
        authorization=data.get("authorization", ""), token_env=data.get("token_env", ""),
        max_concurrency=int(data.get("max_concurrency", 50)),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> RaceConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["RaceTest", "RaceConfig", "from_dict", "load_config"]
