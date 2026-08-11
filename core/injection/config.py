"""Configuration + target discovery for `/inject`.

An injection point is a single ``(method, path, param, location)`` to test. The
operator can hand-write them, or the runner can harvest them from a prior
`/webgraph` run's ``normalized/{endpoints,parameters}.jsonl`` so injection
targets exactly the surface the graph already mapped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

# The vuln classes the runner knows how to test.
ALL_CLASSES = (
    "ssti", "cmdi", "sqli", "nosqli", "path_traversal", "ssrf_metadata", "xss",
    # blind (require an OAST client):
    "ssrf", "xxe", "cmdi_blind", "sqli_oob",
)
BLIND_CLASSES = ("ssrf", "xxe", "cmdi_blind", "sqli_oob")


@dataclass
class InjectionPoint:
    method: str
    path: str
    param: str
    location: str = "query"        # query | body
    content_type: str = "form"     # form | json (body only)

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path} [{self.location}:{self.param}]"


@dataclass
class InjectionConfig:
    base_url: str
    points: List[InjectionPoint] = field(default_factory=list)
    classes: List[str] = field(default_factory=lambda: list(ALL_CLASSES))
    authorization: str = ""
    token_env: str = ""            # optional bearer token for authenticated injection

    def enabled_classes(self, *, have_oast: bool) -> List[str]:
        out = [c for c in self.classes if c in ALL_CLASSES]
        if not have_oast:
            out = [c for c in out if c not in BLIND_CLASSES]
        return out


def _point_from(d: Mapping[str, Any]) -> InjectionPoint:
    return InjectionPoint(
        method=d.get("method", "GET"), path=d["path"], param=d["param"],
        location=d.get("location", "query"), content_type=d.get("content_type", "form"),
    )


def from_dict(data: Mapping[str, Any]) -> InjectionConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("injection config requires a base_url")
    points = [_point_from(p) for p in (data.get("points") or [])]
    classes = list(data.get("classes") or ALL_CLASSES)
    return InjectionConfig(
        base_url=base_url, points=points, classes=classes,
        authorization=data.get("authorization", ""), token_env=data.get("token_env", ""),
    )


def load_config(path: Path) -> InjectionConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def points_from_webgraph(normalized_dir: Path, *, locations=("query", "body")) -> List[InjectionPoint]:
    """Harvest injection points from a `/webgraph` run's normalized records.

    Joins ``parameters.jsonl`` (name + location + endpoint_id) with
    ``endpoints.jsonl`` (method + path) to produce one point per tested param.
    """
    ndir = Path(normalized_dir)
    endpoints: Dict[str, Dict[str, Any]] = {}
    ep_file = ndir / "endpoints.jsonl"
    if ep_file.exists():
        for line in ep_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                from core.webgraph.scope import endpoint_id
                endpoints[endpoint_id(row.get("method", "GET"), row.get("path", ""))] = row

    points: List[InjectionPoint] = []
    param_file = ndir / "parameters.jsonl"
    if param_file.exists():
        seen = set()
        for line in param_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            pr = json.loads(line)
            loc = pr.get("location", "query")
            if loc not in locations:
                continue
            ep = endpoints.get(pr.get("endpoint_id", ""))
            if not ep:
                continue
            key = (ep["method"], ep["path"], pr["name"], loc)
            if key in seen:
                continue
            seen.add(key)
            points.append(InjectionPoint(method=ep["method"], path=ep["path"],
                                         param=pr["name"], location=loc))
    return points


__all__ = [
    "ALL_CLASSES", "BLIND_CLASSES", "InjectionPoint", "InjectionConfig",
    "from_dict", "load_config", "points_from_webgraph",
]
