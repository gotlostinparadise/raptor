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
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# The vuln classes the runner knows how to test.
ALL_CLASSES = (
    "ssti", "cmdi", "sqli", "nosqli", "path_traversal", "ssrf_metadata", "xss",
    # blind (require an OAST client):
    "ssrf", "xxe", "cmdi_blind", "sqli_oob", "rfi",
)
BLIND_CLASSES = ("ssrf", "xxe", "cmdi_blind", "sqli_oob", "rfi")


@dataclass
class InjectionPoint:
    method: str
    path: str
    param: str
    location: str = "query"        # query | body
    content_type: str = "form"     # form | json (body only)
    # Sibling params of the same endpoint+location at a baseline value, sent
    # alongside the injected param so the app's vulnerable code path actually
    # runs (many forms gate on a submit button / other required fields).
    others: Dict[str, str] = field(default_factory=dict)

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
    # Shared authenticated session (see core.session.attach). ``cookies`` /
    # ``headers`` authenticate a standalone run; ``session`` is a live
    # SessionEngine the orchestrator threads in (cookie jar + bearer at once) —
    # never serialised, so ``from_dict`` leaves it None.
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)
    # T1 — triage + budget. ``request_budget`` caps how many HTTP requests the
    # run may send (None = unbounded); ``triage`` forces the mechanical pre-score
    # even with no model/budget; ``triage_max_pairs`` is an optional explicit hard
    # cap on selected (point, class) pairs (0 = no cap — the budget bounds it).
    request_budget: Optional[int] = None
    triage: bool = False
    triage_max_pairs: int = 0
    # T2 — read/adapt. ``adapt`` turns each in-band test into a probe→read→refine
    # loop (WAF-evasion retries + response-guided ordering); ``adapt_steps`` caps
    # the sends per (point, class) hypothesis (0 = no cap — the budget bounds it).
    adapt: bool = False
    adapt_steps: int = 0

    def enabled_classes(self, *, have_oast: bool) -> List[str]:
        out = [c for c in self.classes if c in ALL_CLASSES]
        if not have_oast:
            out = [c for c in out if c not in BLIND_CLASSES]
        return out


def _point_from(d: Mapping[str, Any]) -> InjectionPoint:
    return InjectionPoint(
        method=d.get("method", "GET"), path=d["path"], param=d["param"],
        location=d.get("location", "query"), content_type=d.get("content_type", "form"),
        others=dict(d.get("others") or {}),
    )


def from_dict(data: Mapping[str, Any]) -> InjectionConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("injection config requires a base_url")
    points = [_point_from(p) for p in (data.get("points") or [])]
    classes = list(data.get("classes") or ALL_CLASSES)
    budget = data.get("request_budget")
    return InjectionConfig(
        base_url=base_url, points=points, classes=classes,
        authorization=data.get("authorization", ""), token_env=data.get("token_env", ""),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
        request_budget=int(budget) if budget else None,
        triage=bool(data.get("triage", False)),
        triage_max_pairs=int(data.get("triage_max_pairs", 0) or 0),
        adapt=bool(data.get("adapt", False)),
        adapt_steps=int(data.get("adapt_steps", 0) or 0),
    )


def load_config(path: Path) -> InjectionConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def build_target_url(base_url: str, point: "InjectionPoint", value: str) -> str:
    """URL with ``value`` injected at ``point.param``, honouring its location.

    ``query`` splices into the real query string (preserving other params);
    ``fragment`` splices into an SPA hash-route's fragment query
    (``/#/route?param=value``) — where a client-side router, not the server,
    reads it. Not for ``body`` points (those aren't URLs; the runner builds a
    request body instead).
    """
    if point.location == "fragment":
        from core.webgraph.scope import spa_route_of_path
        route = spa_route_of_path(point.path) or point.path
        if not route.startswith("/"):
            route = "/" + route
        return f"{base_url}/#{route}?{urlencode([(point.param, value)])}"
    parts = urlsplit(f"{base_url}{point.path}")
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k != point.param]
    kept.append((point.param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(kept), parts.fragment))


def points_from_webgraph(normalized_dir: Path, *,
                         locations=("query", "body", "fragment")) -> List[InjectionPoint]:
    """Harvest injection points from a `/webgraph` run's normalized records.

    Joins ``parameters.jsonl`` (name + location + endpoint_id) with
    ``endpoints.jsonl`` (method + path) to produce one point per tested param.
    """
    ndir = Path(normalized_dir)
    from core.webgraph.scope import endpoint_id
    endpoints: Dict[str, Dict[str, Any]] = {}
    ep_file = ndir / "endpoints.jsonl"
    if ep_file.exists():
        for line in ep_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                endpoints[endpoint_id(row.get("method", "GET"), row.get("path", ""))] = row

    # Pass 1: every param per endpoint, so each point can carry the sibling form
    # context (e.g. DVWA's Submit button) — many apps gate the vulnerable code on
    # the other fields being present.
    raw_params: List[Dict[str, Any]] = []
    ep_params: Dict[str, List[tuple]] = {}
    param_file = ndir / "parameters.jsonl"
    if param_file.exists():
        for line in param_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            pr = json.loads(line)
            raw_params.append(pr)
            ep_params.setdefault(pr.get("endpoint_id", ""), []).append(
                (pr.get("name"), pr.get("location", "query")))

    points: List[InjectionPoint] = []
    seen = set()
    for pr in raw_params:
        loc = pr.get("location", "query")
        if loc not in locations:
            continue
        eid = pr.get("endpoint_id", "")
        ep = endpoints.get(eid)
        if not ep:
            continue
        name = pr["name"]
        key = (ep["method"], ep["path"], name, loc)
        if key in seen:
            continue
        seen.add(key)
        # Baseline sibling value = the param name (distinct per field). Distinct
        # values matter: a shared constant makes password_new == password_conf on
        # a change-password form, which actually changes the password (destroying
        # the session). A submit button still satisfies isset() with any value.
        others = {n: n for (n, l) in ep_params.get(eid, [])
                  if n and n != name and l == loc}
        points.append(InjectionPoint(method=ep["method"], path=ep["path"],
                                     param=name, location=loc, others=others))
    return points


__all__ = [
    "ALL_CLASSES", "BLIND_CLASSES", "InjectionPoint", "InjectionConfig",
    "from_dict", "load_config", "points_from_webgraph", "build_target_url",
]
