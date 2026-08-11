"""Triage & ranking — the read-only LLM advisory layer over a recon graph.

Turns the flat set of hosts a recon run discovered into a *ranked worklist*: a
deterministic interest score from mechanical features (interesting name tokens,
a live HTTP service, an exposed-origin flag, non-standard ports, an interesting
tech banner), optionally reordered + annotated by an LLM. See
``docs/recon-intelligence.md`` for the design.

The safety property (same as :mod:`core.payloads.proposer`): the LLM only ever
*reorders and annotates a set the engine already discovered* — ids it invents
are dropped, ids it omits are appended in heuristic order, and it can never mark
anything "vulnerable" or add a host. The mechanical score is the floor and is
always shown. No model / any failure ⇒ pure heuristic ranking (fully offline,
deterministic). This pass reads the graph only; it never touches the target.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from core.recon.llm import ask_structured

# Interesting name tokens → weight. Deliberately conservative; a prototype set an
# operator can tune. Matched against delimiter-split host labels (exact part).
_CRITICAL = 3.0
_DEV = 2.0
_API = 2.0
_LEGACY = 1.0
TOKEN_WEIGHTS: Dict[str, float] = {
    # admin / infra / secrets-bearing
    **{t: _CRITICAL for t in (
        "admin", "adminer", "phpmyadmin", "manage", "dashboard", "console",
        "internal", "intranet", "corp", "vpn", "citrix", "jenkins", "gitlab",
        "gitea", "git", "grafana", "kibana", "prometheus", "vault", "consul",
        "jira", "confluence", "sonar", "nexus", "artifactory", "harbor",
        "portainer", "rancher", "k8s", "kubernetes", "webmail", "owa",
        "exchange", "backup", "db", "database", "mysql", "postgres", "mongo",
        "redis", "elastic", "teamcity", "bamboo", "staging-admin",
    )},
    # non-prod tiers
    **{t: _DEV for t in (
        "dev", "develop", "staging", "stage", "stg", "uat", "qa", "test",
        "testing", "beta", "sandbox", "demo", "preprod", "canary",
    )},
    # api surface
    **{t: _API for t in (
        "api", "graphql", "rest", "gateway", "gw", "svc", "service", "rpc",
        "grpc", "ws",
    )},
    # legacy / leftovers
    **{t: _LEGACY for t in (
        "old", "legacy", "deprecated", "bak", "tmp", "temp", "archive",
    )},
}

# Interesting server/tech banners (substring match, lower-cased).
INTERESTING_TECH = (
    "jenkins", "gitlab", "jira", "confluence", "tomcat", "jboss", "weblogic",
    "websphere", "coldfusion", "struts", "drupal", "joomla", "wordpress",
    "phpmyadmin", "grafana", "kibana", "elasticsearch", "kubernetes", "docker",
    "spring", "flask", "django", "express", "iis", "weblogic",
)

_SPLIT = re.compile(r"[.\-_]")

_SYSTEM = (
    "You prioritise reconnaissance targets for an AUTHORIZED security test. You "
    "ONLY reorder and annotate a given list of already-discovered hosts by how "
    "attack-worthy each looks. You never assert anything is vulnerable, never "
    "invent hosts, and use only ids from the provided list."
)

_SCHEMA = {
    "type": "object",
    "properties": {
        "ranked": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["id"],
            },
        },
        "narrative": {"type": "string"},
    },
    "required": ["ranked"],
}


@dataclass
class Candidate:
    """One host in the worklist, with its mechanical features + scoring."""

    id: str
    kind: str            # "root" | "subdomain"
    name: str
    resolves: bool = False
    has_http: bool = False
    behind_edge: bool = False
    exposed_origin: bool = False
    servers: List[str] = field(default_factory=list)
    tech: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    rationale: str = ""
    rank: int = 0

    def to_row(self) -> Dict[str, Any]:
        return {
            "rank": self.rank, "id": self.id, "kind": self.kind,
            "name": self.name, "score": round(self.score, 1),
            "resolves": self.resolves, "has_http": self.has_http,
            "behind_edge": self.behind_edge, "exposed_origin": self.exposed_origin,
            "servers": self.servers, "tech": self.tech, "ports": self.ports,
            "reasons": self.reasons, "rationale": self.rationale,
        }


def extract_candidates(graph: Dict[str, Any]) -> List[Candidate]:
    """One :class:`Candidate` per host node, joined with its services/edges.

    Pure function of the recon ``graph.to_json()`` structure.
    """
    nodes = graph.get("nodes", []) or []
    edges = graph.get("edges", []) or []
    by_id = {n["id"]: n for n in nodes}

    exposed = {e["target"] for e in edges if e.get("rel") == "exposed_origin"}
    serves: Dict[str, List[str]] = defaultdict(list)
    resolves_to: Dict[str, List[str]] = defaultdict(list)
    behind_services = {e["source"] for e in edges if e.get("rel") == "behind"}
    for e in edges:
        rel = e.get("rel")
        if rel == "serves":
            serves[e["source"]].append(e["target"])
        elif rel == "resolves_to":
            resolves_to[e["source"]].append(e["target"])
    ip_has_edge = {n["id"] for n in nodes
                   if n.get("type") == "ip" and n.get("edge_kind")}

    out: List[Candidate] = []
    for n in nodes:
        if n.get("type") not in ("root", "subdomain"):
            continue
        hid = n["id"]
        name = n.get("label") or hid.split(":", 1)[-1]
        servers: List[str] = []
        tech: List[str] = []
        ports: List[int] = []
        has_http = False
        behind = False
        for sid in serves.get(hid, []):
            s = by_id.get(sid, {})
            has_http = True
            if s.get("server"):
                servers.append(str(s["server"]))
            for t in (s.get("tech") or []):
                tech.append(str(t))
            if s.get("port"):
                try:
                    ports.append(int(s["port"]))
                except (TypeError, ValueError):
                    pass
            if sid in behind_services:
                behind = True
        for ip in resolves_to.get(hid, []):
            if ip in ip_has_edge:
                behind = True
        cand = Candidate(
            id=hid, kind=n["type"], name=name,
            resolves=bool(n.get("resolves")), has_http=has_http,
            behind_edge=behind, exposed_origin=hid in exposed,
            servers=list(dict.fromkeys(servers)),
            tech=list(dict.fromkeys(tech)), ports=sorted(set(ports)),
        )
        cand.score, cand.reasons = heuristic_score(cand)
        out.append(cand)
    return out


def heuristic_score(cand: Candidate) -> Tuple[float, List[str]]:
    """Deterministic interest score + human-readable reasons for a candidate."""
    score = 0.0
    reasons: List[str] = []
    parts = {p for p in _SPLIT.split(cand.name.lower()) if p}
    for token, weight in TOKEN_WEIGHTS.items():
        if token in parts:
            score += weight
            reasons.append(f"name:{token} (+{weight:g})")
    if cand.exposed_origin:
        score += 3.0
        reasons.append("exposed-origin (+3)")
    if cand.has_http:
        score += 1.0
        reasons.append("live-http (+1)")
    nonstd = [p for p in cand.ports if p not in (80, 443)]
    if nonstd:
        bump = float(min(2, len(nonstd)))
        score += bump
        reasons.append(f"non-std-ports:{nonstd} (+{bump:g})")
    banner = " ".join(cand.servers + cand.tech).lower()
    for tok in INTERESTING_TECH:
        if tok in banner:
            score += 2.0
            reasons.append(f"tech:{tok} (+2)")
            break
    if cand.behind_edge:
        score -= 0.5
        reasons.append("behind-edge (-0.5)")
    return score, reasons


def _build_prompt(candidates: List[Candidate]) -> str:
    lines = [
        "Rank these already-discovered recon targets by how attack-worthy each "
        "looks, best first. Return `ranked` as objects {id, rationale} using ONLY "
        "the ids below, plus a short `narrative` of the overall attack surface.",
        "",
        "Targets (id | name | heuristic-score | signals):",
    ]
    for c in candidates:
        lines.append(f"- {c.id} | {c.name} | {c.score:g} | {', '.join(c.reasons) or 'none'}")
    return "\n".join(lines)


def llm_rerank(
    candidates: List[Candidate], model: str,
    ask: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Tuple[List[str], Dict[str, str], str]:
    """Ask the model for an ordering + rationales + narrative.

    Returns ``(ordered_ids, rationales, narrative)``. On any failure returns
    ``([], {}, "")`` so the caller keeps the heuristic order.
    """
    result = ask_structured(_build_prompt(candidates), _SCHEMA, _SYSTEM, model, ask=ask)
    ranked = result.get("ranked") or []
    ordered_ids: List[str] = []
    rationales: Dict[str, str] = {}
    for r in ranked:
        rid = r.get("id") if isinstance(r, dict) else None
        if rid:
            ordered_ids.append(rid)
            rationales[rid] = (r.get("rationale") or "") if isinstance(r, dict) else ""
    return ordered_ids, rationales, str(result.get("narrative") or "")


def _merge_order(candidates: List[Candidate], ordered_ids: List[str]) -> List[Candidate]:
    """LLM order for known ids first; omitted ids appended in heuristic order."""
    by_id = {c.id: c for c in candidates}
    seen = set()
    out: List[Candidate] = []
    for cid in ordered_ids:
        c = by_id.get(cid)
        if c is not None and cid not in seen:
            out.append(c)
            seen.add(cid)
    for c in candidates:   # candidates arrive heuristic-sorted
        if c.id not in seen:
            out.append(c)
            seen.add(c.id)
    return out


def run_triage(
    out_dir: Union[str, Path],
    *,
    model: Optional[str] = None,
    top: Optional[int] = None,
    llm_top: int = 50,
    ask: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Rank a recon run's hosts; write ``triage.json`` + ``triage.md``.

    ``top`` caps how many targets are written out; ``llm_top`` caps how many are
    sent to the model (cost bound). Returns a summary dict.
    """
    out = Path(out_dir)
    graph_path = out / "graph" / "recon.json"
    if not graph_path.exists():
        raise FileNotFoundError(f"no recon graph at {graph_path}; run /recon first")
    graph = json.loads(graph_path.read_text(encoding="utf-8"))

    candidates = extract_candidates(graph)
    candidates.sort(key=lambda c: (-c.score, c.name))

    method = "heuristic"
    narrative = ""
    if model and candidates:
        subset = candidates[:llm_top]
        ordered_ids, rationales, narrative = llm_rerank(subset, model, ask)
        if ordered_ids:
            method = f"llm+heuristic:{model}"
            candidates = _merge_order(subset, ordered_ids) + candidates[len(subset):]
            for c in candidates:
                c.rationale = rationales.get(c.id, "")

    if top:
        candidates = candidates[:top]
    for i, c in enumerate(candidates, 1):
        c.rank = i

    summary = {
        "generated_by": method,
        "model": model,
        "target_count": len(candidates),
        "narrative": narrative,
        "targets": [c.to_row() for c in candidates],
    }
    (out / "triage.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "triage.md").write_text(render_markdown(summary), encoding="utf-8")
    return summary


def render_markdown(summary: Dict[str, Any]) -> str:
    lines = [
        "# Recon triage — ranked worklist",
        "",
        f"_generated by {summary['generated_by']} · {summary['target_count']} targets_",
        "",
    ]
    if summary.get("narrative"):
        lines += ["## Attack-surface narrative", "", summary["narrative"], ""]
    lines += ["## Targets (most attack-worthy first)", ""]
    for t in summary["targets"]:
        flags = []
        if t["exposed_origin"]:
            flags.append("exposed-origin")
        if t["has_http"]:
            flags.append("http")
        if t["behind_edge"]:
            flags.append("behind-edge")
        head = f"{t['rank']}. **{t['name']}** — score {t['score']:g}"
        if flags:
            head += f"  ({', '.join(flags)})"
        lines.append(head)
        if t.get("rationale"):
            lines.append(f"   - {t['rationale']}")
        if t["reasons"]:
            lines.append(f"   - signals: {', '.join(t['reasons'])}")
    return "\n".join(lines) + "\n"


__all__ = [
    "Candidate", "extract_candidates", "heuristic_score", "llm_rerank",
    "run_triage", "render_markdown", "TOKEN_WEIGHTS",
]
