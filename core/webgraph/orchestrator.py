"""Run-loop, persistence, and graph serialisation for the web-graph pipeline.

This is the piece :mod:`core.recon` never grew — its equivalent lives only in
the ``out/projects/bitpapa/recon`` prototype's ``build.py``/``run.sh``. Here it
is a first-class module: given a set of in-scope origins, a safety
:class:`~core.webgraph.source.Profile`, and a set of sources, it

  1. builds a :class:`~core.webgraph.source.RunContext` rooted at a run dir,
  2. runs the available sources in a discovery loop, diffing the
     :class:`~core.webgraph.source.Surface` to decide when to stop,
  3. accumulates + persists ``normalized/<kind>.jsonl``,
  4. rebuilds the graph from those records via
     :func:`core.webgraph.builder.build_graph` and serialises
     ``graph/web.{json,dot,graphml}``.

Because the graph is a pure function of the record set, step 4 can be re-run at
any time (:func:`rebuild_from_disk`) without re-touching the target — the same
"records are the source of truth" discipline recon uses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Union

from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.graph import Graph
from core.webgraph.scope import canonical_origin
from core.webgraph.source import (
    DEFAULT_PROFILE, PROFILES, Profile, RunContext, Source, SourceResult, Surface,
    all_sources,
)


@dataclass
class RunSummary:
    """Outcome of a web-graph run — counts + where things landed."""

    out_dir: str
    origins: List[str]
    profile: str
    rounds: int
    sources_run: List[str] = field(default_factory=list)
    record_counts: Dict[str, int] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "origins": self.origins,
            "profile": self.profile, "rounds": self.rounds,
            "sources_run": self.sources_run, "record_counts": self.record_counts,
            "errors": self.errors, "node_count": self.node_count,
            "edge_count": self.edge_count,
        }


def _resolve_profile(profile: Union[str, Profile]) -> Profile:
    if isinstance(profile, Profile):
        return profile
    if profile not in PROFILES:
        raise ValueError(
            f"unknown profile {profile!r}; choose one of {sorted(PROFILES)}"
        )
    return PROFILES[profile]


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> int:
    """Append ``rows`` as one-JSON-per-line; create parents. Returns count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True))
            fh.write("\n")
            n += 1
    return n


def persist_records(
    normalized_dir: Path, records_by_kind: Mapping[str, List[Dict[str, Any]]],
) -> Dict[str, int]:
    """Write each kind's rows to ``normalized/<kind>.jsonl``; return counts."""
    counts: Dict[str, int] = {}
    for kind, rows in records_by_kind.items():
        if not rows:
            continue
        counts[kind] = write_jsonl(
            normalized_dir / M.normalized_filename(kind), rows
        )
    return counts


def load_records(normalized_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Read all ``normalized/<kind>.jsonl`` back into a records-by-kind map."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for kind in M.RECORD_KINDS:
        path = normalized_dir / M.normalized_filename(kind)
        if not path.exists():
            continue
        rows: List[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        if rows:
            out[kind] = rows
    return out


def serialize_graph(graph_dir: Path, graph: Graph) -> Dict[str, Path]:
    """Write ``web.json`` / ``web.dot`` / ``web.graphml``; return their paths."""
    graph_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": graph_dir / "web.json",
        "dot": graph_dir / "web.dot",
        "graphml": graph_dir / "web.graphml",
    }
    paths["json"].write_text(json.dumps(graph.to_json(), indent=2), encoding="utf-8")
    paths["dot"].write_text(graph.to_dot(), encoding="utf-8")
    paths["graphml"].write_text(graph.to_graphml(), encoding="utf-8")
    return paths


def rebuild_from_disk(out_dir: Union[str, Path], origins: Sequence[str] = ()) -> Graph:
    """Rebuild + re-serialise the graph purely from persisted records.

    Handy after a manual edit to ``normalized/*.jsonl`` or to regenerate exports
    without re-running any source.
    """
    out = Path(out_dir)
    records = load_records(out / "normalized")
    graph = build_graph(records, origins)
    serialize_graph(out / "graph", graph)
    return graph


def _instantiate_sources(
    sources: Optional[Sequence[Union[Source, type]]],
) -> List[Source]:
    """Normalise the ``sources`` argument to a list of instances.

    ``None`` ⇒ every registered source. Class ⇒ instantiate. Instance ⇒ as-is.
    """
    if sources is None:
        chosen: Iterable[Union[Source, type]] = list(all_sources().values())
    else:
        chosen = sources
    out: List[Source] = []
    for s in chosen:
        out.append(s() if isinstance(s, type) else s)
    return out


def run_webgraph(
    origins: Sequence[str],
    out_dir: Union[str, Path],
    *,
    sources: Optional[Sequence[Union[Source, type]]] = None,
    profile: Union[str, Profile] = DEFAULT_PROFILE,
    max_rounds: int = 2,
    env: Optional[Mapping[str, str]] = None,
    credentials: Optional[Mapping[str, str]] = None,
    http_factory: Optional[Any] = None,
    session: Optional[Any] = None,
    oast: Optional[Any] = None,
) -> RunSummary:
    """Run the web-graph pipeline end to end and return a :class:`RunSummary`.

    ``origins`` are the in-scope application roots (canonicalised on entry).
    ``sources`` defaults to the whole registry; each is filtered through
    :meth:`Source.available` against the resolved ``profile`` so a passive
    profile silently drops active sources. The loop reruns available sources
    while the :class:`Surface` keeps growing (bounded by ``max_rounds``); node
    merge makes rerunning idempotent.
    """
    out = Path(out_dir)
    raw_dir, normalized_dir, graph_dir = out / "raw", out / "normalized", out / "graph"
    for d in (raw_dir, normalized_dir, graph_dir):
        d.mkdir(parents=True, exist_ok=True)

    prof = _resolve_profile(profile)
    canon_origins = tuple(dict.fromkeys(canonical_origin(o) or o for o in origins))

    surface = Surface(origins=set(canon_origins), urls=set(canon_origins))
    instances = _instantiate_sources(sources)

    accumulated: Dict[str, List[Dict[str, Any]]] = {}
    # Row-level dedup keeps persistence idempotent across discovery rounds — a
    # source that reruns and re-emits identical records adds nothing, mirroring
    # the graph's node-merge idempotency. Genuinely distinct observations differ
    # in at least one field and are kept.
    seen: Dict[str, set] = {}
    summary = RunSummary(
        out_dir=str(out), origins=list(canon_origins), profile=prof.name, rounds=0,
    )
    ran: List[str] = []

    for round_no in range(1, max_rounds + 1):
        summary.rounds = round_no
        before = len(surface)
        ctx = RunContext(
            origins=canon_origins, surface=surface, profile=prof,
            raw_dir=raw_dir, normalized_dir=normalized_dir,
            env=env or {}, credentials=credentials or {},
            http_factory=http_factory, session=session, oast=oast,
        )
        for src in instances:
            if not src.enabled_for(prof) or not src.available(ctx):
                continue
            try:
                result: SourceResult = src.run(ctx)
            except Exception as exc:  # a broken source must not abort the run
                summary.errors[src.name] = f"{type(exc).__name__}: {exc}"
                continue
            if src.name not in ran:
                ran.append(src.name)
            if result.error:
                summary.errors[src.name] = result.error
            for kind, rows in result.records.items():
                bucket = accumulated.setdefault(kind, [])
                seg = seen.setdefault(kind, set())
                for row in rows:
                    rowkey = json.dumps(row, sort_keys=True)
                    if rowkey in seg:
                        continue
                    seg.add(rowkey)
                    bucket.append(row)
            surface.merge(result.discovered)
        # Fixed point: no source grew the surface this round.
        if len(surface) == before:
            break

    summary.sources_run = ran
    summary.record_counts = persist_records(normalized_dir, accumulated)

    graph = build_graph(accumulated, canon_origins)
    paths = serialize_graph(graph_dir, graph)
    stats = graph.stats()
    summary.node_count = stats["node_count"]
    summary.edge_count = stats["edge_count"]

    (out / "webgraph-summary.json").write_text(
        json.dumps(summary.to_dict(), indent=2), encoding="utf-8"
    )
    _ = paths
    return summary


__all__ = [
    "RunSummary", "write_jsonl", "persist_records", "load_records",
    "serialize_graph", "rebuild_from_disk", "run_webgraph",
]
