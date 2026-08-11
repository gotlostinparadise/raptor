"""The `/graphql` engine — introspection + alias/batching DoS.

Two GraphQL-specific weaknesses generic scanners miss:

  * **Introspection enabled** in production (information disclosure) — confirmed
    when the endpoint returns its schema.
  * **Alias / batching amplification** — one request aliasing a field N times
    multiplies server work; confirmed when the server resolves all aliases
    instead of rejecting on a complexity/alias limit. Resource-class, so it only
    runs with ``resource_tests`` enabled.

Argument injection is delegated to `/inject` (GraphQL fields land as endpoints in
the graph, so `/inject --from-webgraph` targets them) and field-level
authorization to `/webauthz` (a GraphQL query is a ``POST /graphql`` body that
the authz oracle replays across identities) — no logic is duplicated here.

Safe by default: ``active=False`` sends nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from core.graphql import checks
from core.graphql.config import GraphQLConfig
from core.graphql.introspection import (
    INTROSPECTION_QUERY, operations, post_graphql, schema_from_response,
)
from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.login import BearerAuth, resolve_credential
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.verified import record_confirmed

_TESTER = "tester"


@dataclass
class GraphQLRun:
    out_dir: str
    url: str
    active: bool
    introspection_open: bool = False
    operation_count: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "url": self.url, "active": self.active,
            "introspection_open": self.introspection_open,
            "operation_count": self.operation_count,
            "finding_count": len(self.findings), "findings": self.findings,
            "warnings": self.warnings, "node_count": self.node_count,
            "edge_count": self.edge_count,
        }


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def run_graphql(
    config: GraphQLConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> GraphQLRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = GraphQLRun(out_dir=str(out), url=config.url, active=active)
    eid = f"POST {config.path}"

    if active:
        if profile == "passive":
            raise ValueError("active testing cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError("active testing refused: config.authorization is empty")

    vulns: List[Dict[str, Any]] = []
    recs: Dict[str, List[Dict[str, Any]]] = {
        M.EndpointRecord.KIND: [M.EndpointRecord(
            method="POST", path=config.path, origin=config.base_url,
            url=config.url, source="graphql").to_row()],
    }

    if not active:
        run.findings = [{"planned": True, "checks": ["introspection"] +
                         (["batching_dos"] if config.resource_tests else [])}]
        _finalize(out, run, recs)
        return run

    # build a session engine (normalises non-2xx, carries an optional token)
    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory or (lambda h: _client_for(config.base_url)))(
        [host] if host else [])
    engine = SessionEngine(client)
    engine.add_identity(Identity(name=_TESTER))
    if config.token_env:
        tok = resolve_credential(config.token_env, env)
        if tok:
            engine.authenticate(_TESTER, BearerAuth(tok))
        else:
            run.warnings.append(f"missing ${config.token_env}; unauthenticated")

    # --- introspection ---
    try:
        resp = post_graphql(engine, config.url, INTROSPECTION_QUERY)
        schema = schema_from_response(resp)
    except Exception as exc:
        run.warnings.append(f"introspection failed: {type(exc).__name__}: {exc}")
        schema = None

    if checks.introspection_enabled(schema):
        run.introspection_open = True
        ops = operations(schema)
        run.operation_count = len(ops)
        vulns.append(M.VulnRecord(
            id="GQL-INTROSPECTION", vuln_class="graphql_introspection",
            endpoint_id=eid, severity="medium", owasp="API8",
            status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_REFLECTED_MARKER,
            evidence={"operation_count": len(ops),
                      "sample_operations": [o.name for o in ops[:20]]},
            source="graphql").to_row())
        run.findings.append({"id": "GQL-INTROSPECTION",
                             "class": "graphql_introspection", "proof": "reflected_marker"})
    else:
        ops = []

    # --- alias / batching DoS (resource-class, opt-in) ---
    if config.resource_tests:
        # Prefer a field with NO required args — aliasing a field that needs
        # args yields top-level errors (a false negative), not amplification.
        argless = next((o.name for o in ops if not o.args), "")
        field_name = config.dos_field or argless or (ops[0].name if ops else "")
        if field_name:
            n = config.dos_aliases
            try:
                r = post_graphql(engine, config.url, checks.alias_query(field_name, n))
                if checks.batching_accepted(r, n):
                    vulns.append(M.VulnRecord(
                        id="GQL-BATCHING", vuln_class="graphql_batching_dos",
                        endpoint_id=eid, severity="medium", owasp="API4",
                        status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_REFLECTED_MARKER,
                        evidence={"field": field_name, "aliases": n,
                                  "note": "server resolved all aliases; no complexity limit"},
                        source="graphql").to_row())
                    run.findings.append({"id": "GQL-BATCHING",
                                        "class": "graphql_batching_dos", "proof": "reflected_marker"})
            except Exception as exc:
                run.warnings.append(f"batching check failed: {type(exc).__name__}")
        else:
            run.warnings.append("no field available for batching DoS check")

    if vulns:
        recs[M.VulnRecord.KIND] = vulns
    _finalize(out, run, recs)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: GraphQLRun, recs) -> None:
    from core.webgraph.scope import canonical_origin
    origin = canonical_origin(run.url)
    graph = build_graph(recs, [origin] if origin else [])
    persist_records(out / "normalized", recs)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count, run.edge_count = stats["node_count"], stats["edge_count"]
    (out / "graphql-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["GraphQLRun", "run_graphql"]
