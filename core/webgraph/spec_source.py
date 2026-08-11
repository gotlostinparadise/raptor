"""API-spec import — the first web-graph source, and a fully offline one.

Bridges :mod:`core.apitest.inventory` (which already parses OpenAPI / Swagger /
Postman / GraphQL-introspection into a normalised endpoint inventory) into the
web graph: each inventory endpoint becomes an ``endpoint`` node, each of its
path/query/body params a ``parameter`` node, and the spec's base URL an
``origin``. This is the "connective tissue" claim made concrete — a spec import
and a live crawl land on the *same* endpoint nodes because both key through
:func:`core.webgraph.scope.endpoint_id`.

It is ``active = False``: reading a spec sends no traffic, so it runs even under
the ``passive`` profile (spec-only analysis is always safe).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from core.apitest.inventory import build_inventory, load_spec
from core.webgraph import model as M
from core.webgraph.scope import canonical_origin, endpoint_id, split_url
from core.webgraph.source import RunContext, Source, SourceResult, Surface, register


@register
class ApiSpecImportSource(Source):
    """Import an API description into the graph. Offline; produces no traffic."""

    name = "api_spec_import"
    consumes = ()
    produces = ("origins", "endpoints", "parameters")
    active = False

    def __init__(self, spec_path: Optional[str] = None, base_url: str = "") -> None:
        # The spec path / base URL are source configuration, handed in by the
        # caller when the source is instantiated (the orchestrator forwards
        # pre-built instances unchanged).
        self.spec_path = spec_path
        self.base_url = base_url

    def available(self, ctx: RunContext) -> bool:
        return bool(self.spec_path) and Path(self.spec_path).is_file()

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        try:
            doc = load_spec(Path(self.spec_path))
            inv = build_inventory(doc, source_path=str(self.spec_path),
                                  base_url=self.base_url)
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return result

        base = inv.get("base_url") or self.base_url or (ctx.origins[0] if ctx.origins else "")
        origin = canonical_origin(base) if base else ""
        if origin:
            result.add(M.OriginRecord(origin=origin, source=self.name))
            result.discovered.origins.add(origin)

        for ep in inv.get("endpoints", []):
            method, path = ep.get("method", "GET"), ep.get("path", "")
            if not path:
                continue
            # If the spec path is absolute-URL-ish, split its origin out.
            ep_origin, ep_path = (split_url(path) if "://" in path else (origin, path))
            eid = endpoint_id(method, ep_path)
            result.add(M.EndpointRecord(
                method=method, path=ep_path, origin=ep_origin or origin,
                url=(f"{origin}{ep_path}" if origin and ep_path.startswith("/") else ""),
                auth_required=ep.get("auth_required"),
                object_scoped=bool(ep.get("object_scoped")),
                privileged=bool(ep.get("privileged")),
                owasp_focus=list(ep.get("owasp_focus") or []),
                source=self.name,
            ))
            result.discovered.endpoints.add(eid)
            for loc, key in ((M.LOC_PATH, "path_params"),
                             (M.LOC_QUERY, "query_params"),
                             (M.LOC_BODY, "body_fields")):
                for pname in ep.get(key) or []:
                    if not pname:
                        continue
                    result.add(M.ParamRecord(endpoint_id=eid, name=pname,
                                             location=loc, source=self.name))
        return result


__all__ = ["ApiSpecImportSource"]
