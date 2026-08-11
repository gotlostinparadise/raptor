"""Build the web :class:`~core.webgraph.graph.Graph` from normalised records.

The inverse of a source: sources turn crawl / spec / capture output into
normalised records (:mod:`core.webgraph.model`); this module turns a run's
accumulated records into the typed application graph. Keeping the two apart
means a source never touches the graph — it only emits records — so the graph is
a pure function of the record set and can be rebuilt at any time.

Directly parallels :mod:`core.recon.builder`: a linear pass, one block per record
kind, each calling :meth:`Graph.node` / :meth:`Graph.edge`. Endpoint and
parameter identity flow through :mod:`core.webgraph.scope` so a spec-import
source and a live crawl land on the *same* nodes.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urljoin

from core.webgraph import model as M
from core.webgraph.graph import Graph
from core.webgraph.scope import canonical_origin, endpoint_id, split_url


def _param_node_id(endpoint_id_str: str, location: str, name: str) -> str:
    """Deterministic ``parameter`` node id, scoped to its endpoint."""
    return f"{endpoint_id_str}|{location}:{name}"


def build_graph(
    records_by_kind: Mapping[str, Iterable[Mapping[str, Any]]],
    origins: Sequence[str] = (),
) -> Graph:
    """Construct a :class:`Graph` from normalised records.

    ``records_by_kind`` maps a record kind (``"endpoints"``, ``"requests"``, …)
    to its rows (plain dicts, as produced by :meth:`Record.to_row`). Unknown and
    absent kinds are ignored, so a partial run builds a partial graph.
    ``origins`` seeds ``origin`` nodes for the run's in-scope roots.
    """
    g = Graph()
    for o in origins:
        co = canonical_origin(o) or o
        if co:
            g.node(M.NODE_ORIGIN, co)

    def rows(kind: str) -> Iterable[Mapping[str, Any]]:
        return records_by_kind.get(kind, []) or []

    # --- origins: application origins + fingerprint ---
    for o in rows(M.OriginRecord.KIND):
        origin = o.get("origin")
        if not origin:
            continue
        g.node(M.NODE_ORIGIN, origin, title=o.get("title") or "",
               server=o.get("server") or "", tech=o.get("tech") or [])

    # --- endpoints: templated request targets under an origin ---
    for o in rows(M.EndpointRecord.KIND):
        method, path = o.get("method"), o.get("path")
        if not method or not path:
            continue
        eid = endpoint_id(method, path)
        origin = o.get("origin") or canonical_origin(o.get("url") or "")
        g.node(M.NODE_ENDPOINT, eid, method=method.upper(), path=path,
               origin=origin, status=o.get("status"),
               content_type=o.get("content_type") or "",
               auth_required=o.get("auth_required"),
               object_scoped=bool(o.get("object_scoped")),
               privileged=bool(o.get("privileged")),
               owasp_focus=o.get("owasp_focus") or [],
               source=o.get("source") or "")
        if origin:
            g.node(M.NODE_ORIGIN, origin)
            g.edge((M.NODE_ORIGIN, origin), (M.NODE_ENDPOINT, eid), M.REL_HOSTS)

    # --- parameters: attach to their endpoint ---
    for o in rows(M.ParamRecord.KIND):
        eid, name = o.get("endpoint_id"), o.get("name")
        if not eid or not name:
            continue
        loc = o.get("location") or M.LOC_QUERY
        pid = _param_node_id(eid, loc, name)
        g.node(M.NODE_PARAMETER, pid, name=name, location=loc,
               endpoint_id=eid, example=o.get("example") or "",
               source=o.get("source") or "")
        g.node(M.NODE_ENDPOINT, eid)
        g.edge((M.NODE_ENDPOINT, eid), (M.NODE_PARAMETER, pid), M.REL_HAS_PARAM)

    # --- pages: rendered/fetched documents under an origin ---
    for o in rows(M.PageRecord.KIND):
        url = o.get("url")
        if not url:
            continue
        origin = o.get("origin") or canonical_origin(url)
        g.node(M.NODE_PAGE, url, origin=origin, title=o.get("title") or "",
               status=o.get("status"), rendered=bool(o.get("rendered")),
               source=o.get("source") or "")
        if origin:
            g.node(M.NODE_ORIGIN, origin)
            g.edge((M.NODE_ORIGIN, origin), (M.NODE_PAGE, url), M.REL_HOSTS)

    # --- forms: page has_form; form submits_to a (derived) endpoint ---
    for o in rows(M.FormRecord.KIND):
        page_url = o.get("page_url")
        if not page_url:
            continue
        action = o.get("action") or page_url
        method = (o.get("method") or "GET").upper()
        action_url = urljoin(page_url, action)
        fid = f"{page_url}#form:{method}:{action}"
        g.node(M.NODE_FORM, fid, action=action_url, method=method,
               fields=o.get("fields") or [], source=o.get("source") or "")
        g.node(M.NODE_PAGE, page_url)
        g.edge((M.NODE_PAGE, page_url), (M.NODE_FORM, fid), M.REL_HAS_FORM)
        # The submit target is an endpoint: split the resolved action into its
        # origin + path so the id templatises the path (not the whole URL) and
        # the endpoint hangs off its origin like any other.
        submit_origin, submit_path = split_url(action_url)
        eid = endpoint_id(method, submit_path)
        g.node(M.NODE_ENDPOINT, eid, method=method, path=submit_path,
               origin=submit_origin, source=o.get("source") or "")
        g.edge((M.NODE_FORM, fid), (M.NODE_ENDPOINT, eid), M.REL_SUBMITS_TO)
        if submit_origin:
            g.node(M.NODE_ORIGIN, submit_origin)
            g.edge((M.NODE_ORIGIN, submit_origin), (M.NODE_ENDPOINT, eid), M.REL_HOSTS)

    # --- identities: first-class session nodes ---
    for o in rows(M.IdentityRecord.KIND):
        name = o.get("name")
        if not name:
            continue
        g.node(M.NODE_IDENTITY, name, role=o.get("role") or "",
               authenticated=bool(o.get("authenticated")),
               source=o.get("source") or "")

    # --- requests: accessible_as edge carrying captured evidence ---
    for o in rows(M.RequestRecord.KIND):
        eid = o.get("endpoint_id")
        if not eid:
            continue
        identity = o.get("identity") or "anonymous"
        g.node(M.NODE_ENDPOINT, eid)
        g.node(M.NODE_IDENTITY, identity)
        g.edge((M.NODE_IDENTITY, identity), (M.NODE_ENDPOINT, eid),
               M.REL_ACCESSIBLE_AS, status=o.get("status"),
               resp_len=o.get("resp_len"), body_sha256=o.get("body_sha256") or "",
               allowed=o.get("allowed"), method=o.get("method") or "",
               url=o.get("url") or "", source=o.get("source") or "")

    # --- vulns: vuln node + endpoint --vulnerable_to--> vuln ---
    for o in rows(M.VulnRecord.KIND):
        vid, eid = o.get("id"), o.get("endpoint_id")
        if not vid:
            continue
        g.node(M.NODE_VULN, vid, vuln_class=o.get("vuln_class") or "",
               endpoint_id=eid or "", param=o.get("param") or "",
               identity=o.get("identity") or "", severity=o.get("severity") or "",
               owasp=o.get("owasp") or "", status=o.get("status") or M.STATUS_SUSPECTED,
               proof_kind=o.get("proof_kind") or M.PROOF_NONE,
               source=o.get("source") or "")
        if eid:
            g.node(M.NODE_ENDPOINT, eid)
            g.edge((M.NODE_ENDPOINT, eid), (M.NODE_VULN, vid), M.REL_VULNERABLE_TO)

    return g


__all__ = ["build_graph"]
