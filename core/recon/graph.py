"""Typed infrastructure-recon graph — provider-agnostic asset model.

A recon run discovers assets (domains, subdomains, IPs, orgs, services,
technologies, edge/WAF providers) and the relationships between them. This
module is the data structure that holds them: a typed, multi-attribute
directed graph whose node identity is ``(type, id)`` so that re-runs and
overlapping sources **merge** rather than duplicate.

It owns no I/O beyond serialisation. Sources emit normalised records
(:mod:`core.recon.model`); a builder walks those records and calls
:meth:`Graph.node` / :meth:`Graph.edge`; exporters here turn the result into
JSON (for the dashboard), DOT (Graphviz) and GraphML (yEd / Gephi / Cytoscape).

Merge semantics — the load-bearing invariant every source relies on:

  - **Nodes** key on ``(type, id)``. Re-adding the same key merges attributes:
    lists union (append-if-absent, order-preserving), scalars are
    *first-writer-wins* (``setdefault`` — an existing value is never
    overwritten, so a later low-confidence source cannot clobber an earlier
    authoritative one). Empty values (``None``, ``""``, ``[]``, ``{}``) are
    dropped so a source that "knows nothing" about a field is a no-op.
  - **Edges** key on ``(src, dst, rel)`` where ``src``/``dst`` are node keys.
    Re-adding overwrites the edge's own attrs but never creates a duplicate.
    An edge whose endpoint is ``None`` is silently dropped (lets callers pass
    the result of an optional lookup straight in).

Ported from the ``out/projects/bitpapa/recon/build.py`` prototype's ``Graph``
class, kept behaviour-compatible so existing ``raw/`` data re-ingests losslessly.
"""

from __future__ import annotations

import xml.sax.saxutils as _su
from typing import Any, Dict, List, Optional, Tuple

# A node is addressed by a (type, id) tuple; both halves are strings.
NodeKey = Tuple[str, str]

# Visual class per node type — colour + human label. Consumed by the HTML
# dashboard's legend and by the DOT exporter's fill colours. Keeping the
# palette here (not in the renderer) means every export agrees on colour.
TYPES: Dict[str, Dict[str, str]] = {
    "root":          {"color": "#e63946", "label": "Apex domain"},
    "subdomain":     {"color": "#457b9d", "label": "Subdomain"},
    "ip":            {"color": "#2a9d8f", "label": "IP address"},
    "org":           {"color": "#8338ec", "label": "ASN / Org"},
    "service":       {"color": "#f4a261", "label": "HTTP service"},
    "tech":          {"color": "#e9c46a", "label": "Technology"},
    "edge_provider": {"color": "#6c757d", "label": "Edge / WAF"},
}

_DEFAULT_COLOR = "#999999"

# Values treated as "no information" — a source passing one of these for an
# attribute is a no-op rather than an overwrite-with-nothing.
_EMPTY = (None, "", [], {})


class Graph:
    """Typed multi-attribute directed graph. Nodes keyed ``(type, id)``.

    Pure in-memory structure with no filesystem side effects. Build it by
    calling :meth:`node` and :meth:`edge`; serialise with :meth:`to_json`,
    :meth:`to_dot`, :meth:`to_graphml`.
    """

    #: Exposed on the instance too, so exporters and tests can read the
    #: palette without importing the module-level constant.
    TYPES = TYPES

    def __init__(self) -> None:
        # (type, id) -> {"type", "id", "attrs": {...}}
        self.nodes: Dict[NodeKey, Dict[str, Any]] = {}
        # (src_key, dst_key, rel) -> attrs
        self.edges: Dict[Tuple[NodeKey, NodeKey, str], Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    def node(self, ntype: str, nid: Any, **attrs: Any) -> NodeKey:
        """Create or merge a node; return its ``(type, id)`` key.

        The key is safe to pass straight to :meth:`edge`. Attribute merge
        follows the module invariant: lists union, scalars first-writer-wins,
        empty values ignored.
        """
        key: NodeKey = (ntype, str(nid))
        n = self.nodes.setdefault(key, {"type": ntype, "id": str(nid), "attrs": {}})
        for k, v in attrs.items():
            if v in _EMPTY:
                continue
            if isinstance(v, list):
                cur = n["attrs"].setdefault(k, [])
                for item in v:
                    if item not in cur:
                        cur.append(item)
            else:
                n["attrs"].setdefault(k, v)
        return key

    def edge(
        self,
        src: Optional[NodeKey],
        dst: Optional[NodeKey],
        rel: str,
        **attrs: Any,
    ) -> None:
        """Add (or overwrite the attrs of) a ``src --rel--> dst`` edge.

        No-op if either endpoint is ``None`` — lets callers forward the result
        of an optional lookup without a guard. Idempotent on ``(src, dst, rel)``.
        """
        if src is None or dst is None:
            return
        self.edges[(src, dst, rel)] = attrs

    # ------------------------------------------------------------------
    # serialisation
    # ------------------------------------------------------------------
    def to_json(self) -> Dict[str, Any]:
        """Return ``{nodes, edges, types, stats}`` for the dashboard.

        Nodes are emitted in a stable sort order and referenced by the
        ``"type:id"`` string form. An edge is emitted only when both of its
        endpoints exist as nodes.
        """
        node_list: List[Dict[str, Any]] = []
        index: Dict[NodeKey, int] = {}
        for i, (key, n) in enumerate(sorted(self.nodes.items())):
            index[key] = i
            node_list.append({
                "id": f"{n['type']}:{n['id']}",
                "type": n["type"],
                "label": n["id"],
                "color": self.TYPES.get(n["type"], {}).get("color", _DEFAULT_COLOR),
                **n["attrs"],
            })
        edge_list: List[Dict[str, Any]] = []
        for (src, dst, rel), a in sorted(self.edges.items()):
            if src in index and dst in index:
                edge_list.append({
                    "source": f"{src[0]}:{src[1]}",
                    "target": f"{dst[0]}:{dst[1]}",
                    "rel": rel,
                    **a,
                })
        return {
            "nodes": node_list,
            "edges": edge_list,
            "types": self.TYPES,
            "stats": self.stats(),
        }

    def stats(self) -> Dict[str, Any]:
        """Node/edge counts plus a per-type node breakdown."""
        by_type: Dict[str, int] = {}
        for (t, _id) in self.nodes:
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "by_type": by_type,
        }

    def to_dot(self) -> str:
        """Render as a Graphviz ``digraph`` (left-to-right, filled nodes)."""
        out = [
            "digraph recon {",
            '  rankdir=LR; node [style=filled,fontname="Helvetica"];',
        ]
        for (t, nid), _n in sorted(self.nodes.items()):
            color = self.TYPES.get(t, {}).get("color", _DEFAULT_COLOR)
            lbl = nid.replace('"', "'")
            out.append(f'  "{t}:{nid}" [label="{lbl}",fillcolor="{color}"];')
        for (src, dst, rel), _a in sorted(self.edges.items()):
            out.append(f'  "{src[0]}:{src[1]}" -> "{dst[0]}:{dst[1]}" [label="{rel}"];')
        out.append("}")
        return "\n".join(out)

    def to_graphml(self) -> str:
        """Render as GraphML (node ``type``/``label`` + edge ``rel`` data keys)."""
        e = _su.escape
        out = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '<key id="d_type" for="node" attr.name="type" attr.type="string"/>',
            '<key id="d_label" for="node" attr.name="label" attr.type="string"/>',
            '<key id="d_rel" for="edge" attr.name="rel" attr.type="string"/>',
            '<graph edgedefault="directed">',
        ]
        for (t, nid), _n in sorted(self.nodes.items()):
            gid = e(f"{t}:{nid}")
            out.append(
                f'<node id="{gid}"><data key="d_type">{e(t)}</data>'
                f'<data key="d_label">{e(nid)}</data></node>'
            )
        for i, ((src, dst, rel), _a) in enumerate(sorted(self.edges.items())):
            out.append(
                f'<edge id="e{i}" source="{e(src[0] + ":" + src[1])}" '
                f'target="{e(dst[0] + ":" + dst[1])}">'
                f'<data key="d_rel">{e(rel)}</data></edge>'
            )
        out += ["</graph>", "</graphml>"]
        return "\n".join(out)


__all__ = ["Graph", "NodeKey", "TYPES"]
