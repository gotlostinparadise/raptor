"""Build the recon :class:`~core.recon.graph.Graph` from normalised records.

This is the inverse of a source: sources turn tool output into normalised
records (:mod:`core.recon.model`); this module turns a run's accumulated
records into the typed asset graph. Keeping the two apart means a source never
touches the graph — it only emits records — and the graph is a pure function of
the record set, so it can be rebuilt at any time (``run.sh graph`` in the
prototype) and is deterministic given the same records.

Ported from the ingest half of ``out/projects/bitpapa/recon/build.py``, but
reading from the normalised record schema instead of raw tool files, and with
two deliberate generalisations over the prototype:

  - **Discovery provenance** comes from :attr:`DnsRecord.discovery` (the field
    the producing source stamped), never from an inferred filename — so the
    prototype's active/passive mislabelling can't recur.
  - **Certificate edges** are keyed on *data*, not source. A cert bearing a
    root/apex name yields a ``cert_origin`` edge; a cert bearing an in-scope
    subdomain SAN yields ``tls_san`` — regardless of whether the cert came from
    Censys, crt.sh, or a direct TLS grab. (The prototype hard-split these by
    source, which is why ``cert_origin`` was Censys-only.)
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from core.recon import model as M
from core.recon.graph import Graph
from core.recon.scope import normalise_name as _norm_name, root_of


def build_graph(
    records_by_kind: Mapping[str, Iterable[Mapping[str, Any]]],
    roots: Sequence[str],
) -> Graph:
    """Construct a :class:`Graph` from normalised records.

    ``records_by_kind`` maps a record kind (``"dns"``, ``"hosts"``, …) to its
    rows (plain dicts, as produced by :meth:`Record.to_row`). Unknown kinds and
    absent kinds are ignored, so a partial run builds a partial graph.
    """
    g = Graph()
    roots = tuple(roots)
    root_set = set(roots)
    for r in roots:
        g.node(M.NODE_ROOT, r)

    def rows(kind: str) -> Iterable[Mapping[str, Any]]:
        return records_by_kind.get(kind, []) or []

    def host_type(name: str) -> str:
        return M.NODE_ROOT if name in root_set else M.NODE_SUBDOMAIN

    # --- subdomains: passive enumeration -> subdomain nodes ---
    for o in rows(M.SubdomainRecord.KIND):
        name = o.get("name")
        if not name or name in root_set:
            continue
        rt = o.get("root") or root_of(name, roots)
        g.node(M.NODE_SUBDOMAIN, name, sources=o.get("sources") or [], root=rt)
        g.edge((M.NODE_ROOT, rt), (M.NODE_SUBDOMAIN, name), M.REL_HAS_SUBDOMAIN)

    # --- dns: resolution + records; discovery read from the record ---
    for o in rows(M.DnsRecord.KIND):
        name = o.get("name")
        if not name:
            continue
        ntype = host_type(name)
        g.node(ntype, name, resolves=True,
               discovery=o.get("discovery") or M.DISCOVERY_PASSIVE)
        if ntype == M.NODE_SUBDOMAIN:
            g.edge((M.NODE_ROOT, root_of(name, roots)),
                   (M.NODE_SUBDOMAIN, name), M.REL_HAS_SUBDOMAIN)
        for ip in (o.get("a") or []) + (o.get("aaaa") or []):
            g.node(M.NODE_IP, ip)
            g.edge((ntype, name), (M.NODE_IP, ip), M.REL_RESOLVES_TO)
        for cn in (o.get("cname") or []):
            g.node(M.NODE_SUBDOMAIN, cn, external=True)
            g.edge((ntype, name), (M.NODE_SUBDOMAIN, cn), M.REL_CNAME)

    # --- hosts: ASN/org/geo + cdncheck edge classification ---
    for o in rows(M.HostRecord.KIND):
        ip = o.get("ip")
        if not ip:
            continue
        org = o.get("org") or ""
        g.node(M.NODE_IP, ip, asn=o.get("asn") or "", org=org,
               country=o.get("country") or "", city=o.get("city") or "")
        if org:
            g.node(M.NODE_ORG, org, asn=o.get("asn") or "",
                   country=o.get("country") or "")
            g.edge((M.NODE_IP, ip), (M.NODE_ORG, org), M.REL_ANNOUNCED_BY)
        kind, name = o.get("edge_kind") or "", o.get("edge_name") or ""
        if kind and name:
            g.node(M.NODE_IP, ip, edge_kind=kind, edge_name=name)
            g.node(M.NODE_EDGE_PROVIDER, name, kind=kind)
            g.edge((M.NODE_IP, ip), (M.NODE_EDGE_PROVIDER, name), kind)

    # --- http: live services + tech + behind(edge) ---
    for o in rows(M.HttpRecord.KIND):
        host = o.get("host")
        if not host:
            continue
        url = o.get("url") or ""
        svc = url or f"http://{host}"
        tech = o.get("tech") or []
        g.node(M.NODE_SERVICE, svc, status=o.get("status"),
               title=o.get("title") or "", server=o.get("server") or "",
               tech=tech)
        g.edge((host_type(host), host), (M.NODE_SERVICE, svc), M.REL_SERVES)
        for t in tech:
            g.node(M.NODE_TECH, t)
            g.edge((M.NODE_SERVICE, svc), (M.NODE_TECH, t), M.REL_USES)
        edge_hint = [t for t in tech if "ddos" in t.lower() or "guard" in t.lower()]
        if (o.get("server") or "").lower() == "ddos-guard" and "DDoS-Guard" not in edge_hint:
            edge_hint.append("DDoS-Guard")
        for eh in edge_hint:
            g.node(M.NODE_EDGE_PROVIDER, eh, kind="waf")
            g.edge((M.NODE_SERVICE, svc), (M.NODE_EDGE_PROVIDER, eh), M.REL_BEHIND)

    # --- ports: open port/service on an IP (naabu, censys) ---
    for o in rows(M.PortRecord.KIND):
        ip, port = o.get("ip"), o.get("port")
        if not ip or not port:
            continue
        proto = (o.get("proto") or "").upper()
        svc = f"{ip}:{port}"
        g.node(M.NODE_SERVICE, svc, server=o.get("software") or proto,
               tech=[proto] if proto else [], port=port,
               source=o.get("source") or "")
        g.edge((M.NODE_IP, ip), (M.NODE_SERVICE, svc), M.REL_EXPOSES)

    # --- certs: SAN names -> subdomains; data-keyed cert_origin / tls_san ---
    for o in rows(M.CertRecord.KIND):
        ip = o.get("ip")
        src = o.get("source") or "cert"
        for raw_name in (o.get("names") or []):
            name = _norm_name(raw_name)
            if not name:
                continue
            if name in root_set:
                # A cert presenting the apex/root => this IP is an origin for it.
                if ip:
                    g.edge((M.NODE_IP, ip), (M.NODE_ROOT, name), M.REL_CERT_ORIGIN)
                continue
            g.node(M.NODE_SUBDOMAIN, name, sources=[f"{src}-cert"])
            g.edge((M.NODE_ROOT, root_of(name, roots)),
                   (M.NODE_SUBDOMAIN, name), M.REL_HAS_SUBDOMAIN)
            if ip:
                g.edge((M.NODE_IP, ip), (M.NODE_SUBDOMAIN, name), M.REL_TLS_SAN)

    # --- netblock: registered ownership -> org + in_netblock edge ---
    for o in rows(M.NetblockRecord.KIND):
        org = o.get("org") or ""
        if not org:
            continue
        g.node(M.NODE_ORG, org, asn=o.get("asn") or "", country=o.get("country") or "")
        ip = o.get("ip")
        if ip:
            g.node(M.NODE_IP, ip)
            g.edge((M.NODE_IP, ip), (M.NODE_ORG, org), M.REL_IN_NETBLOCK)

    # --- origin: WAF-bypass / exposed-origin foothold (gated on verdict) ---
    for o in rows(M.OriginRecord.KIND):
        if o.get("verdict") != "exposed_origin":
            continue
        ip, host_hdr = o.get("ip"), o.get("host_header") or ""
        if not ip or not host_hdr:
            continue
        g.node(M.NODE_IP, ip, exposed_origin=True)
        tgt = host_type(host_hdr)
        g.node(tgt, host_hdr)
        g.edge((M.NODE_IP, ip), (tgt, host_hdr), M.REL_EXPOSED_ORIGIN)

    # --- vhost: DNS-less host reachable via Host-header routing (gated) ---
    for o in rows(M.VhostRecord.KIND):
        if o.get("verdict") != "reachable_vhost":
            continue
        host, ip = o.get("host"), o.get("ip")
        if not host or not ip:
            continue
        g.node(M.NODE_SUBDOMAIN, host, vhost_reachable=True, dns_less=True,
               vhost_ip=ip, vhost_trick=o.get("trick") or "")
        g.edge((M.NODE_ROOT, root_of(host, roots)),
               (M.NODE_SUBDOMAIN, host), M.REL_HAS_SUBDOMAIN)
        g.edge((M.NODE_IP, str(ip)), (M.NODE_SUBDOMAIN, host), M.REL_VHOST_REACHABLE)

    return g


__all__ = ["build_graph", "root_of"]
