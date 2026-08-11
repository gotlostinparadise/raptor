"""Normalised recon record schema + graph vocabulary.

Two things live here:

1. **The graph vocabulary** — the canonical node-type and edge-relation
   names. :mod:`core.recon.graph` owns the data structure; this module names
   what may go in it, so sources and the builder agree on spelling.

2. **The normalised record schema** — one dataclass per record *kind*. Sources
   emit these (as plain dicts via :meth:`Record.to_row`); the builder reads
   them to construct the graph; they are persisted one-JSON-per-line under a
   run's ``normalized/<kind>.jsonl``. Field names are kept identical to the
   ``out/projects/bitpapa/recon`` prototype's ``normalized/*.jsonl`` so that
   existing data re-ingests losslessly, with three new kinds added
   (``ports``, ``certs``, ``netblock``).

Design note — the active/passive fix. In the prototype, whether a DNS finding
was tagged ``active`` vs ``passive`` was inferred *downstream* from the raw
filename it came from (``dnsx.jsonl`` → passive, ``bruteforce*.jsonl`` →
active), and the two inference sites disagreed (one keyed on a filename no
script produced), so deep-bruteforce hosts were mislabelled. Here the
producing source stamps :attr:`DnsRecord.discovery` directly and the builder
reads that field — there is no filename inference anywhere, so the two can't
drift.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Dict, List, Optional


# ─────────────────────────── graph vocabulary ───────────────────────────

# Node types — must match the keys of :data:`core.recon.graph.TYPES`.
NODE_ROOT = "root"
NODE_SUBDOMAIN = "subdomain"
NODE_IP = "ip"
NODE_ORG = "org"
NODE_SERVICE = "service"
NODE_TECH = "tech"
NODE_EDGE_PROVIDER = "edge_provider"

NODE_TYPES = (
    NODE_ROOT, NODE_SUBDOMAIN, NODE_IP, NODE_ORG,
    NODE_SERVICE, NODE_TECH, NODE_EDGE_PROVIDER,
)

# Edge relations — the verb on a directed edge.
REL_HAS_SUBDOMAIN = "has_subdomain"      # root      -> subdomain
REL_RESOLVES_TO = "resolves_to"          # host      -> ip
REL_CNAME = "cname"                      # host      -> subdomain
REL_ANNOUNCED_BY = "announced_by"        # ip        -> org
REL_CDN = "cdn"                          # ip        -> edge_provider
REL_WAF = "waf"                          # ip        -> edge_provider
REL_CLOUD = "cloud"                      # ip        -> edge_provider
REL_SERVES = "serves"                    # host      -> service
REL_USES = "uses"                        # service   -> tech
REL_BEHIND = "behind"                    # service   -> edge_provider
REL_EXPOSED_ORIGIN = "exposed_origin"    # ip        -> host   (WAF bypass)
REL_VHOST_REACHABLE = "vhost_reachable"  # ip        -> subdomain (DNS-less)
REL_CERT_ORIGIN = "cert_origin"          # ip        -> root   (serves scope cert)
REL_EXPOSES = "exposes"                  # ip        -> service (open port)
REL_TLS_SAN = "tls_san"                  # ip        -> host   (SAN on direct cert)
REL_IN_NETBLOCK = "in_netblock"          # ip        -> org    (RDAP/whois netblock)

EDGE_RELATIONS = (
    REL_HAS_SUBDOMAIN, REL_RESOLVES_TO, REL_CNAME, REL_ANNOUNCED_BY,
    REL_CDN, REL_WAF, REL_CLOUD, REL_SERVES, REL_USES, REL_BEHIND,
    REL_EXPOSED_ORIGIN, REL_VHOST_REACHABLE, REL_CERT_ORIGIN, REL_EXPOSES,
    REL_TLS_SAN, REL_IN_NETBLOCK,
)

# Discovery provenance — was the finding observed with active traffic to the
# target's own infrastructure, or from a passive third-party source?
DISCOVERY_PASSIVE = "passive"
DISCOVERY_ACTIVE = "active"


# ─────────────────────────── normalised records ─────────────────────────

@dataclass
class Record:
    """Base for every normalised record kind.

    Subclasses set :attr:`KIND` (the ``normalized/<KIND>.jsonl`` stem) and
    declare the schema as fields. :meth:`to_row` returns a JSON-serialisable
    dict — the on-disk / graph-builder representation. ``KIND`` is a
    ``ClassVar`` so it never leaks into the row.
    """

    KIND: ClassVar[str] = ""

    def to_row(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubdomainRecord(Record):
    """A name in scope and where it was seen. From passive enumeration."""

    KIND: ClassVar[str] = "subdomains"
    name: str
    root: str
    sources: List[str] = field(default_factory=list)


@dataclass
class DnsRecord(Record):
    """Resolution of a name: A/AAAA/CNAME plus discovery provenance."""

    KIND: ClassVar[str] = "dns"
    name: str
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    status: Optional[str] = None
    # DISCOVERY_PASSIVE | DISCOVERY_ACTIVE — stamped by the producing source;
    # the graph builder reads this field, never a filename (see module note).
    discovery: str = DISCOVERY_PASSIVE


@dataclass
class HostRecord(Record):
    """IP-level metadata: ASN, org, geo, and edge/WAF classification.

    ``edge_kind`` / ``edge_name`` carry a CDN/WAF/cloud classification for the
    IP (from cdncheck): ``edge_kind`` is one of ``"cdn"``/``"waf"``/``"cloud"``
    and ``edge_name`` the provider (e.g. ``"DDoS-Guard"``). The builder turns a
    populated pair into an ``edge_provider`` node + a typed edge. Empty ⇒ the
    IP wasn't classified as fronted, so no edge is drawn.
    """

    KIND: ClassVar[str] = "hosts"
    ip: str
    asn: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    edge_kind: str = ""
    edge_name: str = ""


@dataclass
class HttpRecord(Record):
    """A live HTTP service and its fingerprint."""

    KIND: ClassVar[str] = "http"
    host: str
    url: str = ""
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    tech: List[str] = field(default_factory=list)
    content_length: Optional[int] = None
    ip: Optional[str] = None


@dataclass
class TlsRecord(Record):
    """TLS leaf certificate observed on a service."""

    KIND: ClassVar[str] = "tls"
    host: str
    cn: str = ""
    san: List[str] = field(default_factory=list)
    issuer: str = ""


@dataclass
class PortRecord(Record):
    """An open port / service on an IP (from a port scan or asset lookup).

    New kind (not in the prototype's normalized set). ``source`` records which
    tool observed it (``censys``, ``naabu``, …) since active and passive
    observations carry different confidence.
    """

    KIND: ClassVar[str] = "ports"
    ip: str
    port: int
    proto: str = ""
    software: str = ""
    source: str = ""


@dataclass
class CertRecord(Record):
    """A certificate and the DNS names on it (CT log or asset lookup).

    New kind. ``names`` is the SAN/CN set already normalised + scope-filtered
    by the source; the builder promotes each to a subdomain node.
    """

    KIND: ClassVar[str] = "certs"
    source: str
    names: List[str] = field(default_factory=list)
    ip: Optional[str] = None
    sha256: Optional[str] = None
    issuer: Optional[str] = None


@dataclass
class NetblockRecord(Record):
    """Registered netblock / ASN ownership for an IP (RDAP / whois).

    New kind. Ties an IP to the org that *registered* the surrounding CIDR,
    which is stronger provenance than the BGP-announced org alone. ``ip`` is
    the address the lookup was performed for, so the builder can draw an
    ``ip --in_netblock--> org`` edge; ``cidr`` is the block that IP falls in.
    """

    KIND: ClassVar[str] = "netblock"
    cidr: str
    asn: str = ""
    org: str = ""
    country: str = ""
    source: str = ""
    ip: Optional[str] = None


@dataclass
class OriginRecord(Record):
    """WAF-bypass / exposed-origin probe result (mirrors the raw probe row).

    Persisted verbatim; the builder gates on ``verdict == "exposed_origin"``.
    """

    KIND: ClassVar[str] = "origin"
    ip: str
    host_header: str = ""
    scheme: str = ""
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    body_sha256: str = ""
    matches_baseline: Optional[bool] = None
    verdict: str = ""


@dataclass
class VhostRecord(Record):
    """Host-header virtual-host probe result (mirrors the raw probe row).

    Persisted verbatim; the builder gates on ``verdict == "reachable_vhost"``.
    """

    KIND: ClassVar[str] = "vhost"
    host: str
    ip: str
    scheme: str = ""
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    content_length: Optional[int] = None
    body_sha256: str = ""
    distinct_from_default: Optional[bool] = None
    trick: str = ""
    verdict: str = ""


# Every concrete record kind, keyed by its ``KIND`` stem. Used to enumerate
# the ``normalized/*.jsonl`` surface and to validate a source's ``produces``.
RECORD_TYPES: Dict[str, type] = {
    cls.KIND: cls
    for cls in (
        SubdomainRecord, DnsRecord, HostRecord, HttpRecord, TlsRecord,
        PortRecord, CertRecord, NetblockRecord, OriginRecord, VhostRecord,
    )
}

RECORD_KINDS = tuple(RECORD_TYPES.keys())


def normalized_filename(kind: str) -> str:
    """On-disk name for a record kind's JSONL file."""
    return f"{kind}.jsonl"


__all__ = [
    # node types
    "NODE_ROOT", "NODE_SUBDOMAIN", "NODE_IP", "NODE_ORG", "NODE_SERVICE",
    "NODE_TECH", "NODE_EDGE_PROVIDER", "NODE_TYPES",
    # edge relations
    "REL_HAS_SUBDOMAIN", "REL_RESOLVES_TO", "REL_CNAME", "REL_ANNOUNCED_BY",
    "REL_CDN", "REL_WAF", "REL_CLOUD", "REL_SERVES", "REL_USES", "REL_BEHIND",
    "REL_EXPOSED_ORIGIN", "REL_VHOST_REACHABLE", "REL_CERT_ORIGIN",
    "REL_EXPOSES", "REL_TLS_SAN", "REL_IN_NETBLOCK", "EDGE_RELATIONS",
    # discovery
    "DISCOVERY_PASSIVE", "DISCOVERY_ACTIVE",
    # records
    "Record", "SubdomainRecord", "DnsRecord", "HostRecord", "HttpRecord",
    "TlsRecord", "PortRecord", "CertRecord", "NetblockRecord", "OriginRecord",
    "VhostRecord", "RECORD_TYPES", "RECORD_KINDS", "normalized_filename",
]
