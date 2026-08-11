"""App-layer graph vocabulary + normalised record schema.

The web graph is the application-layer twin of :mod:`core.recon` — same design,
different surface. Recon models *infrastructure* (domains, IPs, ASNs); this
models the *application*: origins, pages, forms, endpoints, their parameters,
the identities traffic was sent as, and the vulnerabilities found. Two things
live here, exactly as in :mod:`core.recon.model`:

1. **The graph vocabulary** — canonical node-type and edge-relation names.
   :mod:`core.webgraph.graph` owns the structure; this names what may go in it,
   so sources and the builder agree on spelling.

2. **The normalised record schema** — one dataclass per record *kind*. Sources
   emit these (as plain dicts via :meth:`Record.to_row`); the builder reads them
   to construct the graph; they persist one-JSON-per-line under a run's
   ``normalized/<kind>.jsonl``.

The load-bearing modelling choice: an **endpoint node is a template**
(``GET /api/users/{id}``), keyed via :func:`core.webgraph.scope.endpoint_id`, so
that the same route hit with different object ids merges onto one node. That is
what makes BOLA analysis a graph query — one endpoint, an ``accessible_as`` edge
per identity, each carrying the observed request/response as evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Dict, List, Optional


# ─────────────────────────── graph vocabulary ───────────────────────────

# Node types — must match the keys of :data:`core.webgraph.graph.TYPES`.
NODE_ORIGIN = "origin"
NODE_PAGE = "page"
NODE_ENDPOINT = "endpoint"
NODE_PARAMETER = "parameter"
NODE_FORM = "form"
NODE_IDENTITY = "identity"
NODE_VULN = "vuln"

NODE_TYPES = (
    NODE_ORIGIN, NODE_PAGE, NODE_ENDPOINT, NODE_PARAMETER,
    NODE_FORM, NODE_IDENTITY, NODE_VULN,
)

# Edge relations — the verb on a directed edge.
REL_HOSTS = "hosts"                  # origin   -> page | endpoint
REL_LINKS_TO = "links_to"            # page     -> page      (hyperlink)
REL_LOADS = "loads"                  # page     -> endpoint  (XHR / fetch / resource)
REL_HAS_FORM = "has_form"            # page     -> form
REL_SUBMITS_TO = "submits_to"        # form     -> endpoint
REL_HAS_PARAM = "has_param"          # endpoint -> parameter
REL_REDIRECTS_TO = "redirects_to"    # endpoint -> endpoint
REL_ACCESSIBLE_AS = "accessible_as"  # identity -> endpoint  (attrs: status, allowed)
REL_VULNERABLE_TO = "vulnerable_to"  # endpoint | parameter -> vuln

EDGE_RELATIONS = (
    REL_HOSTS, REL_LINKS_TO, REL_LOADS, REL_HAS_FORM, REL_SUBMITS_TO,
    REL_HAS_PARAM, REL_REDIRECTS_TO, REL_ACCESSIBLE_AS, REL_VULNERABLE_TO,
)

# Parameter locations.
LOC_QUERY = "query"
LOC_PATH = "path"
LOC_BODY = "body"
LOC_HEADER = "header"
LOC_COOKIE = "cookie"
PARAM_LOCATIONS = (LOC_QUERY, LOC_PATH, LOC_BODY, LOC_HEADER, LOC_COOKIE)

# Finding status — mirrors the api-findings / VerifiedOutcome vocabulary. The
# LLM proposes; a tool/oracle promotes ``suspected`` -> ``confirmed``.
STATUS_CONFIRMED = "confirmed"
STATUS_SUSPECTED = "suspected"
STATUS_RULED_OUT = "ruled_out"

# Proof kinds — how a finding was *verified* (the oracle, not the LLM). These
# are the web-side equivalents of a fuzzer crash: a tool-produced artifact.
PROOF_OAST_CALLBACK = "oast_callback"      # blind class: an out-of-band hit
PROOF_AUTHZ_DIFF = "authz_diff"            # access control: A/B/unauth response diff
PROOF_REFLECTED_MARKER = "reflected_marker"  # injection: our marker came back
PROOF_STATE_ORACLE = "state_oracle"        # business logic/race: observed state violation
PROOF_NONE = ""                            # unverified (suspected only)


# ─────────────────────────── normalised records ─────────────────────────

@dataclass
class Record:
    """Base for every normalised record kind.

    Subclasses set :attr:`KIND` (the ``normalized/<KIND>.jsonl`` stem) and
    declare the schema as fields. :meth:`to_row` returns a JSON-serialisable
    dict. ``KIND`` is a ``ClassVar`` so it never leaks into the row.
    """

    KIND: ClassVar[str] = ""

    def to_row(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OriginRecord(Record):
    """An application origin (``scheme://host[:port]``) that was reached."""

    KIND: ClassVar[str] = "origins"
    origin: str
    title: str = ""
    server: str = ""
    tech: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class PageRecord(Record):
    """A rendered/fetched page (an HTML document at a canonical URL).

    ``rendered`` distinguishes a DOM-aware capture (browser source) from a
    static fetch (HTTP crawler) — the whole reason the browser harness exists is
    that ``rendered=True`` pages expose endpoints the static crawl never sees.
    """

    KIND: ClassVar[str] = "pages"
    url: str
    origin: str = ""
    title: str = ""
    status: Optional[int] = None
    rendered: bool = False
    source: str = ""


@dataclass
class FormRecord(Record):
    """An HTML form on a page: where it submits and the fields it carries."""

    KIND: ClassVar[str] = "forms"
    page_url: str
    action: str = ""
    method: str = "GET"
    fields: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class EndpointRecord(Record):
    """A request target — a *templated* method+path, not a concrete URL.

    ``object_scoped`` / ``privileged`` / ``owasp_focus`` mirror
    :mod:`core.apitest.inventory` so a spec-import source and a live crawl
    populate the same fields. ``auth_required`` is None when unknown.
    """

    KIND: ClassVar[str] = "endpoints"
    method: str
    path: str
    origin: str = ""
    url: str = ""
    status: Optional[int] = None
    content_type: str = ""
    auth_required: Optional[bool] = None
    object_scoped: bool = False
    privileged: bool = False
    owasp_focus: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class ParamRecord(Record):
    """A parameter on an endpoint. ``location`` ∈ :data:`PARAM_LOCATIONS`.

    ``endpoint_id`` is the parent endpoint's node id
    (:func:`core.webgraph.scope.endpoint_id`), so the builder can attach a
    ``has_param`` edge without re-deriving it.
    """

    KIND: ClassVar[str] = "parameters"
    endpoint_id: str
    name: str
    location: str = LOC_QUERY
    example: str = ""
    source: str = ""


@dataclass
class IdentityRecord(Record):
    """A session identity traffic was (or can be) sent as.

    The app-layer answer to recon's bare role strings: a first-class node so
    ``accessible_as`` edges can hang per-identity evidence off an endpoint.
    ``anonymous`` is a valid, un-authenticated identity.
    """

    KIND: ClassVar[str] = "identities"
    name: str
    role: str = ""
    authenticated: bool = False
    source: str = ""


@dataclass
class RequestRecord(Record):
    """A captured request/response pair — the evidence a source observed.

    Rides onto the graph as attributes of the ``identity --accessible_as-->
    endpoint`` edge (status, length, body hash), the same provenance-as-attrs
    discipline recon uses. ``endpoint_id`` + ``identity`` locate the edge;
    ``allowed`` is the source's read of whether access was granted (2xx/3xx to a
    protected route), left None when not assessed.
    """

    KIND: ClassVar[str] = "requests"
    endpoint_id: str
    identity: str = "anonymous"
    method: str = "GET"
    url: str = ""
    status: Optional[int] = None
    resp_len: Optional[int] = None
    body_sha256: str = ""
    allowed: Optional[bool] = None
    source: str = ""


@dataclass
class VulnRecord(Record):
    """A finding. Builds a ``vuln`` node + a ``vulnerable_to`` edge.

    ``status``/``proof_kind`` carry the oracle discipline: a finding is only
    ``confirmed`` when a tool produced a proof (:data:`PROOF_OAST_CALLBACK` etc.);
    otherwise it stays ``suspected``. ``evidence`` is an opaque, oracle-specific
    blob passed straight through to the :class:`VerifiedOutcome` adapter.
    """

    KIND: ClassVar[str] = "vulns"
    id: str
    vuln_class: str
    endpoint_id: str
    param: str = ""
    identity: str = ""
    severity: str = ""
    owasp: str = ""
    status: str = STATUS_SUSPECTED
    proof_kind: str = PROOF_NONE
    evidence: Dict[str, Any] = field(default_factory=dict)
    source: str = ""


# Every concrete record kind, keyed by its ``KIND`` stem. Used to enumerate the
# ``normalized/*.jsonl`` surface and to validate a source's ``produces``.
RECORD_TYPES: Dict[str, type] = {
    cls.KIND: cls
    for cls in (
        OriginRecord, PageRecord, FormRecord, EndpointRecord, ParamRecord,
        IdentityRecord, RequestRecord, VulnRecord,
    )
}

RECORD_KINDS = tuple(RECORD_TYPES.keys())


def normalized_filename(kind: str) -> str:
    """On-disk name for a record kind's JSONL file."""
    return f"{kind}.jsonl"


__all__ = [
    # node types
    "NODE_ORIGIN", "NODE_PAGE", "NODE_ENDPOINT", "NODE_PARAMETER",
    "NODE_FORM", "NODE_IDENTITY", "NODE_VULN", "NODE_TYPES",
    # edge relations
    "REL_HOSTS", "REL_LINKS_TO", "REL_LOADS", "REL_HAS_FORM", "REL_SUBMITS_TO",
    "REL_HAS_PARAM", "REL_REDIRECTS_TO", "REL_ACCESSIBLE_AS", "REL_VULNERABLE_TO",
    "EDGE_RELATIONS",
    # param locations
    "LOC_QUERY", "LOC_PATH", "LOC_BODY", "LOC_HEADER", "LOC_COOKIE",
    "PARAM_LOCATIONS",
    # finding vocabulary
    "STATUS_CONFIRMED", "STATUS_SUSPECTED", "STATUS_RULED_OUT",
    "PROOF_OAST_CALLBACK", "PROOF_AUTHZ_DIFF", "PROOF_REFLECTED_MARKER",
    "PROOF_STATE_ORACLE", "PROOF_NONE",
    # records
    "Record", "OriginRecord", "PageRecord", "FormRecord", "EndpointRecord",
    "ParamRecord", "IdentityRecord", "RequestRecord", "VulnRecord",
    "RECORD_TYPES", "RECORD_KINDS", "normalized_filename",
]
