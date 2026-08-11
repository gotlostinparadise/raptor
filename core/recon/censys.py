"""Censys Platform asset enrichment — FREE-TIER compatible.

Design: **enrich known assets, don't search.** The Censys free tier
cannot use the bulk ``/search/query`` endpoint (paid, and it requires an
organization ID). It *can* use the per-asset LOOKUP endpoints with
nothing but an API key::

    GET /v3/global/asset/host/{ip}
    GET /v3/global/asset/certificate/{sha256}
    GET /v3/global/asset/web-property/{id}

So this module takes IPs RAPTOR already discovered (dnsx output, a
project's ``raw/ips.txt``, a scan's host list) and asks Censys what it
has seen there: open ports, service software, ASN/org/geo, and the DNS
names on any TLS certificate served. Cert SANs that fall inside the
target's scope roots are new subdomain surface.

Two non-obvious things are load-bearing — both cost real debugging time
to find, so don't "clean them up":

1. **User-Agent is mandatory.** The Censys API sits behind Cloudflare,
   which 403s (error 1010) the default ``Python-urllib`` UA. Any normal
   client UA passes. :data:`CENSYS_USER_AGENT` is sent on every call.

2. **No organization ID.** Lookups authenticate with
   ``Authorization: Bearer censys_…`` alone. Anything demanding an org
   ID is a paid search endpoint and is out of scope here.

Egress goes through :mod:`core.http` with a one-host allowlist, so a
compromised response parser cannot exfiltrate to an attacker host — the
in-process proxy refuses CONNECT anywhere but Censys.

Credentials never appear in log lines, error strings, or output records.
See :func:`resolve_api_key` for the lookup order. ``CENSYS_API_KEY`` is
deliberately absent from ``RaptorConfig.SAFE_ENV_ALLOWLIST``, so
``get_safe_env()`` strips it from any subprocess environment; this module
makes its calls in-process and never hands the key to a child.

Record schema — see :func:`parse_host` — is stable and documented in
``docs/recon.md``; graph builders consume it as-is.

Two entry points, one implementation. :class:`CensysSource` is the
:mod:`core.recon.source` plugin the orchestrator schedules; the functions
below are the library it wraps, and remain directly usable (that's what
``libexec/raptor-censys`` calls). The plugin adds declarative wiring —
egress hosts, credential vars, record kinds — and normalises the host
records into ``hosts`` / ``ports`` / ``certs``. It does not build graph
edges: the builder does that from the records.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from core.http import HttpClient, HttpError

# --- constants -------------------------------------------------------

CENSYS_HOST = "api.platform.censys.io"
CENSYS_BASE = f"https://{CENSYS_HOST}/v3/global"

# Cloudflare fronts the API and blocks the stdlib default UA (error
# 1010). This value is not decorative — see module docstring.
CENSYS_USER_AGENT = "raptor-recon/1.0 (+censys-platform)"

# Free tier is rate-limited hard. Serialise lookups and pace them; the
# retry/backoff/circuit-breaker in core.http handles 429s on top of this.
FREE_TIER_DELAY_SECONDS = 0.6

# Per-call cap. Host lookups are a few KB; anything vastly larger is a
# server-side anomaly, not data we want to parse.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# Credential file locations, tried in order after the environment.
# ``API_KEY="censys_…"`` — the shell-sourceable form already in use.
_CRED_ENV_VAR = "CENSYS_API_KEY"
_CRED_PATH_ENV_VAR = "RAPTOR_CENSYS_CREDENTIALS"
_CRED_BASENAME = ".censys"
_CRED_RE = re.compile(r'^\s*(?:export\s+)?API_KEY\s*=\s*"?([^"\n]+?)"?\s*$', re.M)


class MissingCredential(Exception):
    """No Censys API key could be resolved.

    The message lists *where* we looked, never *what* we found.
    """


# --- credentials -----------------------------------------------------

def _credential_candidates(explicit: Optional[Path] = None) -> List[Path]:
    """Ordered credential-file candidates. Pure; no filesystem access."""
    candidates: List[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    from_env = os.environ.get(_CRED_PATH_ENV_VAR)
    if from_env:
        candidates.append(Path(from_env))
    # RAPTOR_DIR is the installation root. Read only if the launcher set
    # it — this module never guesses a path and never falls back to cwd.
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir:
        candidates.append(Path(raptor_dir) / _CRED_BASENAME)
    candidates.append(Path.home() / ".config" / "raptor" / "censys")
    return candidates


def resolve_api_key(explicit_path: Optional[Path] = None) -> str:
    """Return the Censys API key, or raise :class:`MissingCredential`.

    Resolution order:

    1. ``CENSYS_API_KEY`` in the environment.
    2. ``RAPTOR_CENSYS_CREDENTIALS`` → path to a credentials file
       (or ``explicit_path``, which takes precedence over both files
       and is how the libexec shim passes the repo-root ``.censys``).
    3. ``$RAPTOR_DIR/.censys`` when ``RAPTOR_DIR`` is set.
    4. ``~/.config/raptor/censys``.

    Files hold a single ``API_KEY="censys_…"`` line. The returned value
    is never logged; callers must keep it out of records and messages.
    """
    from_env = (os.environ.get(_CRED_ENV_VAR) or "").strip()
    if from_env:
        return from_env

    candidates = _credential_candidates(explicit_path)
    for path in candidates:
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Unreadable candidate (permissions, race) is not fatal —
            # fall through to the next one. Never surface the content.
            continue
        match = _CRED_RE.search(text)
        if match:
            key = match.group(1).strip()
            if key:
                return key

    looked_in = ", ".join(str(p) for p in candidates)
    raise MissingCredential(
        f"No Censys API key. Set ${_CRED_ENV_VAR}, or write "
        f'API_KEY="censys_…" to one of: {looked_in}'
    )


# --- client ----------------------------------------------------------

def default_client(user_agent: str = CENSYS_USER_AGENT) -> HttpClient:
    """HttpClient for Censys — egress-allowlisted to Censys only.

    Routes through the in-process proxy at :mod:`core.sandbox.proxy`
    with a single-host allowlist. Tests inject their own HttpClient
    into :class:`CensysClient` instead of calling this, so they never
    start a proxy.
    """
    from core.http.egress_backend import EgressClient
    return EgressClient([CENSYS_HOST], user_agent=user_agent)


class CensysClient:
    """Thin wrapper over the Censys Platform per-asset lookup endpoints.

    ``http`` is any :class:`core.http.HttpClient`; omit it for the
    egress-allowlisted default. ``api_key`` is held only in the
    Authorization header we build per call — it is never stored on the
    record, logged, or interpolated into an error message.
    """

    def __init__(
        self,
        api_key: str,
        http: Optional[HttpClient] = None,
        *,
        base_url: str = CENSYS_BASE,
        user_agent: str = CENSYS_USER_AGENT,
        timeout: int = 30,
    ) -> None:
        if not api_key:
            raise MissingCredential("CensysClient requires a non-empty API key")
        self._api_key = api_key
        self._http = http if http is not None else default_client(user_agent)
        self._base_url = base_url.rstrip("/")
        self._user_agent = user_agent
        self._timeout = timeout
        # Last HTTP-layer failure, for status reporting. Never contains
        # the key: core.http messages carry a sanitised URL only.
        self.last_error: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            # Re-sent per call as well as being the client default: the
            # Cloudflare 403 is silent and confusing, and a caller may
            # pass in an HttpClient built with some other UA.
            "User-Agent": self._user_agent,
        }

    def _lookup(self, path: str) -> Optional[Dict[str, Any]]:
        """GET ``{base}/{path}``; return the decoded body or None.

        Returns None rather than raising for *any* HTTP-layer failure —
        403 (no entitlement / blocked UA), 404 (asset unknown to
        Censys), 429 (rate limit, already retried by core.http). One
        dead asset must not abort enrichment of the rest.
        """
        url = f"{self._base_url}/{path}"
        try:
            return self._http.get_json(
                url,
                timeout=self._timeout,
                headers=self._headers(),
                max_bytes=MAX_RESPONSE_BYTES,
            )
        except HttpError as exc:
            # core.http never logs request headers and puts only a
            # sanitised URL in its messages, so this cannot leak the
            # key — but we still keep the record of it to the status.
            self.last_error = f"{type(exc).__name__}: {exc}"
            return None

    def lookup_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Host asset: ports, services, software, certs, whois, geo."""
        return self._lookup(f"asset/host/{_path_segment(ip)}")

    def lookup_certificate(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Certificate asset by SHA-256 fingerprint."""
        return self._lookup(f"asset/certificate/{_path_segment(sha256)}")

    def lookup_web_property(self, web_property_id: str) -> Optional[Dict[str, Any]]:
        """Web-property asset (``host:port`` style identifier)."""
        return self._lookup(f"asset/web-property/{_path_segment(web_property_id)}")


def _path_segment(value: str) -> str:
    """Percent-encode a caller-supplied path segment.

    Asset identifiers reach us from run artifacts (``raw/ips.txt`` and
    friends), which are only as clean as the tool that wrote them. A
    stray ``../`` or space would otherwise reshape the request URL.
    """
    from urllib.parse import quote
    return quote(str(value).strip(), safe="")


# --- parsing ---------------------------------------------------------

def _resource(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Unwrap ``result.resource``, tolerating the flatter shape."""
    result = payload.get("result") or {}
    if isinstance(result, dict):
        resource = result.get("resource")
        if isinstance(resource, dict):
            return resource
        return result
    return {}


def _software_name(service: Dict[str, Any]) -> Optional[str]:
    """First product (or vendor) Censys attributes to the service."""
    for entry in (service.get("software") or []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("product") or entry.get("vendor")
        if name:
            return name
    return None


def _certificate_names(service: Dict[str, Any]) -> List[str]:
    """DNS names on the service's TLS leaf certificate.

    Censys has shipped several shapes for this over the life of the
    Platform API; accept the ones observed in the wild rather than
    binding to one and silently returning nothing when it moves.
    """
    tls = service.get("tls") or service.get("certificate") or {}
    if not isinstance(tls, dict):
        return []
    certificates = tls.get("certificates")
    leaf = {}
    if isinstance(certificates, dict):
        leaf = certificates.get("leaf_data") or {}
    if not isinstance(leaf, dict) or not leaf:
        leaf = tls.get("leaf_data") if isinstance(tls.get("leaf_data"), dict) else {}
    names = (leaf or {}).get("names") or tls.get("names") or []
    if not isinstance(names, list):
        return []
    return [str(n) for n in names if n]


def normalise_name(name: str) -> str:
    """Lowercase a DNS name and strip a leading wildcard label."""
    return str(name).strip().lower().lstrip("*").lstrip(".")


def in_scope(name: str, domains: Sequence[str]) -> bool:
    """True when ``name`` is one of ``domains`` or a subdomain of one.

    Suffix matching is label-aware on purpose: a bare
    ``name.endswith(domain)`` also matches ``notbitpapa.com`` for
    ``bitpapa.com`` and would inject out-of-scope hosts into the graph.
    """
    for domain in domains:
        domain = normalise_name(domain)
        if not domain:
            continue
        if name == domain or name.endswith("." + domain):
            return True
    return False


def parse_host(
    payload: Dict[str, Any],
    ip: str,
    domains: Sequence[str] = (),
) -> Tuple[Dict[str, Any], List[str]]:
    """Turn a host-lookup payload into a record plus its in-scope names.

    Returns ``(record, names)`` where ``record`` is the stable schema::

        {
          "ip": str,
          "services": [{"port": int|None,
                        "proto": str|None,
                        "software": str|None}],
          "names": [str],              # in-scope cert names on this host
          "asn": int|None,
          "org": str|None,
          "country": str|None,
          "city": str|None,
          "presents_domain_cert": bool # a real in-scope leaf cert here
        }

    and ``names`` is the same in-scope list, returned separately so
    callers can union across hosts without re-walking the records.
    """
    resource = _resource(payload)
    services: List[Dict[str, Any]] = []
    host_names: set = set()

    for service in (resource.get("services") or []):
        if not isinstance(service, dict):
            continue
        services.append({
            "port": service.get("port"),
            "proto": service.get("protocol") or service.get("transport_protocol"),
            "software": _software_name(service),
        })
        for raw_name in _certificate_names(service):
            name = normalise_name(raw_name)
            if name and in_scope(name, domains):
                host_names.add(name)

    autonomous_system = resource.get("autonomous_system") or {}
    whois_org = (resource.get("whois") or {}).get("organization") or {}
    location = resource.get("location") or {}

    names = sorted(host_names)
    record = {
        "ip": resource.get("ip") or ip,
        "services": services,
        "names": names,
        "asn": autonomous_system.get("asn"),
        "org": autonomous_system.get("name") or whois_org.get("name"),
        "country": location.get("country"),
        # Censys reports city alongside country; the model's HostRecord
        # carries it too (ipinfo populates the same field), so emitting
        # it keeps the two sources mergeable.
        "city": location.get("city"),
        # Only true when Censys observed a leaf cert for an in-scope
        # name here — this is what promotes an IP to "origin candidate".
        "presents_domain_cert": bool(names),
    }
    return record, names


# --- enrichment ------------------------------------------------------

@dataclass
class EnrichmentResult:
    """Outcome of a host-enrichment pass."""

    hosts: List[Dict[str, Any]] = field(default_factory=list)
    names: List[str] = field(default_factory=list)
    requested: int = 0
    failed: List[str] = field(default_factory=list)

    @property
    def service_count(self) -> int:
        return sum(len(h["services"]) for h in self.hosts)


def enrich_hosts(
    ips: Iterable[str],
    domains: Sequence[str] = (),
    *,
    client: Optional[CensysClient] = None,
    api_key: Optional[str] = None,
    delay: float = FREE_TIER_DELAY_SECONDS,
    sleep = time.sleep,
) -> EnrichmentResult:
    """Look up every IP and return records plus the union of cert names.

    Serial by design: the free tier will not tolerate concurrency, and
    the whole point of this module is that it works on the free tier.
    ``delay`` seconds are slept between lookups (including after a
    failed one — a 403 storm should back off, not spin).

    ``client`` is the injection seam for tests. Otherwise a client is
    built from ``api_key`` (or the resolved credential).
    """
    if client is None:
        client = CensysClient(api_key or resolve_api_key())

    result = EnrichmentResult()
    all_names: set = set()

    for raw_ip in ips:
        ip = str(raw_ip).strip()
        if not ip:
            continue
        result.requested += 1
        payload = client.lookup_host(ip)
        if payload is None:
            result.failed.append(ip)
            if delay:
                sleep(delay)
            continue
        record, names = parse_host(payload, ip, domains)
        result.hosts.append(record)
        all_names.update(names)
        if delay:
            sleep(delay)

    result.names = sorted(all_names)
    return result


# --- output ----------------------------------------------------------

def iter_jsonl(records: Iterable[Dict[str, Any]]) -> Iterator[str]:
    """Serialise records as JSONL lines (newline included)."""
    for record in records:
        yield json.dumps(record, sort_keys=True) + "\n"


def write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> int:
    """Write ``records`` as JSONL; return the number of records."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for line in iter_jsonl(records):
            handle.write(line)
            count += 1
    return count


def read_ips(path: Path) -> List[str]:
    """Read one IP per line, ignoring blanks and ``#`` comments."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    ips: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)
    return ips


# --- source plugin ---------------------------------------------------

from core.recon.model import CertRecord, HostRecord, PortRecord  # noqa: E402
from core.recon.source import (  # noqa: E402
    RunContext, Source, SourceResult, register,
)


@register
class CensysSource(Source):
    """Censys as a scheduled recon source.

    Passive: every request goes to Censys, never to the target, so this
    runs in all safety profiles including ``passive``.

    Emits ``hosts`` (ASN/org/geo), ``ports`` (one per observed service)
    and ``certs`` (in-scope names on served leaf certificates). Cert
    names also go into ``discovered.names`` — a SAN inside scope is new
    subdomain surface, so the discovery loop gets another pass at it.
    The raw lookup records are still written verbatim to
    ``raw/censys-hosts.jsonl`` for provenance.
    """

    name = "censys"
    egress_hosts = (CENSYS_HOST,)
    credential_env_vars = (_CRED_ENV_VAR,)
    consumes = ("ips",)
    produces = ("hosts", "ports", "certs")
    active = False

    #: Seconds between lookups. The free tier needs the pace; a paid key
    #: (or a test) can lower it. Instance-settable, not a constant, so
    #: nothing has to monkeypatch time.sleep to run this source fast.
    delay: float = FREE_TIER_DELAY_SECONDS

    def _resolve_key(self, ctx: RunContext) -> Optional[str]:
        """Orchestrator-supplied credential, else the on-disk fallback.

        The base ``has_credentials`` only consults ``ctx.credentials``,
        which would make the file-based key invisible to the scheduler:
        an operator with a working ``$RAPTOR_DIR/.censys`` and no
        exported env var would see Censys silently skipped as
        "unavailable". Checking both here keeps the declarative
        contract and the documented credential order in agreement.
        """
        from_ctx = ctx.credential(_CRED_ENV_VAR)
        if from_ctx:
            return from_ctx
        try:
            return resolve_api_key()
        except MissingCredential:
            return None

    def has_credentials(self, ctx: RunContext) -> bool:
        return self._resolve_key(ctx) is not None

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)

        key = self._resolve_key(ctx)
        if key is None:
            # Reachable when the orchestrator runs a source without
            # consulting available() first. Report, don't raise — one
            # unconfigured source must not abort the pipeline.
            result.error = "no Censys API key configured"
            return result

        client = CensysClient(key, http=ctx.http_client(self))
        # Sorted, not raw set order: lookups are paced and serial, so a
        # nondeterministic order makes runs hard to compare and partial
        # results hard to resume.
        enrichment = enrich_hosts(sorted(ctx.assets.ips), ctx.roots,
                                  client=client, delay=self.delay)

        result.requested = enrichment.requested
        result.failed = list(enrichment.failed)

        for host in enrichment.hosts:
            ip = host["ip"]
            result.add(HostRecord(
                ip=ip,
                asn=(f"AS{host['asn']}" if host.get("asn") else ""),
                org=host.get("org") or "",
                country=host.get("country") or "",
                city=host.get("city") or "",
            ))
            for service in host["services"]:
                if not service.get("port"):
                    continue
                result.add(PortRecord(
                    ip=ip,
                    port=service["port"],
                    proto=service.get("proto") or "",
                    software=service.get("software") or "",
                    source=self.name,
                ))
            if host["names"]:
                result.add(CertRecord(
                    source=self.name, names=list(host["names"]), ip=ip,
                ))
                # Feeds the discovery loop: these are subdomains we did
                # not know about before this lookup.
                result.discovered.names.update(host["names"])
            result.discovered.ips.add(ip)

        raw = ctx.raw_path("censys-hosts.jsonl")
        write_jsonl(raw, enrichment.hosts)
        result.raw_path = raw
        return result


__all__ = [
    "CENSYS_BASE",
    "CENSYS_HOST",
    "CENSYS_USER_AGENT",
    "CensysClient",
    "CensysSource",
    "EnrichmentResult",
    "FREE_TIER_DELAY_SECONDS",
    "MissingCredential",
    "default_client",
    "enrich_hosts",
    "in_scope",
    "iter_jsonl",
    "normalise_name",
    "parse_host",
    "read_ips",
    "resolve_api_key",
    "write_jsonl",
]
