"""Source-plugin interface for the recon pipeline.

A *source* takes the assets a run already knows about (scope roots, resolved
names, IPs, certificate hashes) and produces normalised records plus any newly
discovered assets. Every source — a passive API lookup (crt.sh, Censys,
Shodan), an active DNS/HTTP tool wrapper (dnsx, httpx, naabu), or a bespoke
probe (exposed-origin, vhost) — implements the same small contract, so the
orchestrator can schedule them uniformly and adding a source is one file.

The contract, in one place:

  - **Declare your egress.** :attr:`Source.egress_hosts` lists every host the
    source may reach. The framework hands the source an
    :class:`~core.http.HttpClient` already allowlisted to exactly those hosts
    (via the in-process proxy), so a compromised response parser cannot
    exfiltrate anywhere else. A source that shells out to a tool instead of
    making HTTP calls leaves this empty.
  - **Declare your secrets.** :attr:`Source.credential_env_vars` names the
    environment variables holding the source's API keys. This drives two
    things: the framework resolves those values and passes them in (in-process,
    never to a child), and a single conformance test iterates every source's
    declared vars to assert none of them leak into ``get_safe_env()``.
  - **Declare your traffic.** :attr:`Source.active` marks sources that send
    traffic to the *target's own* infrastructure (DNS bruteforce, port scans,
    HTTP probes). The safety :class:`Profile` gates these — the ``passive``
    profile runs none of them.
  - **Declare your I/O.** :attr:`Source.consumes` / :attr:`Source.produces`
    name the asset kinds the source reads and the record kinds it writes.

Ports over ``run.sh``'s implicit stage chain: there, each stage's inputs,
outputs, and safety knobs lived in shell comments. Here they're declared
attributes the orchestrator can read.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any, Callable, ClassVar, Dict, List, Mapping, Optional, Sequence, Set, Tuple,
    Type, TYPE_CHECKING,
)

from core.recon.model import RECORD_KINDS, normalized_filename

if TYPE_CHECKING:  # avoid importing the http stack at module import time
    from core.http import HttpClient


# ─────────────────────────── assets ───────────────────────────

@dataclass
class Assets:
    """The set of things a run knows about, used as source input and as the
    fixed point of the discovery loop.

    Only identity-bearing sets live here (names, IPs, cert fingerprints);
    attributes hang off the graph, not this container. The orchestrator diffs
    an :class:`Assets` before and after a round to decide whether another
    recursion pass could find anything new.
    """

    names: Set[str] = field(default_factory=set)   # in-scope hostnames (roots + subs)
    ips: Set[str] = field(default_factory=set)
    certs: Set[str] = field(default_factory=set)   # certificate SHA-256 fingerprints

    def merge(self, other: "Assets") -> "Assets":
        """Union ``other`` into ``self`` in place; return ``self``."""
        self.names |= other.names
        self.ips |= other.ips
        self.certs |= other.certs
        return self

    def copy(self) -> "Assets":
        return Assets(set(self.names), set(self.ips), set(self.certs))

    def __len__(self) -> int:
        return len(self.names) + len(self.ips) + len(self.certs)

    def __bool__(self) -> bool:
        return len(self) > 0


# ─────────────────────────── safety profiles ───────────────────────────

@dataclass(frozen=True)
class Profile:
    """A router-/target-safety envelope for a run.

    Encodes the hard-won lesson from the prototype that concurrency and
    resolver fan-out — not raw request count — are what exhaust a home
    router's NAT table. The knobs here are consumed by the active source
    wrappers (Phase 2/3); the two booleans gate *which* sources may run at all.
    """

    name: str
    allow_active: bool          # may any source touch the target's infra?
    allow_massdns: bool = False  # may heavy resolver fan-out run? (VPS only)
    knobs: Mapping[str, Any] = field(default_factory=dict)


# The three named profiles. Knob values carry the enum-lite.sh / deep-enum.sh
# settings so active wrappers can read them straight off the profile.
PROFILES: Dict[str, Profile] = {
    # Zero traffic to the target. Passive third-party sources only.
    "passive": Profile(name="passive", allow_active=False, allow_massdns=False),
    # Home-network-safe active enum: dnsx-only, hard rate cap, few resolvers,
    # no massdns fan-out (the enum-lite.sh envelope).
    "home": Profile(
        name="home", allow_active=True, allow_massdns=False,
        knobs={"dns_rate": 300, "dns_threads": 25, "resolvers": 5,
               "perm_cap": 15000, "http_rate": 10},
    ),
    # VPS-grade: massdns/shuffledns permitted, still throttled off the
    # flood-a-home-router defaults (the deep-enum.sh envelope).
    "vps": Profile(
        name="vps", allow_active=True, allow_massdns=True,
        knobs={"dns_rate": 300, "dns_threads": 100, "massdns_threads": 500,
               "massdns_interval_ms": 15, "wildcard_threads": 50},
    ),
}

DEFAULT_PROFILE = "home"


# ─────────────────────────── run context ───────────────────────────

@dataclass
class RunContext:
    """Everything a source needs to run, handed in by the orchestrator.

    Sources never reach into global state — the run directory, the current
    asset set, the safety profile, credentials and the HTTP factory all arrive
    here, which is what makes a source unit-testable with a stub context.
    """

    roots: Tuple[str, ...]
    assets: Assets
    profile: Profile
    raw_dir: Path
    normalized_dir: Path
    # Sanitised environment for subprocess-based (tool-wrapper) sources.
    env: Mapping[str, str] = field(default_factory=dict)
    # Resolved credential values keyed by env-var name. Populated in-process by
    # the trusted orchestrator; never exported to a child environment.
    credentials: Mapping[str, str] = field(default_factory=dict)
    # Injection seam for tests: build an HttpClient for the given allowlist.
    # Defaults to core.http.default_client (EgressClient when hosts given).
    http_factory: Optional[Callable[[Sequence[str]], "HttpClient"]] = None

    def http_client(self, source: "Source") -> "HttpClient":
        """An HttpClient allowlisted to ``source``'s declared egress hosts."""
        hosts = list(source.egress_hosts)
        if self.http_factory is not None:
            return self.http_factory(hosts)
        from core.http import default_client
        # default_client(None) -> unrestricted UrllibClient; only reached when a
        # source declares no egress hosts (i.e. doesn't make HTTP calls).
        return default_client(hosts or None)

    def credential(self, env_var: str) -> Optional[str]:
        """Resolved value of a declared credential var, or ``None``."""
        return self.credentials.get(env_var) or None

    def raw_path(self, name: str) -> Path:
        """Path for a source's verbatim provenance file under ``raw/``."""
        return self.raw_dir / name

    def normalized_path(self, kind: str) -> Path:
        """Path for a record kind's ``normalized/<kind>.jsonl``."""
        return self.normalized_dir / normalized_filename(kind)


# ─────────────────────────── source result ───────────────────────────

@dataclass
class SourceResult:
    """What a source returns: normalised records + newly discovered assets.

    ``records`` maps a record *kind* (``"hosts"``, ``"ports"``, …) to the list
    of JSON-serialisable rows the source produced. ``discovered`` is the assets
    that were new this run, fed back into the discovery loop. ``failed`` and
    ``error`` capture partial/whole failure without aborting the pipeline.
    """

    source: str
    records: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    discovered: Assets = field(default_factory=Assets)
    raw_path: Optional[Path] = None
    requested: int = 0
    failed: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def add(self, record: Any) -> None:
        """Append a :class:`~core.recon.model.Record` (or a ``(kind, row)``).

        Accepts a Record instance (uses its ``KIND``/``to_row``) or an explicit
        ``(kind, dict)`` pair for callers that already have a plain row.
        """
        if isinstance(record, tuple):
            kind, row = record
        else:
            kind, row = record.KIND, record.to_row()
        if kind not in RECORD_KINDS:
            raise ValueError(f"unknown record kind: {kind!r}")
        self.records.setdefault(kind, []).append(row)

    def record_count(self) -> int:
        return sum(len(rows) for rows in self.records.values())


# ─────────────────────────── source base ───────────────────────────

class Source(abc.ABC):
    """Base class for every recon source. See the module docstring for the
    contract. Subclasses set the class attributes and implement :meth:`run`."""

    #: Unique, stable identifier (also the registry key, e.g. ``"crtsh"``).
    name: ClassVar[str] = ""
    #: Hosts this source may reach over HTTP. Empty ⇒ makes no HTTP calls.
    egress_hosts: ClassVar[Tuple[str, ...]] = ()
    #: Environment variables holding this source's API key(s).
    credential_env_vars: ClassVar[Tuple[str, ...]] = ()
    #: Asset kinds consumed: subset of {"roots", "names", "ips", "certs"}.
    consumes: ClassVar[Tuple[str, ...]] = ()
    #: Record kinds produced: subset of :data:`core.recon.model.RECORD_KINDS`.
    produces: ClassVar[Tuple[str, ...]] = ()
    #: True if the source sends traffic to the *target's* own infrastructure.
    active: ClassVar[bool] = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Validate the declared ``produces`` early — a typo here would silently
        # drop records at write time otherwise. ``name`` is validated at
        # registration (fakes/abstract intermediates needn't set it).
        bad = [k for k in cls.produces if k not in RECORD_KINDS]
        if bad:
            raise ValueError(
                f"{cls.__name__}.produces has unknown record kinds: {bad}"
            )

    def enabled_for(self, profile: Profile) -> bool:
        """Whether the safety ``profile`` permits this source to run at all."""
        return (not self.active) or profile.allow_active

    def has_credentials(self, ctx: RunContext) -> bool:
        """Whether every declared credential var resolved to a value."""
        return all(ctx.credential(v) for v in self.credential_env_vars)

    def available(self, ctx: RunContext) -> bool:
        """Default readiness: profile permits it and its credentials resolved.

        Override to add dependency checks (e.g. the wrapped binary is on PATH).
        """
        return self.enabled_for(ctx.profile) and self.has_credentials(ctx)

    @abc.abstractmethod
    def run(self, ctx: RunContext) -> SourceResult:
        """Do the work; return normalised records + discovered assets."""
        raise NotImplementedError


# ─────────────────────────── registry ───────────────────────────

_REGISTRY: Dict[str, Type[Source]] = {}


def register(cls: Type[Source]) -> Type[Source]:
    """Class decorator: add a concrete source to the registry by ``name``."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set a non-empty class attr 'name'")
    existing = _REGISTRY.get(cls.name)
    if existing is not None and existing is not cls:
        raise ValueError(
            f"source name {cls.name!r} already registered to {existing.__name__}"
        )
    _REGISTRY[cls.name] = cls
    return cls


def unregister(name: str) -> None:
    """Remove a source from the registry (test hygiene; no-op if absent)."""
    _REGISTRY.pop(name, None)


def get_source(name: str) -> Type[Source]:
    """Look up a registered source class by name; raise ``KeyError`` if absent."""
    return _REGISTRY[name]


def all_sources() -> Dict[str, Type[Source]]:
    """A name→class snapshot of the registry, sorted by name."""
    return dict(sorted(_REGISTRY.items()))


def registered_credential_env_vars() -> frozenset:
    """Union of every registered source's declared credential env vars.

    The security conformance test iterates this to assert no recon credential
    can leak through :func:`core.config.RaptorConfig.get_safe_env`.
    """
    out: Set[str] = set()
    for cls in _REGISTRY.values():
        out.update(cls.credential_env_vars)
    return frozenset(out)


__all__ = [
    "Assets", "Profile", "PROFILES", "DEFAULT_PROFILE", "RunContext",
    "SourceResult", "Source", "register", "unregister", "get_source",
    "all_sources", "registered_credential_env_vars",
]
