"""Source-plugin interface for the web-graph pipeline.

The application-layer analogue of :mod:`core.recon.source`. A *web source* takes
the surface a run already knows about (in-scope origins, discovered URLs and
endpoints) and produces normalised records plus any newly discovered surface.
Every source — a static HTTP crawl, a DOM-aware browser crawl, an API-spec
import, a proxy capture — implements the same small contract, so the
orchestrator can schedule them uniformly and adding a source is one file.

The contract mirrors recon's exactly:

  - **Declare your egress.** :attr:`Source.egress_hosts` lists every host the
    source may reach; the framework hands it an allowlisted
    :class:`~core.http.HttpClient`. A source that drives a subprocess/browser
    instead leaves this empty and arranges its own sandboxed egress.
  - **Declare your secrets.** :attr:`Source.credential_env_vars` names the env
    vars holding the source's credentials (e.g. an OAST server token).
  - **Declare your traffic.** :attr:`Source.active` marks sources that send
    traffic to the *target application*. The WAF-aware :class:`Profile` gates
    these — the ``passive`` profile runs none.
  - **Declare your I/O.** :attr:`Source.consumes` / :attr:`Source.produces` name
    the surface kinds the source reads and the record kinds it writes.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any, Callable, ClassVar, Dict, List, Mapping, Optional, Sequence, Set, Tuple,
    Type, TYPE_CHECKING,
)

from core.webgraph.model import RECORD_KINDS, normalized_filename

if TYPE_CHECKING:  # avoid importing the http stack at module import time
    from core.http import HttpClient


# ─────────────────────────── surface ───────────────────────────

@dataclass
class Surface:
    """The application surface a run knows about — source input and the fixed
    point of the discovery loop.

    Only identity-bearing sets live here (origins, canonical URLs, endpoint
    ids); attributes hang off the graph, not this container. The orchestrator
    diffs a :class:`Surface` before and after a round to decide whether another
    crawl pass could find anything new.
    """

    origins: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)   # endpoint node ids

    def merge(self, other: "Surface") -> "Surface":
        """Union ``other`` into ``self`` in place; return ``self``."""
        self.origins |= other.origins
        self.urls |= other.urls
        self.endpoints |= other.endpoints
        return self

    def copy(self) -> "Surface":
        return Surface(set(self.origins), set(self.urls), set(self.endpoints))

    def __len__(self) -> int:
        return len(self.origins) + len(self.urls) + len(self.endpoints)

    def __bool__(self) -> bool:
        return len(self) > 0


# ─────────────────────────── safety profiles ───────────────────────────

@dataclass(frozen=True)
class Profile:
    """A WAF-/target-safety envelope for a web run.

    The app-layer counterpart to recon's :class:`~core.recon.source.Profile`.
    ``allow_active`` gates whether any source may send traffic to the target
    application at all; ``knobs`` carry the rate/concurrency ceiling and the
    WAF-evasion switch that active sources read straight off the profile.
    """

    name: str
    allow_active: bool
    knobs: Mapping[str, Any] = field(default_factory=dict)


# The named profiles. Rates are deliberately conservative — the lesson from
# recon (concurrency, not raw count, is what trips defences) applies double to a
# WAF, which rate-limits and fingerprints aggressive scanners.
PROFILES: Dict[str, Profile] = {
    # Zero traffic to the target application. Spec-import / offline analysis only.
    "passive": Profile(name="passive", allow_active=False),
    # Authorised, throttled active testing. The safe default for a real engagement.
    "safe": Profile(
        name="safe", allow_active=True,
        knobs={"rps": 5, "concurrency": 4, "waf_evasion": False,
               "max_pages": 500, "max_depth": 6},
    ),
    # Louder: higher rate + payload encoding/mutation to probe a WAF. Opt-in.
    "aggressive": Profile(
        name="aggressive", allow_active=True,
        knobs={"rps": 20, "concurrency": 10, "waf_evasion": True,
               "max_pages": 2000, "max_depth": 10},
    ),
}

DEFAULT_PROFILE = "safe"


# ─────────────────────────── run context ───────────────────────────

@dataclass
class RunContext:
    """Everything a web source needs to run, handed in by the orchestrator.

    Sources never reach into global state — the run directory, the current
    surface, the safety profile, credentials, the HTTP factory, and the optional
    session / OAST handles all arrive here, which is what makes a source
    unit-testable with a stub context.
    """

    origins: Tuple[str, ...]
    surface: Surface
    profile: Profile
    raw_dir: Path
    normalized_dir: Path
    env: Mapping[str, str] = field(default_factory=dict)
    credentials: Mapping[str, str] = field(default_factory=dict)
    http_factory: Optional[Callable[[Sequence[str]], "HttpClient"]] = None
    # Optional shared primitives, injected when available (A2/A3). Typed Any to
    # avoid an import cycle; a source feature-detects rather than assuming.
    session: Optional[Any] = None   # core.session.SessionEngine
    oast: Optional[Any] = None      # core.oast.OastClient

    def http_client(self, source: "Source") -> "HttpClient":
        """An HttpClient allowlisted to ``source``'s declared egress hosts."""
        hosts = list(source.egress_hosts)
        if self.http_factory is not None:
            return self.http_factory(hosts)
        from core.http import default_client
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
    """What a source returns: normalised records + newly discovered surface."""

    source: str
    records: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    discovered: Surface = field(default_factory=Surface)
    raw_path: Optional[Path] = None
    requested: int = 0
    failed: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def add(self, record: Any) -> None:
        """Append a :class:`~core.webgraph.model.Record` (or a ``(kind, row)``)."""
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
    """Base class for every web source. See the module docstring for the
    contract. Subclasses set the class attributes and implement :meth:`run`."""

    #: Unique, stable identifier (also the registry key, e.g. ``"http_crawl"``).
    name: ClassVar[str] = ""
    #: Hosts this source may reach over HTTP. Empty ⇒ makes no direct HTTP calls.
    egress_hosts: ClassVar[Tuple[str, ...]] = ()
    #: Environment variables holding this source's credential(s).
    credential_env_vars: ClassVar[Tuple[str, ...]] = ()
    #: Surface kinds consumed: subset of {"origins", "urls", "endpoints"}.
    consumes: ClassVar[Tuple[str, ...]] = ()
    #: Record kinds produced: subset of :data:`core.webgraph.model.RECORD_KINDS`.
    produces: ClassVar[Tuple[str, ...]] = ()
    #: True if the source sends traffic to the *target application*.
    active: ClassVar[bool] = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
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

        Override to add dependency checks (e.g. Playwright is importable).
        """
        return self.enabled_for(ctx.profile) and self.has_credentials(ctx)

    @abc.abstractmethod
    def run(self, ctx: RunContext) -> SourceResult:
        """Do the work; return normalised records + discovered surface."""
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
    """Union of every registered source's declared credential env vars."""
    out: Set[str] = set()
    for cls in _REGISTRY.values():
        out.update(cls.credential_env_vars)
    return frozenset(out)


__all__ = [
    "Surface", "Profile", "PROFILES", "DEFAULT_PROFILE", "RunContext",
    "SourceResult", "Source", "register", "unregister", "get_source",
    "all_sources", "registered_credential_env_vars",
]
