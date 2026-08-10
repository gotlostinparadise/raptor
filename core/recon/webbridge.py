"""Infra → app bridge: feed discovered origins into the web-graph pipeline.

The recon graph models *infrastructure* (names, IPs, services); the web graph
models the *application* (origins, pages, endpoints, params, identities). This
module is the one-way join between them: it reads the ``http`` records a recon
run produced, derives the in-scope **origins** (scheme + host [+ port]) of the
live HTTP services, and hands those to :func:`core.webgraph.orchestrator.run_webgraph`
so the app-layer graph lands under ``<run>/web/`` in the *same* run directory.
Both graphs then share a lifecycle run dir, so ``/project report``, ``/diagram``,
and ``libexec/raptor-verified-outcomes`` see them together.

Layering: :mod:`core.recon` never imports :mod:`core.webgraph`. This module may —
it is imported only when ``/recon --web`` is requested (the CLI lazy-imports it),
so the app-layer stack is never dragged into a plain infra run.

The ``session`` / ``oast`` parameters are forwarded straight into
``run_webgraph``'s (previously unused) slots. A bare ``/recon --web`` has no
identity config, so it passes ``None``; a caller that has built a
:class:`core.session.SessionEngine` (e.g. via a ``/webauthz`` config) and/or an
:class:`core.oast.OastClient` passes them here to enable authenticated crawl and
out-of-band correlation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, Sequence, Union
from urllib.parse import urlsplit

# Recon → webgraph safety-profile name mapping. Recon profiles gate traffic to
# *infrastructure*; webgraph profiles gate traffic to the *application*. Passive
# stays passive; the two active tiers line up by aggressiveness.
_PROFILE_MAP = {"passive": "passive", "home": "safe", "vps": "aggressive"}


def _origins_from_records(records: dict) -> List[str]:
    """Derive canonical app origins from a recon run's ``http`` records."""
    from core.webgraph.scope import canonical_origin

    origins: List[str] = []
    seen = set()
    for row in records.get("http", []) or []:
        url = row.get("url") or ""
        host = row.get("host") or ""
        seed = url or (f"https://{host}" if host else "")
        if not seed:
            continue
        origin = canonical_origin(seed) or seed
        if origin not in seen:
            seen.add(origin)
            origins.append(origin)
    return origins


def build_web_graph(
    out_dir: Union[str, Path],
    roots: Sequence[str],
    *,
    profile: str = "home",
    authorization: str = "",
    session: Optional[Any] = None,
    oast: Optional[Any] = None,
    extra_origins: Sequence[str] = (),
    include_url_history: bool = False,
    browser: bool = False,
    authz_config: Optional[str] = None,
) -> Any:
    """Build the app-layer graph from a completed recon run's origins.

    Returns the :class:`core.webgraph.orchestrator.RunSummary`. Reads the recon
    run's persisted ``normalized/http.jsonl`` (so it runs after :func:`run_recon`
    or off an existing run dir), derives origins, and writes the web graph under
    ``<out_dir>/web/``. ``authorization`` is threaded through so an active web
    profile inherits the same attestation the recon run was authorized with.

    ``include_url_history`` opts into the passive
    :class:`core.webgraph.url_history.UrlHistorySource` (archive.org endpoint
    mining) — off by default because it contacts a third party; passing origins
    is otherwise the only surface seeded here.
    """
    from core.recon.orchestrator import load_records
    from core.webgraph.orchestrator import run_webgraph

    out = Path(out_dir)
    records = load_records(out / "normalized")
    origins = _origins_from_records(records)
    for o in extra_origins:
        if o and o not in origins:
            origins.append(o)

    web_profile = _PROFILE_MAP.get(profile, "safe")

    # Build a SessionEngine from a /webauthz identity config so the browser crawl
    # runs authenticated (reaching the BOLA/BFLA surface). Only when a config is
    # given and the caller didn't already supply an engine.
    if authz_config and session is None:
        session = _build_session(authz_config, origins)

    # Source selection. ``None`` lets the registered spec/browser sources gate
    # themselves off; but browser crawl and url_history are explicit opt-ins here
    # (url_history is never auto-registered; browser we want deterministically on
    # when asked, seeded with the resolved identity via ctx.session).
    src_list: List[Any] = []
    if browser:
        from core.browser.crawl_source import BrowserCrawlSource
        src_list.append(BrowserCrawlSource())
    if include_url_history:
        from core.webgraph.url_history import UrlHistorySource
        src_list.append(UrlHistorySource())
    sources = src_list or None

    return run_webgraph(
        origins,
        out / "web",
        sources=sources,
        profile=web_profile,
        session=session,
        oast=oast,
    )


def _build_session(authz_config: str, origins: Sequence[str]) -> Optional[Any]:
    """A logged-in :class:`SessionEngine` from a /webauthz config, or ``None``.

    Guarded end to end: a missing file, a parse error, or an absent webauthz
    stack degrades to an anonymous crawl rather than aborting the web build.
    """
    try:
        import os
        from core.http import default_client
        from core.webauthz.config import load_config
        from core.webauthz.runner import build_engine
    except Exception:
        return None
    try:
        cfg = load_config(Path(authz_config))
        hosts = [h for h in (urlsplit(o).hostname for o in origins) if h]
        client = default_client(hosts or None)
        engine, _warnings = build_engine(cfg, client, env=dict(os.environ))
        return engine
    except Exception:
        return None


__all__ = ["build_web_graph"]
