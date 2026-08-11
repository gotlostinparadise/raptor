"""DOM-aware crawl as a web-graph source — the browser's counterpart to a
static HTTP crawl.

A :class:`~core.webgraph.source.Source` (``active``, gated by the safety profile
+ authorization) that drives the headless browser over an application's
same-origin pages, letting each render fully before harvesting links, forms, and
the runtime XHR/fetch endpoints a static crawler can't see. Everything it finds
lands on the same ``(type, id)`` graph nodes as the spec import — that is the
connective-tissue payoff.

Egress: by default the source constrains the browser to the hostnames of the
run's in-scope origins via the egress proxy. ``allow_unproxied`` (loopback
fixtures, explicit opt-out) skips that; a remote navigation without either is
refused by the session.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import urlsplit

from core.browser import harness as _harness
from core.browser.auth import context_args_for_identity, resolve_identity
from core.browser.capture import records_from_capture
from core.webgraph.model import IdentityRecord
from core.webgraph.scope import (
    canonical_origin, canonical_url, fragment_route, in_scope,
)
from core.webgraph.source import RunContext, Source, SourceResult, Surface, register


def _hosts_of(origins: Sequence[str]) -> List[str]:
    out: List[str] = []
    for o in origins:
        host = urlsplit(canonical_origin(o) or o).hostname
        if host and host not in out:
            out.append(host)
    return out


def _visit_key(url: str) -> str:
    """Dedup key that keeps SPA hash-routes distinct.

    ``canonical_url`` folds the fragment away, so ``/#/search`` and ``/#/about``
    would collapse onto the base page and never be crawled. Appending the route
    keeps them separate (``…#/search`` ≠ ``…#/about`` ≠ base) so each renders.
    """
    base = canonical_url(url) or url
    fr = fragment_route(url)
    return f"{base}#{fr[0]}" if fr is not None else base


@register
class BrowserCrawlSource(Source):
    """Render + crawl same-origin pages with headless Chromium."""

    name = "browser_crawl"
    consumes = ("origins", "urls")
    produces = ("origins", "pages", "endpoints", "parameters", "forms", "identities")
    active = True

    def __init__(
        self,
        seeds: Sequence[str] = (),
        *,
        max_pages: Optional[int] = None,
        max_depth: Optional[int] = None,
        headless: bool = True,
        allow_unproxied: bool = False,
        proxy_hosts: Optional[Sequence[str]] = None,
        identity: Optional[str] = None,
    ) -> None:
        self.seeds = tuple(seeds)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.headless = headless
        self.allow_unproxied = allow_unproxied
        self._proxy_hosts = tuple(proxy_hosts) if proxy_hosts is not None else None
        # Identity name to crawl as; None = first authenticated identity on the
        # engine, if any (see core.browser.auth.resolve_identity).
        self.identity_name = identity

    def available(self, ctx: RunContext) -> bool:
        return super().available(ctx) and _harness.available()

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        origins = list(self.seeds) or list(ctx.origins)
        if not origins:
            result.error = "no origins to crawl"
            return result

        knobs = ctx.profile.knobs
        max_pages = self.max_pages or int(knobs.get("max_pages", 50))
        max_depth = self.max_depth or int(knobs.get("max_depth", 3))
        proxy_hosts = () if self.allow_unproxied else (
            list(self._proxy_hosts) if self._proxy_hosts is not None
            else _hosts_of(ctx.origins or origins)
        )

        # Authenticated crawl: if the run carries a session engine, resolve an
        # identity and seed every browser context with its headers + cookies so
        # the crawl reaches the logged-in surface (where BOLA/BFLA live). Absent
        # or anonymous session => an anonymous crawl, unchanged.
        session_args: Dict[str, Any] = {}
        identity = resolve_identity(ctx.session, self.identity_name)
        if identity is not None:
            session_args = context_args_for_identity(identity)
            result.add(IdentityRecord(
                name=getattr(identity, "name", "user"),
                role=getattr(identity, "role", "") or "",
                authenticated=True, source=self.name,
            ))

        visited: Set[str] = set()
        # Preserve a seed's fragment route (if any); otherwise canonicalise.
        queue: deque = deque(
            ((o if fragment_route(o) is not None else (canonical_url(o) or o)), 0)
            for o in origins)

        try:
            with _harness.BrowserHarness(
                headless=self.headless, proxy_hosts=proxy_hosts,
                allow_unproxied=self.allow_unproxied,
            ) as h:
                while queue and len(visited) < max_pages:
                    url, depth = queue.popleft()
                    key = _visit_key(url)
                    if not url or key in visited:
                        continue
                    visited.add(key)
                    session = h.new_session(**session_args)
                    try:
                        session.navigate(url)
                        cap = session.capture()
                    except Exception as exc:
                        result.failed.append(f"{url}: {type(exc).__name__}")
                        continue
                    finally:
                        session.close()

                    for kind, rows in records_from_capture(cap, source=self.name).items():
                        for row in rows:
                            result.add((kind, row))
                    result.discovered.urls.add(key)

                    if depth < max_depth:
                        for link in cap.links:
                            if not in_scope(link, origins):
                                continue
                            # Keep the fragment for a hash-route link so the SPA
                            # route renders; canonicalise a plain link.
                            nav = (link if fragment_route(link) is not None
                                   else canonical_url(link))
                            if nav and _visit_key(nav) not in visited:
                                queue.append((nav, depth + 1))
                                result.discovered.urls.add(_visit_key(nav))
        except _harness.BrowserUnavailable as exc:
            result.error = str(exc)
        return result


__all__ = ["BrowserCrawlSource"]
