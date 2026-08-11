"""Static HTTP crawl as a web-graph source — server-rendered surface mapping.

A :class:`~core.webgraph.source.Source` (``active``, gated by the safety profile)
that fetches an app's HTML over :mod:`core.http`, follows same-origin ``<a href>``
links breadth-first, and turns each page's links + forms into the graph's
``page`` / ``endpoint`` / ``parameter`` / ``form`` records. It is the missing map
stage for classic, server-rendered apps: the browser crawl needs Playwright and
the spec import needs an OpenAPI document, but a plain HTML site (DVWA, WebGoat,
most non-SPA apps) needs only this.

Everything it emits lands on the same ``(type, id)`` nodes as the spec import and
the browser crawl (endpoint ids are templated method+path via
:func:`core.webgraph.scope.endpoint_id`), so a form field discovered here and a
spec body param land on one endpoint node — the connective-tissue payoff.

**Authenticated crawl.** When the run carries a
:class:`core.session.SessionEngine` (the ``--login`` session ``/webpentest``
threads in), every fetch goes *through* that engine as the logged-in identity, so
its cookie jar + auth headers ride along and the crawl reaches the post-login
surface where the injectable / authz bugs live. With no session (or an anonymous
one) it crawls unauthenticated — unchanged.
"""

from __future__ import annotations

from collections import deque
from typing import Any, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

from core.http_crawl.parse import ParsedForm, parse_page
from core.webgraph import model as M
from core.webgraph.scope import (
    canonical_origin, canonical_url, endpoint_id, in_scope, split_url, strip_query,
)
from core.webgraph.source import RunContext, Source, SourceResult, register

# Content types we attempt to parse as HTML.
_HTML_HINTS = ("text/html", "application/xhtml")


def _is_html(resp: Any) -> bool:
    """Whether ``resp`` looks like HTML we should parse for links/forms."""
    headers = getattr(resp, "headers", {}) or {}
    ct = (headers.get("content-type") or "").lower()
    if ct:
        return any(hint in ct for hint in _HTML_HINTS)
    # No content-type declared (bare fixtures) — sniff the leading bytes.
    body = getattr(resp, "body", b"") or b""
    head = body[:512].lstrip().lower()
    return (head.startswith(b"<!doctype html") or head.startswith(b"<html")
            or b"<form" in head or b"<a " in head)


def _text(resp: Any) -> str:
    body = getattr(resp, "body", b"") or b""
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)


def _plain_fetch(client: Any, url: str) -> Any:
    """GET via a plain HttpClient, normalising a raised error to a Response.

    Mirrors the ``_fetch`` shape in the other web-pentest runners: pass
    ``raise_on_status=False`` so a 4xx/3xx still yields its headers/body, and fall
    back for a bare-Protocol client (test fakes) that lacks that kwarg.
    """
    try:
        return client.request("GET", url, follow_redirects=True, raise_on_status=False)
    except TypeError:
        from core.http import HttpError, Response
        try:
            return client.request("GET", url, follow_redirects=True)
        except HttpError as exc:
            return Response(status=int(exc.status or 0), headers={}, body=b"", url=url)


@register
class HttpCrawlSource(Source):
    """Fetch + crawl same-origin server-rendered pages over plain HTTP."""

    name = "http_crawl"
    consumes = ("origins", "urls")
    produces = ("origins", "pages", "endpoints", "parameters", "forms", "identities")
    active = True

    def __init__(
        self,
        seeds: Sequence[str] = (),
        *,
        max_pages: Optional[int] = None,
        max_depth: Optional[int] = None,
        identity: Optional[str] = None,
    ) -> None:
        self.seeds = tuple(seeds)
        self.max_pages = max_pages
        self.max_depth = max_depth
        # Identity name to crawl as; None = first authenticated identity on the
        # engine, if any (see core.browser.auth.resolve_identity).
        self.identity_name = identity

    # ------------------------------------------------------------------
    # fetch plumbing
    # ------------------------------------------------------------------
    def _resolve_identity(self, ctx: RunContext) -> str:
        """Pick the identity name to crawl as ('anonymous' when none/unauth)."""
        if ctx.session is None:
            return "anonymous"
        from core.browser.auth import resolve_identity
        ident = resolve_identity(ctx.session, self.identity_name)
        return getattr(ident, "name", "anonymous") if ident is not None else "anonymous"

    def _client(self, ctx: RunContext, origin: str) -> Any:
        """A plain HttpClient for ``origin`` (only used when no session engine)."""
        if ctx.http_factory is not None:
            host = urlsplit(origin).hostname or ""
            return ctx.http_factory([host] if host else [])
        from core.webhttp import pentest_client
        return pentest_client(origin)

    def _fetch(self, ctx: RunContext, client: Any, ident_name: str, url: str) -> Any:
        """One GET — through the session engine (authenticated) or a plain client."""
        try:
            if ctx.session is not None:
                return ctx.session.request(ident_name, "GET", url, follow_redirects=True)
            return _plain_fetch(client, url)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # record emission
    # ------------------------------------------------------------------
    def _emit_link_endpoint(self, result: SourceResult, link: str,
                            scope: Sequence[str]) -> None:
        """A link carrying a query string is a GET endpoint + its query params."""
        parts = urlsplit(link)
        if not parts.query:
            return
        if scope and not in_scope(link, scope):
            return
        origin, path = split_url(link)
        eid = endpoint_id("GET", path)
        result.add(M.EndpointRecord(method="GET", path=path, origin=origin,
                                    url=strip_query(link), source=self.name))
        for name, _val in parse_qsl(parts.query, keep_blank_values=True):
            if name:
                result.add(M.ParamRecord(endpoint_id=eid, name=name,
                                         location=M.LOC_QUERY, source=self.name))

    def _emit_form(self, result: SourceResult, page_url: str, form: ParsedForm,
                   scope: Sequence[str]) -> None:
        """A form → a ``form`` record plus its submit endpoint + field params.

        The builder derives the submit endpoint from the ``form`` record, but it
        does *not* turn the form's fields into ``parameter`` nodes — so we emit
        those explicitly here. That is what makes a form field an injectable point
        (``points_from_webgraph`` joins endpoints × parameters): a POST form's
        fields become body params, a GET form's become query params.
        """
        action = form.action or page_url
        method = form.method.upper() if form.method.upper() in ("GET", "POST") else "GET"
        result.add(M.FormRecord(page_url=page_url, action=action, method=method,
                                fields=list(form.fields), source=self.name))
        # Only turn a same-origin submit target into graph endpoint/param nodes.
        if scope and not in_scope(action, scope):
            return
        origin, path = split_url(action)
        eid = endpoint_id(method, path)
        result.add(M.EndpointRecord(method=method, path=path, origin=origin,
                                    url=strip_query(action), source=self.name))
        loc = M.LOC_BODY if method == "POST" else M.LOC_QUERY
        for fname in form.fields:
            if fname:
                result.add(M.ParamRecord(endpoint_id=eid, name=fname,
                                         location=loc, source=self.name))

    # ------------------------------------------------------------------
    # run loop
    # ------------------------------------------------------------------
    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        origins = list(self.seeds) or list(ctx.origins)
        if not origins:
            result.error = "no origins to crawl"
            return result

        knobs = ctx.profile.knobs
        max_pages = self.max_pages or int(knobs.get("max_pages", 50))
        max_depth = (self.max_depth if self.max_depth is not None
                     else int(knobs.get("max_depth", 3)))

        # In-scope origins: a link off-site is never followed or recorded.
        scope: List[str] = [canonical_origin(o) or o for o in (ctx.origins or origins)]

        ident_name = self._resolve_identity(ctx)
        if ident_name and ident_name != "anonymous":
            result.add(M.IdentityRecord(name=ident_name, authenticated=True,
                                        source=self.name))

        client = None if ctx.session is not None else self._client(ctx, origins[0])

        # BFS frontier keyed by canonical page url (query/fragment stripped) so
        # ``/view?id=1`` and ``/view?id=2`` are one page but their params are
        # still harvested. ``known`` guards against re-queueing.
        queue: deque = deque()
        known: Set[str] = set()
        for o in origins:
            cu = canonical_url(o) or o
            if cu not in known:
                known.add(cu)
                queue.append((cu, 0))

        visited: Set[str] = set()
        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()
            key = canonical_url(url) or url
            if key in visited:
                continue
            visited.add(key)

            resp = self._fetch(ctx, client, ident_name, url)
            if resp is None:
                result.failed.append(url)
                continue
            result.requested += 1
            status = getattr(resp, "status", None)

            html = _is_html(resp)
            page = parse_page(_text(resp), key) if html else None
            result.add(M.PageRecord(url=key, origin=canonical_origin(key),
                                    title=(page.title if page else ""),
                                    status=status, rendered=False, source=self.name))
            result.discovered.urls.add(key)
            if page is None:
                continue

            for form in page.forms:
                self._emit_form(result, key, form, scope)

            for link in page.links:
                if scope and not in_scope(link, scope):
                    continue
                self._emit_link_endpoint(result, link, scope)
                nav = canonical_url(link)
                if not nav or nav in known:
                    continue
                known.add(nav)
                result.discovered.urls.add(nav)
                if depth < max_depth:
                    queue.append((nav, depth + 1))
        return result


__all__ = ["HttpCrawlSource"]
