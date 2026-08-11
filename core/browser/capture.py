"""Captured browser artifacts + their projection to web-graph records.

Deliberately free of any Playwright import so these dataclasses — and the
record conversion — are unit-testable with no browser. :mod:`core.browser.session`
populates a :class:`PageCapture` from a live page; :func:`records_from_capture`
turns it into the same normalised :mod:`core.webgraph.model` records a static
crawl would emit, so DOM-discovered and statically-discovered surface land on
the *same* graph nodes.

The whole point of the browser harness is what a non-JS fetch can't see: XHR/fetch
endpoints a SPA calls at runtime, DOM-injected forms, ``postMessage`` channels,
and console output. Those live on the capture below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit

from core.webgraph import model as M
from core.webgraph.scope import (
    canonical_origin, canonical_url, endpoint_id, fragment_route,
    spa_endpoint_path, split_url,
)

# Playwright resource types that represent an application endpoint call (as
# opposed to a static asset like an image or stylesheet).
_API_RESOURCE_TYPES = {"xhr", "fetch", "websocket", "eventsource"}


@dataclass
class NetworkRequest:
    url: str
    method: str = "GET"
    resource_type: str = ""
    status: Optional[int] = None

    @property
    def is_api(self) -> bool:
        return self.resource_type in _API_RESOURCE_TYPES


@dataclass
class ConsoleMessage:
    level: str
    text: str


@dataclass
class PostMessageEvent:
    """A ``window.postMessage`` observed via an injected listener."""

    origin: str
    data: str


@dataclass
class FormCapture:
    action: str
    method: str = "GET"
    fields: List[str] = field(default_factory=list)


@dataclass
class PageCapture:
    """Everything one navigated page exposed."""

    url: str
    final_url: str = ""
    title: str = ""
    status: Optional[int] = None
    links: List[str] = field(default_factory=list)
    forms: List[FormCapture] = field(default_factory=list)
    requests: List[NetworkRequest] = field(default_factory=list)
    console: List[ConsoleMessage] = field(default_factory=list)
    postmessages: List[PostMessageEvent] = field(default_factory=list)

    def api_requests(self) -> List[NetworkRequest]:
        return [r for r in self.requests if r.is_api]


def records_from_capture(cap: PageCapture, *, source: str = "browser_crawl") -> Dict[str, List[Dict[str, Any]]]:
    """Project a :class:`PageCapture` to a records-by-kind map for the graph.

    Emits a ``pages`` record (``rendered=True`` — the DOM-aware marker), an
    ``endpoints`` + ``parameters`` record per runtime API call, an ``origins``
    record, and a ``forms`` record per captured form.
    """
    out: Dict[str, List[Dict[str, Any]]] = {}

    def add(rec) -> None:
        out.setdefault(rec.KIND, []).append(rec.to_row())

    page_url = canonical_url(cap.final_url or cap.url) or (cap.final_url or cap.url)
    origin = canonical_origin(cap.final_url or cap.url)
    if origin:
        add(M.OriginRecord(origin=origin, title=cap.title, source=source))
    add(M.PageRecord(url=page_url, origin=origin, title=cap.title,
                     status=cap.status, rendered=True, source=source))

    for req in cap.api_requests():
        req_origin, path = split_url(req.url)
        eid = endpoint_id(req.method, path)
        add(M.EndpointRecord(method=req.method, path=path,
                             origin=req_origin or origin,
                             url=req.url, status=req.status, source=source))
        for name, _value in parse_qsl(urlsplit(req.url).query):
            add(M.ParamRecord(endpoint_id=eid, name=name,
                              location=M.LOC_QUERY, source=source))

    for form in cap.forms:
        add(M.FormRecord(page_url=page_url, action=form.action,
                         method=form.method, fields=form.fields, source=source))

    # SPA hash-routes: the rendered URL and any in-app links may carry a
    # client-side route with its own query string (``/#/search?q=…``). The
    # server never sees it (everything after ``#`` is client-side), so it
    # surfaces only here — model it as a ``fragment``-located endpoint so the
    # DOM-aware oracle can target Angular/Vue/React hash-routes.
    seen_spa: set = set()
    for spa_url in [cap.final_url or cap.url, *cap.links]:
        parsed = fragment_route(spa_url or "")
        if not parsed:
            continue
        route, params = parsed
        spa_origin = canonical_origin(spa_url) or origin
        spa_path = spa_endpoint_path(route)
        eid = endpoint_id("GET", spa_path)
        if eid not in seen_spa:
            seen_spa.add(eid)
            add(M.EndpointRecord(method="GET", path=spa_path,
                                 origin=spa_origin or origin, url=spa_url,
                                 source=source))
        for name, _value in params:
            key = (eid, name)
            if key in seen_spa:
                continue
            seen_spa.add(key)
            add(M.ParamRecord(endpoint_id=eid, name=name,
                              location=M.LOC_FRAGMENT, source=source))

    return out


__all__ = [
    "NetworkRequest", "ConsoleMessage", "PostMessageEvent", "FormCapture",
    "PageCapture", "records_from_capture",
]
