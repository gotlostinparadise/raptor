"""URL-history source — passive endpoint discovery from web archives.

The pure-Python analogue of ``gau``/``waybackurls``: given the in-scope origins a
recon run surfaced, it asks a public archive what URLs it has ever seen on those
hosts and turns each into app-graph surface — an ``endpoint`` (templated
method+path), its query ``parameter``\\ s, and a ``page``. Historical URLs are the
single richest passive feed for the application graph and need no new model work.

It talks only to the archive (``web.archive.org``), never the target, so it is
``active = False`` and egress-allowlisted to that host through
:meth:`RunContext.http_client` — a compromised parser cannot exfiltrate
elsewhere, exactly like the recon passive sources.

**Not auto-registered on purpose.** Unlike the spec-import / browser sources
(whose :meth:`available` is ``False`` until you pass a spec / install Playwright),
this source has no such gate — it would run in *every* ``run_webgraph`` with a
default source set and quietly hit a third party. So it is an explicit opt-in:
callers (the recon→web bridge's ``--url-history``, or ``/webgraph``) instantiate
and pass it deliberately. It is never in ``all_sources()``.
"""

from __future__ import annotations

from typing import Any, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

from core.http import HttpError
from core.webgraph.model import EndpointRecord, OriginRecord, PageRecord, ParamRecord
from core.webgraph.scope import canonical_origin, canonical_url, endpoint_id, strip_query
from core.webgraph.source import RunContext, Source, SourceResult

ARCHIVE_HOST = "web.archive.org"
DEFAULT_PER_HOST_CAP = 5000
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
REQUEST_TIMEOUT = 60


class UrlHistorySource(Source):
    name = "url_history"
    egress_hosts = (ARCHIVE_HOST,)
    credential_env_vars = ()
    consumes = ("origins",)
    produces = ("origins", "pages", "endpoints", "parameters")
    active = False

    def __init__(self, per_host_cap: int = DEFAULT_PER_HOST_CAP) -> None:
        self._cap = per_host_cap

    def _query_url(self, host: str) -> str:
        return (
            f"https://{ARCHIVE_HOST}/cdx/search/cdx?url={host}/*"
            f"&output=json&fl=original&collapse=urlkey&limit={self._cap}"
        )

    def run(self, ctx: RunContext) -> SourceResult:
        http = ctx.http_client(self)
        result = SourceResult(source=self.name)

        # In-scope by host (archive rows may carry either scheme / a default port).
        in_scope_hosts = {
            urlsplit(o).hostname for o in ctx.origins if urlsplit(o).hostname
        }
        if not in_scope_hosts:
            return result

        seen_ep: Set[str] = set()
        seen_param: Set[Tuple[str, str, str]] = set()
        seen_page: Set[str] = set()
        seen_origin: Set[str] = set()

        for host in sorted(in_scope_hosts):
            result.requested += 1
            try:
                data = http.get_json(self._query_url(host), timeout=REQUEST_TIMEOUT,
                                     max_bytes=MAX_RESPONSE_BYTES)
            except HttpError as exc:
                result.failed.append(host)
                result.error = f"{type(exc).__name__}: {exc}"
                continue

            for row in (data or []):
                # CDX json is a list of [original] rows; the first row is a header.
                url = row[0] if isinstance(row, list) and row else row
                if not isinstance(url, str) or url == "original":
                    continue
                parts = urlsplit(url.strip())
                if parts.hostname not in in_scope_hosts:
                    continue
                origin = canonical_origin(url)
                if not origin:
                    continue
                path = parts.path or "/"
                eid = endpoint_id("GET", path)

                if origin not in seen_origin:
                    seen_origin.add(origin)
                    result.add(OriginRecord(origin=origin, source=self.name))
                    result.discovered.origins.add(origin)

                if eid not in seen_ep:
                    seen_ep.add(eid)
                    result.add(EndpointRecord(
                        method="GET", path=path, origin=origin,
                        url=strip_query(url), source=self.name,
                    ))
                    result.discovered.endpoints.add(eid)

                for name, value in parse_qsl(parts.query):
                    key = (eid, name, "query")
                    if key in seen_param:
                        continue
                    seen_param.add(key)
                    result.add(ParamRecord(
                        endpoint_id=eid, name=name, location="query",
                        example=value[:80], source=self.name,
                    ))

                page = canonical_url(url)
                if page and page not in seen_page:
                    seen_page.add(page)
                    result.add(PageRecord(url=page, origin=origin, source=self.name))
                    result.discovered.urls.add(page)

        return result


__all__ = ["UrlHistorySource", "ARCHIVE_HOST"]
