"""Tests for core.http_crawl.source — the static crawler drives the web graph.

No real network: a :class:`~core.session.tests.fakes.FakeClient` serves a small
multi-page server-rendered app, handed to the source through the ``RunContext``'s
``http_factory``. The assertions are on the resulting ``(type, id)`` graph — the
same surface ``/inject`` later harvests.
"""

from urllib.parse import urlsplit

from core.http_crawl.source import HttpCrawlSource
from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.tests.fakes import FakeClient, resp
from core.webgraph.builder import build_graph
from core.webgraph.scope import canonical_origin
from core.webgraph.source import PROFILES, RunContext, Surface

_BASE = "https://app.test"

# A classic server-rendered app: linked pages, a GET search form, a POST login
# form, a query-carrying link, and an off-site link that must NOT be crawled.
_INDEX = b"""<!doctype html><title>Home</title>
<a href="/page1">one</a> <a href="/page2">two</a>
<a href="/view?id=1">item</a>
<a href="http://evil.test/steal">offsite</a>
<form action="/search" method="get"><input name="q"></form>
<form action="/login" method="post"><input name="user"><input name="pass"></form>"""

_PAGE1 = b"""<!doctype html><title>One</title><a href="/">home</a>"""
_PAGE2 = b"""<!doctype html><title>Two</title>"""
_OTHER = b"""<!doctype html><title>x</title>"""

_PAGES = {"/": _INDEX, "/page1": _PAGE1, "/page2": _PAGE2}


def _handler(seen_headers=None):
    def h(method, url, headers, body):
        if seen_headers is not None:
            seen_headers.append(headers)
        path = urlsplit(url).path or "/"
        body_out = _PAGES.get(path, _OTHER)
        return resp(200, body=body_out, url=url, **{"Content-Type": "text/html"})
    return h


def _ctx(session=None, seen_headers=None):
    return RunContext(
        origins=(_BASE,), surface=Surface(origins={_BASE}), profile=PROFILES["safe"],
        raw_dir=None, normalized_dir=None,
        http_factory=(None if session is not None else (lambda hosts: FakeClient(_handler(seen_headers)))),
        session=session,
    )


def _graph_from_run():
    src = HttpCrawlSource(seeds=[_BASE + "/"], max_pages=20, max_depth=3)
    result = src.run(_ctx())
    return build_graph(result.records, [_BASE]), result


def test_linked_pages_land_in_graph():
    g, _ = _graph_from_run()
    pages = {k[1] for k in g.nodes if k[0] == "page"}
    assert f"{_BASE}/" in pages
    assert f"{_BASE}/page1" in pages           # followed a link
    assert f"{_BASE}/page2" in pages


def test_form_params_become_parameter_nodes():
    g, _ = _graph_from_run()
    # GET form → query param q on GET /search
    assert ("endpoint", "GET /search") in g.nodes
    assert ("parameter", "GET /search|query:q") in g.nodes
    # POST form → body params user/pass on POST /login
    assert ("endpoint", "POST /login") in g.nodes
    assert ("parameter", "POST /login|body:user") in g.nodes
    assert ("parameter", "POST /login|body:pass") in g.nodes


def test_link_query_params_become_parameter_nodes():
    g, _ = _graph_from_run()
    assert ("endpoint", "GET /view") in g.nodes
    assert ("parameter", "GET /view|query:id") in g.nodes


def test_offsite_link_not_crawled_or_recorded():
    g, _ = _graph_from_run()
    origins = {k[1] for k in g.nodes if k[0] == "origin"}
    pages = {k[1] for k in g.nodes if k[0] == "page"}
    assert canonical_origin("http://evil.test") not in origins
    assert not any("evil.test" in p for p in pages)


def test_injection_points_harvestable_from_the_crawled_surface(tmp_path):
    # the whole R1 payoff: the crawled form/link params are exactly what /inject
    # harvests via points_from_webgraph.
    from core.webgraph.orchestrator import persist_records
    src = HttpCrawlSource(seeds=[_BASE + "/"])
    result = src.run(_ctx())
    persist_records(tmp_path / "normalized", result.records)
    from core.injection.config import points_from_webgraph
    points = points_from_webgraph(tmp_path / "normalized")
    labels = {p.label for p in points}
    assert "POST /login [body:user]" in labels
    assert "GET /search [query:q]" in labels
    assert "GET /view [query:id]" in labels


def test_dry_scope_dedup_visits_each_page_once():
    # page1 links back to "/" — the frontier must not loop.
    src = HttpCrawlSource(seeds=[_BASE + "/"])
    result = src.run(_ctx())
    page_rows = [r for r in result.records.get("pages", [])]
    urls = [r["url"] for r in page_rows]
    assert len(urls) == len(set(urls))         # no page fetched/emitted twice


def test_authenticated_crawl_reuses_session_cookies():
    # R1 must crawl authenticated by reusing core/session: a cookie set on the
    # logged-in identity must ride onto every crawl request.
    seen = []
    engine = SessionEngine(FakeClient(_handler(seen)))
    ident = Identity(name="session", authenticated=True)
    ident.jar.set("PHPSESSID", "abc123", "app.test")
    engine.add_identity(ident)

    src = HttpCrawlSource(seeds=[_BASE + "/"])
    result = src.run(_ctx(session=engine))

    assert seen, "crawler sent no requests through the session engine"
    assert all("PHPSESSID=abc123" in (h.get("Cookie") or "") for h in seen)
    # the authenticated identity is recorded on the graph
    assert any(r["name"] == "session" for r in result.records.get("identities", []))
