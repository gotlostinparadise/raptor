"""Integration test for core.http_crawl — crawl a real local server over HTTP.

Marked ``integration`` (deselected by default per pytest.ini); run with
``pytest -m integration core/http_crawl``. All traffic is loopback (127.0.0.1) —
no third-party egress. This is the R1 acceptance: the crawler maps a
multi-page, server-rendered app and the graph carries its linked pages + form
params, mapped over real HTTP (not a fake client).
"""

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.http_crawl.source import HttpCrawlSource
from core.webgraph.orchestrator import run_webgraph

pytestmark = [pytest.mark.integration]

_INDEX = b"""<!doctype html><title>Home</title>
<a href="/products">products</a>
<a href="/about">about</a>
<a href="/view?id=1">first item</a>
<form action="/search" method="get"><input name="term"></form>
<form action="/login" method="post"><input name="username"><input name="password"></form>"""

_PRODUCTS = b"""<!doctype html><title>Products</title><a href="/">home</a>"""
_ABOUT = b"""<!doctype html><title>About</title>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence the default access log
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        body = {"/": _INDEX, "/products": _PRODUCTS, "/about": _ABOUT}.get(path, b"<title>x</title>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def test_static_crawl_maps_server_rendered_app_over_real_http(tmp_path):
    with _server() as base:
        summary = run_webgraph(
            [base], tmp_path, sources=[HttpCrawlSource(seeds=[base + "/"])],
            profile="safe",
        )

    assert "http_crawl" in summary.sources_run
    web = json.loads((tmp_path / "graph" / "web.json").read_text())
    # group each node's raw label (n["id"] is the "type:label" prefixed form)
    by_type = {}
    for n in web["nodes"]:
        by_type.setdefault(n["type"], set()).add(n["label"])

    # linked pages were followed and recorded
    pages = by_type.get("page", set())
    assert f"{base}/" in pages and f"{base}/products" in pages and f"{base}/about" in pages

    # form submit targets + a query-carrying link became endpoints
    endpoints = by_type.get("endpoint", set())
    assert {"GET /search", "POST /login", "GET /view"} <= endpoints

    # form fields (GET query + POST body) + link query became parameter nodes
    params = by_type.get("parameter", set())
    assert "GET /search|query:term" in params
    assert "POST /login|body:username" in params
    assert "POST /login|body:password" in params
    assert "GET /view|query:id" in params
