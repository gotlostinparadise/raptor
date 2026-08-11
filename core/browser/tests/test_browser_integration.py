"""Integration tests for core.browser — drive a real headless Chromium.

Marked ``integration`` (deselected by default per pytest.ini); run with
``pytest -m integration core/browser``. They need Playwright + Chromium
installed and skip cleanly otherwise. All traffic is loopback / ``data:`` — no
third-party egress, so they stay inside the egress envelope without a proxy.
"""

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.browser import harness as H
from core.browser.capture import records_from_capture
from core.browser.crawl_source import BrowserCrawlSource
from core.webgraph.builder import build_graph
from core.webgraph.source import PROFILES, RunContext, Surface

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not H.available(), reason="playwright/chromium not installed"),
]

_INDEX = b"""<!doctype html><title>Home</title>
<a href="/orders">orders</a>
<form action="/search" method="get"><input name="q"></form>
<script>
  window.postMessage({hello:'world'}, '*');
  fetch('/api/items?page=2');
</script>"""

_ORDERS = b"""<!doctype html><title>Orders</title><h1 id=h>Orders</h1>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        body = {"/": _INDEX, "/orders": _ORDERS}.get(path)
        if body is None and path == "/api/items":
            body = b'{"items":[]}'
        if body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
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


def test_session_executes_js_and_captures_postmessage():
    with H.BrowserHarness() as h:
        s = h.new_session()
        s.navigate("data:text/html,<h1 id=t>hi</h1>"
                   "<script>window.V=6*7;window.postMessage('ping','*')</script>")
        assert s.eval_js("window.V") == 42
        cap = s.capture()
        assert any(pm.data == "ping" for pm in cap.postmessages)


def test_egress_refused_for_remote_without_proxy():
    with H.BrowserHarness() as h:  # no proxy_hosts, allow_unproxied=False
        s = h.new_session()
        with pytest.raises(H.BrowserEgressError):
            s.navigate("https://example.com/")


def test_dom_crawl_finds_runtime_endpoint_and_links():
    with _server() as base:
        with H.BrowserHarness(allow_unproxied=True) as h:
            s = h.new_session()
            s.navigate(base + "/")
            # give the page's fetch() a moment to fire
            s.eval_js("new Promise(r => setTimeout(r, 200))")
            cap = s.capture()
    recs = records_from_capture(cap)
    eps = {e["path"] for e in recs.get("endpoints", [])}
    assert "/api/items" in eps                       # runtime fetch captured
    assert any(f["action"].endswith("/search") for f in recs.get("forms", []))


def test_browser_crawl_source_feeds_graph_end_to_end():
    with _server() as base:
        src = BrowserCrawlSource(seeds=[base + "/"], allow_unproxied=True,
                                 max_pages=5, max_depth=2)
        ctx = RunContext(origins=(base,), surface=Surface(),
                         profile=PROFILES["safe"], raw_dir=None, normalized_dir=None)
        assert src.available(ctx)
        result = src.run(ctx)
    g = build_graph(result.records, [base])
    pages = [k for k in g.nodes if k[0] == "page"]
    assert len(pages) >= 2                            # / and /orders crawled
    assert ("endpoint", "GET /api/items") in g.nodes
