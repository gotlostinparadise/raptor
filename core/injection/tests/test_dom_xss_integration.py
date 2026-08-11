"""Integration proof for the SPA hash-route DOM-XSS chain — it actually fires.

``test_fragment_routes.py`` pins the *pure* chain (capture → graph → harvest →
URL-build) with no browser. What no test exercises is the last, hardest hop:
driving :func:`core.injection.dom_xss.confirm_dom_xss` through a real headless
Chromium so the injected handler *executes* and sets ``window.__raptor_xss``.
Execution — not reflection — is the DOM-XSS verdict, and the SPA fragment
(``/#/search?q=…``) is where that verdict actually lives, so this is the end of
the chain that only a browser oracle can certify.

Marked ``integration`` (deselected by default per pytest.ini; run with
``pytest -m integration core/injection``). Needs Playwright + Chromium and skips
cleanly otherwise. All traffic is loopback — no third-party egress.
"""

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.browser import harness as H
from core.injection.config import InjectionPoint
from core.injection.dom_xss import confirm_dom_xss

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not H.available(), reason="playwright/chromium not installed"),
]

# A deliberately vulnerable single-page app: it reads the query string out of the
# URL *fragment* (the hash-route the server never sees) and sinks it, unescaped,
# into the DOM via innerHTML. That is the real Angular/SPA DOM-XSS shape — an
# `<img onerror>` / `<svg onload>` vector inserted this way executes.
_VULN_SPA = b"""<!doctype html><meta charset="utf-8"><title>vuln-spa</title>
<div id="out"></div>
<script>
function render() {
  var h = location.hash || "";
  var i = h.indexOf("?");
  if (i < 0) return;
  var q = new URLSearchParams(h.slice(i + 1)).get("q");
  if (q !== null) { document.getElementById("out").innerHTML = q; }  // sink
}
window.addEventListener("hashchange", render);
render();
</script>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        # The fragment never reaches the server; every route serves the SPA shell.
        if self.path.split("?", 1)[0] in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(_VULN_SPA)
        else:
            self.send_response(404)
            self.end_headers()


@contextmanager
def _spa_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def test_dom_xss_fires_on_spa_hash_route():
    point = InjectionPoint(method="GET", path="/#/search", param="q",
                           location="fragment")
    with _spa_server() as base:
        with H.BrowserHarness(allow_unproxied=True) as h:
            findings = confirm_dom_xss(h, base, [point])

    # A finding means a catalog vector executed in the DOM (sentinel matched) —
    # the whole capture→graph→harvest→build→navigate→poll chain, proven live.
    assert findings, "expected a DOM-XSS confirmation on the SPA fragment route"
    f = findings[0]
    assert f["context"] == "dom-executed"
    assert f["point"].location == "fragment"      # fired via the hash-route, not a real query
    assert f["token"] and f["token"] in f["payload"]
    assert f["entry"]                              # the catalog entry id that won


def test_inert_spa_yields_no_dom_xss():
    """Control: a server that renders nothing must not confirm — guards against a
    sentinel that leaks in from anywhere but the injected, executed handler."""
    class _Inert(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<!doctype html><title>inert</title><p>nothing here</p>")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Inert)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        point = InjectionPoint(method="GET", path="/#/search", param="q",
                               location="fragment")
        with H.BrowserHarness(allow_unproxied=True) as h:
            findings = confirm_dom_xss(h, base, [point])
    finally:
        srv.shutdown()
    assert findings == []
