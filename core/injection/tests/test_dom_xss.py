"""Tests for core.injection.dom_xss — browser-backed DOM-XSS confirmation.

Uses a stub harness (no Playwright) that simulates execution: it returns the
sentinel only when the navigated URL carried our onerror payload — i.e. the
handler "ran". Proves the oracle keys on execution, not reflection.
"""

import re
import urllib.parse

from core.injection.config import InjectionPoint, from_dict
from core.injection.dom_xss import confirm_dom_xss
from core.injection.runner import run_injection
from core.session.tests.fakes import FakeClient, resp


class _StubSession:
    def __init__(self, vulnerable, headers=None):
        self.vulnerable = vulnerable
        self.headers = headers
        self._url = ""

    def navigate(self, url):
        self._url = url

    def eval_js(self, script):
        if "setTimeout" in script:
            return None
        if "window.__raptor_xss" in script and self.vulnerable:
            m = re.search(r"window\.__raptor_xss='([a-z0-9]+)'",
                          urllib.parse.unquote(self._url))
            return m.group(1) if m else None
        return None

    def close(self):
        pass


class _StubHarness:
    def __init__(self, vulnerable):
        self.vulnerable = vulnerable
        self.last_headers = None
        self.navigated = []

    def new_session(self, extra_http_headers=None):
        self.last_headers = extra_http_headers
        session = _StubSession(self.vulnerable, extra_http_headers)
        _orig = session.navigate

        def _rec(url):
            self.navigated.append(url)
            _orig(url)

        session.navigate = _rec
        return session


_POINTS = [InjectionPoint(method="GET", path="/search", param="q", location="query")]
_FRAG_POINTS = [InjectionPoint(method="GET", path="/#/search", param="q",
                              location="fragment")]


def test_confirm_dom_xss_detects_execution():
    hits = confirm_dom_xss(_StubHarness(vulnerable=True), "https://app.test", _POINTS)
    assert len(hits) == 1 and hits[0]["context"] == "dom-executed"


def test_confirm_dom_xss_no_execution_no_finding():
    assert confirm_dom_xss(_StubHarness(vulnerable=False), "https://app.test", _POINTS) == []


def test_confirm_dom_xss_skips_body_points():
    body_pt = [InjectionPoint(method="POST", path="/x", param="b", location="body")]
    assert confirm_dom_xss(_StubHarness(vulnerable=True), "https://app.test", body_pt) == []


def test_confirm_dom_xss_drives_spa_hash_route():
    # the SPA/DOM-XSS case: a fragment (hash-route) param must be driven, and
    # the browser must navigate the fragment URL — not a REST path.
    h = _StubHarness(vulnerable=True)
    hits = confirm_dom_xss(h, "https://app.test", _FRAG_POINTS)
    assert len(hits) == 1 and hits[0]["context"] == "dom-executed"
    assert any("/#/search?q=" in u for u in h.navigated)   # fragment, not query


def test_confirm_dom_xss_no_execution_on_hash_route():
    assert confirm_dom_xss(_StubHarness(vulnerable=False), "https://app.test",
                           _FRAG_POINTS) == []


def test_confirm_dom_xss_seeds_auth_headers():
    h = _StubHarness(vulnerable=True)
    confirm_dom_xss(h, "https://app.test", _POINTS,
                    session_headers={"Authorization": "Bearer JWT"})
    assert h.last_headers == {"Authorization": "Bearer JWT"}


def _cfg():
    return from_dict({"base_url": "https://app.test", "authorization": "ok",
                      "points": [{"method": "GET", "path": "/search", "param": "q",
                                  "location": "query"}], "classes": ["xss"]})


def test_run_injection_dom_xss_finding_is_state_oracle(tmp_path):
    # HTTP xss oracle finds nothing (static app); the browser harness confirms DOM XSS
    safe = lambda hosts: FakeClient(lambda *a: resp(200, body=b"<div>static</div>"))
    run = run_injection(_cfg(), out_dir=tmp_path, active=True, client_factory=safe,
                        dom_xss_harness=_StubHarness(vulnerable=True))
    xss = [f for f in run.findings if f["class"] == "xss"]
    assert xss and xss[0]["proof"] == "state_oracle"
