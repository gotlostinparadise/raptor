"""Tests for core.injection.dom_xss.confirm_stored_xss — stored-XSS confirmation.

The defining property of stored XSS is that the write target and the render
target are DECOUPLED: a payload POSTed to one endpoint executes when some *other*
page renders the stored copy. The stub below models exactly that — the writer
persists a payload into a shared store, and the browser sentinel fires only when
the designated render page is navigated. So a finding requires (a) the payload to
survive the write unsanitised AND (b) the right render page to be checked.
"""

import re

from core.injection.config import InjectionPoint
from core.injection.dom_xss import confirm_stored_xss

_TOK_RE = re.compile(r"__raptor_xss='([a-z0-9]+)'")


class _StoredSession:
    def __init__(self, app):
        self.app = app
        self._url = ""

    def navigate(self, url):
        self._url = url

    def eval_js(self, script):
        if "setTimeout" in script:
            return None
        if "window.__raptor_xss" in script:
            # the stored payload executes ONLY on the render page
            if self.app.render_page in self._url and self.app.stored:
                return self.app.stored[-1]
        return None

    def close(self):
        pass


class _StoredApp:
    """Stored-XSS app model: persisted payloads render on ``render_page`` only."""

    def __init__(self, render_page, *, sanitize=False):
        self.render_page = render_page
        self.sanitize = sanitize
        self.stored = []
        self.writes = 0

    def writer(self, point, value):
        self.writes += 1
        m = _TOK_RE.search(value)
        if m and not self.sanitize:
            self.stored.append(m.group(1))

    def new_session(self, extra_http_headers=None):
        return _StoredSession(self)


_WRITE = [InjectionPoint(method="POST", path="/guestbook", param="comment",
                         location="body")]


def test_stored_xss_confirmed_on_decoupled_render_page():
    app = _StoredApp(render_page="/guestbook/view")
    hits = confirm_stored_xss(app, "https://app.test", _WRITE,
                              ["/", "/guestbook/view"], writer=app.writer)
    assert len(hits) == 1
    assert hits[0]["context"] == "stored-dom-executed"
    assert hits[0]["render_url"] == "/guestbook/view"
    assert hits[0]["point"] is _WRITE[0]
    assert app.writes >= 1                       # the payload was actually POSTed


def test_stored_xss_sanitized_write_no_finding():
    # the app strips the payload on write → nothing stored → never executes
    app = _StoredApp(render_page="/guestbook/view", sanitize=True)
    hits = confirm_stored_xss(app, "https://app.test", _WRITE,
                              ["/guestbook/view"], writer=app.writer)
    assert hits == []


def test_stored_xss_requires_the_right_render_page():
    # payload stored fine, but we never navigate the page that renders it →
    # decoupling means no confirmation (no false positive from the write alone)
    app = _StoredApp(render_page="/guestbook/view")
    hits = confirm_stored_xss(app, "https://app.test", _WRITE,
                              ["/", "/about"], writer=app.writer)
    assert hits == []


def test_stored_xss_only_body_points_are_written():
    # a query/fragment point is not a stored-write candidate here
    frag = [InjectionPoint(method="GET", path="/#/x", param="q", location="fragment")]
    app = _StoredApp(render_page="/x")
    hits = confirm_stored_xss(app, "https://app.test", frag, ["/x"], writer=app.writer)
    assert hits == [] and app.writes == 0
