"""Tests for the session-identity -> browser-context bridge (no Playwright).

The pure conversion (resolve_identity / context_args_for_identity) is tested
directly; the crawl-source wiring is exercised through a fake harness so the
authenticated-crawl path has CI coverage even though real Chromium does not run
in CI.
"""

from __future__ import annotations

import pytest

from core.browser import crawl_source as cs
from core.browser.auth import context_args_for_identity, resolve_identity
from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.webgraph.source import PROFILES, RunContext, Surface


def _engine_with_user():
    eng = SessionEngine(None)   # client unused for this construction
    user = Identity(name="user_a", role="member", authenticated=True)
    user.set_bearer("tok123")
    user.jar.set("session", "abc", host="app.example.com", path="/")
    eng.add_identity(user)
    return eng, user


# ─────────────────────────── pure conversion ───────────────────────────

def test_cookiejar_cookies_export():
    _, user = _engine_with_user()
    cookies = user.jar.cookies()
    assert [(c.name, c.value, c.host, c.path) for c in cookies] == [
        ("session", "abc", "app.example.com", "/")
    ]


def test_context_args_for_identity():
    _, user = _engine_with_user()
    args = context_args_for_identity(user)
    assert args["extra_http_headers"] == {"Authorization": "Bearer tok123"}
    assert args["cookies"] == [
        {"name": "session", "value": "abc", "domain": "app.example.com", "path": "/"}
    ]


def test_context_args_drops_cookie_header():
    ident = Identity(name="x", auth_headers={"Cookie": "leak=1", "X-API-Key": "k"})
    args = context_args_for_identity(ident)
    assert args["extra_http_headers"] == {"X-API-Key": "k"}


def test_resolve_identity_by_name_and_default():
    eng, user = _engine_with_user()
    assert resolve_identity(eng, "user_a") is user
    # default picks the first non-anonymous identity
    assert resolve_identity(eng) is user
    # unknown name -> None
    assert resolve_identity(eng, "nobody") is None


def test_resolve_identity_none_cases():
    assert resolve_identity(None) is None
    # engine with only anonymous -> None
    eng = SessionEngine(None)
    assert resolve_identity(eng) is None
    # explicitly naming anonymous -> None (means "no auth to seed")
    assert resolve_identity(eng, "anonymous") is None


# ─────────────────────────── crawl wiring (fake harness) ───────────────────────────

class _FakeSession:
    def navigate(self, url, **kw):
        return 200

    def capture(self):
        from core.browser.capture import PageCapture
        return PageCapture(url="https://app.example.com/", title="Home",
                           status=200, links=[])

    def close(self):
        pass


class _FakeHarness:
    last_kwargs = None

    def __init__(self, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def new_session(self, **kwargs):
        _FakeHarness.last_kwargs = kwargs
        return _FakeSession()


def _ctx(tmp_path, session):
    raw = tmp_path / "raw"
    norm = tmp_path / "normalized"
    raw.mkdir(parents=True, exist_ok=True)
    norm.mkdir(parents=True, exist_ok=True)
    return RunContext(
        origins=("https://app.example.com",),
        surface=Surface(origins={"https://app.example.com"}),
        profile=PROFILES["safe"], raw_dir=raw, normalized_dir=norm,
        session=session,
    )


def test_crawl_seeds_context_with_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(cs._harness, "BrowserHarness", _FakeHarness)
    eng, _user = _engine_with_user()
    _FakeHarness.last_kwargs = None

    result = cs.BrowserCrawlSource(max_pages=1).run(_ctx(tmp_path, eng))

    # the browser context was seeded with the identity's header + cookie
    kw = _FakeHarness.last_kwargs
    assert kw["extra_http_headers"] == {"Authorization": "Bearer tok123"}
    assert kw["cookies"][0]["name"] == "session"
    # and an IdentityRecord was emitted
    idents = result.records.get("identities", [])
    assert any(i["name"] == "user_a" and i["authenticated"] for i in idents)


def test_crawl_anonymous_when_no_session(tmp_path, monkeypatch):
    monkeypatch.setattr(cs._harness, "BrowserHarness", _FakeHarness)
    _FakeHarness.last_kwargs = None

    result = cs.BrowserCrawlSource(max_pages=1).run(_ctx(tmp_path, None))

    # no identity => no seeding, no IdentityRecord
    assert _FakeHarness.last_kwargs == {}
    assert "identities" not in result.records
