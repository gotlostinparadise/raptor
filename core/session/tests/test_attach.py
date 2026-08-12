"""Tests for core.session.attach — thread one session into the HTTP phases."""

from core.session.attach import engine_for, merged_auth_headers
from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.tests.fakes import FakeClient, resp

_BASE = "https://app.test"


def _factory(calls=None):
    def h(method, url, headers, body):
        if calls is not None:
            calls.append((method, url, headers))
        return resp(200, body=b"ok")
    return lambda hosts: FakeClient(h)


# ─────────────────────────── engine_for ───────────────────────────

def test_engine_for_builds_fresh_engine_with_bearer_from_token_env():
    engine, name, warns = engine_for(_BASE, token_env="TOK", env={"TOK": "abc"},
                                     client_factory=_factory())
    assert name == "tester" and warns == []
    assert engine.identity("tester").auth_headers["Authorization"] == "Bearer abc"


def test_engine_for_seeds_cookies_and_headers():
    engine, name, _ = engine_for(_BASE, cookies={"SID": "xyz"},
                                 headers={"X-API-Key": "k"}, client_factory=_factory())
    ident = engine.identity(name)
    assert ident.auth_headers["X-API-Key"] == "k"
    assert "SID=xyz" in (ident.jar.header_for(_BASE + "/x") or "")
    assert ident.authenticated is True          # cookies imply an established session


def test_engine_for_warns_on_missing_token_env():
    engine, _name, warns = engine_for(_BASE, token_env="NOPE", env={},
                                      client_factory=_factory())
    assert any("NOPE" in w for w in warns)


def test_engine_for_reuses_live_session_and_its_identity():
    live = SessionEngine(FakeClient(lambda *a: resp(200)))
    ident = Identity(name="session", authenticated=True)
    ident.set_bearer("JWT")
    live.add_identity(ident)

    engine, name, warns = engine_for(_BASE, session=live, client_factory=_factory())
    assert engine is live                       # reused, not rebuilt
    assert name == "session"                    # the authenticated identity
    assert warns == []


def test_engine_for_live_session_anonymous_only_falls_back_to_anonymous():
    live = SessionEngine(FakeClient(lambda *a: resp(200)))   # only "anonymous"
    engine, name, _ = engine_for(_BASE, session=live)
    assert engine is live and name == "anonymous"


# ─────────────────────────── merged_auth_headers ───────────────────────────

def test_merged_headers_from_live_session_identity():
    live = SessionEngine(FakeClient(lambda *a: resp(200)))
    ident = Identity(name="session", authenticated=True)
    ident.set_bearer("JWT")
    ident.jar.set("SID", "v", "app.test")
    live.add_identity(ident)

    out = merged_auth_headers(_BASE + "/api", session=live)
    assert out["Authorization"] == "Bearer JWT"
    assert "SID=v" in out["Cookie"]


def test_merged_headers_from_explicit_cookies_and_headers():
    out = merged_auth_headers(_BASE, cookies={"a": "1", "b": "2"},
                              headers={"X-Auth": "t"})
    assert out["X-Auth"] == "t"
    assert out["Cookie"] == "a=1; b=2"


def test_merged_headers_empty_when_nothing_to_attach():
    assert merged_auth_headers(_BASE) == {}
    # an anonymous-only engine yields nothing either
    live = SessionEngine(FakeClient(lambda *a: resp(200)))
    assert merged_auth_headers(_BASE, session=live) == {}
