"""Tests for core.session.login — login strategies."""

from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.login import (
    ApiKeyAuth, BasicAuth, BearerAuth, FormLogin, JsonLogin, resolve_credential,
)
from core.session.tests.fakes import FakeClient, resp


def _engine(handler):
    eng = SessionEngine(FakeClient(handler))
    eng.add_identity(Identity(name="user_a"))
    return eng


def test_bearer_auth_sets_header_and_authenticated():
    eng = _engine(lambda *a: resp(200))
    eng.authenticate("user_a", BearerAuth("jwt.token.here"))
    ident = eng.identity("user_a")
    assert ident.auth_headers["Authorization"] == "Bearer jwt.token.here"
    assert ident.authenticated is True


def test_api_key_and_basic_auth():
    eng = _engine(lambda *a: resp(200))
    eng.authenticate("user_a", ApiKeyAuth("X-API-Key", "k-123"))
    assert eng.identity("user_a").auth_headers["X-API-Key"] == "k-123"

    eng.authenticate("user_a", BasicAuth("bob", "pw"))
    # base64("bob:pw") == "Ym9iOnB3"
    assert eng.identity("user_a").auth_headers["Authorization"] == "Basic Ym9iOnB3"


def test_form_login_posts_and_captures_cookie():
    def handler(method, url, headers, body):
        if url.endswith("/login") and method == "POST":
            assert b"user=bob" in body
            return resp(302, **{"Set-Cookie": "session=LOGGEDIN; Path=/"})
        return resp(200)

    eng = _engine(handler)
    r = eng.authenticate("user_a", FormLogin(
        "https://x.com/login", {"user": "bob", "pass": "pw"}))
    assert r.status == 302
    assert eng.identity("user_a").authenticated is True
    assert eng.identity("user_a").jar.header_for("https://x.com/") == "session=LOGGEDIN"


def test_form_login_failure_marks_unauthenticated():
    eng = _engine(lambda m, u, h, b: resp(401))
    eng.authenticate("user_a", FormLogin("https://x.com/login", {"user": "x"}))
    assert eng.identity("user_a").authenticated is False


def test_json_login_extracts_token_from_body_and_sets_bearer():
    # Juice-Shop-style: POST creds -> {"authentication":{"token":"JWT"}}
    def handler(method, url, headers, body):
        import json
        if url.endswith("/rest/user/login") and method == "POST":
            assert json.loads(body)["email"] == "a@x.test"
            return resp(200, body=b'{"authentication":{"token":"JWT123","umail":"a@x.test"}}')
        # a later request must carry the bearer
        assert headers.get("Authorization") == "Bearer JWT123"
        return resp(200, body=b'{"data":"secret"}')

    eng = _engine(handler)
    eng.authenticate("user_a", JsonLogin(
        "https://x.com/rest/user/login",
        {"email": "a@x.test", "password": "pw"}))
    ident = eng.identity("user_a")
    assert ident.authenticated is True
    assert ident.auth_headers["Authorization"] == "Bearer JWT123"
    # the token flows onto subsequent requests
    eng.request("user_a", "GET", "https://x.com/rest/basket/1")


def test_json_login_fails_cleanly_when_no_token():
    eng = _engine(lambda m, u, h, b: resp(401, body=b'{"error":"invalid"}'))
    eng.authenticate("user_a", JsonLogin("https://x.com/login", {"email": "x"}))
    assert eng.identity("user_a").authenticated is False
    assert "Authorization" not in eng.identity("user_a").auth_headers


def test_resolve_credential_reads_env():
    assert resolve_credential("MY_TOKEN", {"MY_TOKEN": "s3cret"}) == "s3cret"
    assert resolve_credential("MISSING", {}) is None
