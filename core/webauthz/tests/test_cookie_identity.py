"""Cookie/header auth for authz identities — a browser-supplied session (opaque
cookie + WAF challenge cookies) authenticates an identity, so multi-identity
BOLA/BFLA works against CAPTCHA-gated / cookie-auth APIs without a scriptable
login (the auth strategies only cover bearer/api_key/basic/form/json).
"""

from core.session.tests.fakes import FakeClient, resp
from core.webauthz.config import from_dict
from core.webauthz.runner import build_engine


def _cfg(**extra):
    d = {"base_url": "https://app.test", "authorization": "engagement; authorized",
         "identities": [
             {"name": "user_a",
              "cookies": {"access_token": "aaa", "__ddg1_": "chal"},
              "headers": {"User-Agent": "UA"}},
             {"name": "user_b", "cookies": {"access_token": "bbb"}},
             {"name": "anonymous"}]}
    d.update(extra)
    return from_dict(d)


def test_identity_config_reads_cookies_and_headers():
    ids = {i.name: i for i in _cfg().identities}
    assert ids["user_a"].cookies == {"access_token": "aaa", "__ddg1_": "chal"}
    assert ids["user_a"].headers == {"User-Agent": "UA"}
    assert ids["user_b"].cookies == {"access_token": "bbb"} and not ids["user_b"].headers
    assert not ids["anonymous"].cookies and not ids["anonymous"].headers


def test_build_engine_seeds_cookie_and_header_auth():
    eng, warns = build_engine(_cfg(), FakeClient(lambda *a: resp(200, body=b"ok")))
    a = eng.identity("user_a")
    assert "access_token" in a.jar.names() and "__ddg1_" in a.jar.names()
    assert a.auth_headers.get("User-Agent") == "UA"
    assert a.authenticated is True
    b = eng.identity("user_b")
    assert "access_token" in b.jar.names() and b.authenticated is True
    anon = eng.identity("anonymous")
    assert not anon.jar.names() and not anon.auth_headers
