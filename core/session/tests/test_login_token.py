"""Tests for the CSRF-token form login (R4) and the hidden-input scraper."""
from __future__ import annotations

from types import SimpleNamespace

from core.session.login import FormLoginWithToken, extract_input_value


def test_extract_input_value_order_and_quote_agnostic():
    assert extract_input_value(
        '<input type="hidden" name="user_token" value="ABC123">', "user_token"
    ) == "ABC123"
    # value before name, single quotes
    assert extract_input_value(
        "<input value='tok9' name='user_token' type='hidden'>", "user_token"
    ) == "tok9"
    # unquoted value
    assert extract_input_value("<input name=user_token value=xyz>", "user_token") == "xyz"
    # absent
    assert extract_input_value("<form><input name='u'></form>", "user_token") is None


class _FakeIdentity:
    def __init__(self, name="session"):
        self.name = name
        self.authenticated = False


def _engine(get_html: bytes, post_status: int = 302, post_body: bytes = b"Welcome"):
    calls = []

    class _E:
        def request(self, identity, method, url, *, body=None, headers=None,
                    follow_redirects=False):
            calls.append(SimpleNamespace(method=method, url=url, body=body,
                                         follow_redirects=follow_redirects))
            if method == "GET":
                return SimpleNamespace(status=200, body=get_html)
            return SimpleNamespace(status=post_status, body=post_body)

    return _E(), calls


def test_form_login_with_token_scrapes_then_posts():
    html = (b'<form><input type="hidden" name="user_token" value="TOK-42">'
            b'<input name="username"></form>')
    eng, calls = _engine(html)
    ident = _FakeIdentity()
    strat = FormLoginWithToken(
        "http://lab/login.php",
        {"username": "admin", "password": "pw", "Login": "Login"},
        token_field="user_token",
    )
    strat.apply(eng, ident)
    assert [c.method for c in calls] == ["GET", "POST"]
    post = calls[1]
    assert b"user_token=TOK-42" in post.body        # scraped token merged in
    assert b"username=admin" in post.body
    assert ident.authenticated is True              # 302 < 400 → default success


def test_success_predicate_can_reject_via_body():
    # A login page returned again (failure) must not count as authenticated.
    html = b'<form><input type="hidden" name="user_token" value="T"></form>'
    eng, _ = _engine(html, post_status=200, post_body=b'<input name="user_token">Login failed')
    ident = _FakeIdentity()
    strat = FormLoginWithToken(
        "http://lab/login.php", {"u": "a"}, token_field="user_token",
        success=lambda r: r.status < 400 and b"Login failed" not in (r.body or b""),
    )
    strat.apply(eng, ident)
    assert ident.authenticated is False


def test_absent_token_still_posts_gracefully():
    eng, calls = _engine(b"<form><input name='u'></form>", post_status=200, post_body=b"ok")
    ident = _FakeIdentity()
    strat = FormLoginWithToken("http://lab/login", {"u": "a"}, token_field="user_token")
    strat.apply(eng, ident)
    post = [c for c in calls if c.method == "POST"][0]
    assert b"user_token" not in post.body           # nothing to scrape → not added
    assert ident.authenticated is True
