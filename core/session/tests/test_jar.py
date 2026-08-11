"""Tests for core.session.jar — the pragmatic cookie jar."""

from core.session.jar import CookieJar


def test_set_and_header_for_same_host():
    j = CookieJar()
    j.set("session", "abc", "app.x.com")
    assert j.header_for("https://app.x.com/dash") == "session=abc"


def test_update_from_response_parses_set_cookie():
    j = CookieJar()
    j.update_from_response("https://app.x.com/login", "session=xyz; Path=/; HttpOnly")
    assert j.header_for("https://app.x.com/") == "session=xyz"


def test_host_suffix_match_but_not_cross_site():
    j = CookieJar()
    j.set("t", "1", "x.com")
    assert j.header_for("https://api.x.com/") == "t=1"      # subdomain gets it
    assert j.header_for("https://evil.com/") is None         # other site does not


def test_path_prefix_match_longest_first():
    j = CookieJar()
    j.set("a", "1", "x.com", "/")
    j.set("b", "2", "x.com", "/admin")
    hdr = j.header_for("https://x.com/admin/panel")
    assert hdr == "b=2; a=1"                                  # longer path first
    assert j.header_for("https://x.com/public") == "a=1"     # /admin excluded


def test_max_age_zero_deletes():
    j = CookieJar()
    j.set("session", "abc", "x.com")
    j.update_from_response("https://x.com/logout", "session=; Max-Age=0")
    assert j.header_for("https://x.com/") is None


def test_names_and_clear():
    j = CookieJar()
    j.set("a", "1", "x.com")
    j.set("b", "2", "x.com")
    assert j.names() == ["a", "b"]
    j.clear()
    assert j.names() == []
