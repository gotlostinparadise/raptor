"""Tests for core.http_crawl.parse — HTML → links / forms / fields extraction."""

from core.http_crawl.parse import parse_page

_BASE = "https://app.test/dir/index.php"


def test_links_resolved_absolute_and_relative():
    html = """<a href="/a">a</a> <a href="b.php">b</a>
              <a href="https://app.test/c">c</a>"""
    page = parse_page(html, _BASE)
    assert "https://app.test/a" in page.links
    assert "https://app.test/dir/b.php" in page.links          # relative to page dir
    assert "https://app.test/c" in page.links


def test_non_navigational_hrefs_skipped():
    html = """<a href="#top">top</a><a href="javascript:void(0)">x</a>
              <a href="mailto:a@b.c">mail</a><a href="/real">real</a>"""
    page = parse_page(html, _BASE)
    assert page.links == ["https://app.test/real"]


def test_get_form_fields_and_method():
    html = """<form action="/search" method="GET">
                <input name="q"><input type="submit"></form>"""
    page = parse_page(html, _BASE)
    assert len(page.forms) == 1
    f = page.forms[0]
    assert f.action == "https://app.test/search" and f.method == "GET"
    assert f.fields == ["q"]                     # unnamed submit input excluded


def test_post_form_multiple_field_kinds():
    html = """<form action="login.php" method="post">
                <input name="user"><input name="pass">
                <select name="role"><option>a</option></select>
                <textarea name="note"></textarea>
                <button name="go">go</button></form>"""
    page = parse_page(html, _BASE)
    f = page.forms[0]
    assert f.action == "https://app.test/dir/login.php" and f.method == "POST"
    assert f.fields == ["user", "pass", "role", "note", "go"]


def test_form_with_no_action_submits_to_self():
    page = parse_page('<form method="post"><input name="id"></form>', _BASE)
    assert page.forms[0].action == _BASE and page.forms[0].fields == ["id"]


def test_title_and_malformed_html_degrades():
    page = parse_page("<title>My App</title><a href=/x>x<form><input name=q>", _BASE)
    assert page.title == "My App"
    assert "https://app.test/x" in page.links
    assert page.forms and page.forms[0].fields == ["q"]
