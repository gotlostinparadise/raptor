"""Track 1 — SPA hash-route DOM-XSS chain.

A single-page app routes off the URL *fragment* (``/#/search?q=…``), which the
server never sees. These tests pin the end-to-end representation the DOM-XSS
oracle needs: parse a hash-route → model it as a ``fragment``-located endpoint →
harvest it as an injection point → rebuild ``…/#/search?q=<payload>``. The
capture → graph → harvest → URL-build chain used to drop the fragment at every
hop; this is the regression guard.
"""

import json

from core.browser.capture import PageCapture, records_from_capture
from core.injection.config import (
    InjectionPoint, build_target_url, points_from_webgraph,
)
from core.webgraph import model as M
from core.webgraph.scope import (
    endpoint_id, fragment_route, is_spa_path, spa_endpoint_path,
    spa_route_of_path,
)


# ─────────────────────────── scope helpers ───────────────────────────

def test_fragment_route_parses_hash_route_with_query():
    assert fragment_route("http://h/#/search?q=x&p=2") == (
        "/search", [("q", "x"), ("p", "2")])


def test_fragment_route_none_for_plain_anchor_and_no_fragment():
    assert fragment_route("http://h/page#section") is None   # in-page anchor
    assert fragment_route("http://h/rest/products?q=x") is None  # real query
    assert fragment_route("http://h/") is None


def test_spa_endpoint_path_roundtrip():
    p = spa_endpoint_path("/search")
    assert p == "/#/search" and is_spa_path(p)
    assert spa_route_of_path(p) == "/search"
    assert spa_route_of_path("/rest/x") is None


def test_spa_endpoint_id_templatises_route_object_ids():
    # a route object id collapses just like a REST path id
    assert endpoint_id("GET", spa_endpoint_path("/products/42")) == "GET /#/products/{id}"


# ─────────────────────────── capture projection ───────────────────────────

def test_capture_emits_fragment_endpoint_and_param_from_final_url():
    cap = PageCapture(url="http://h/", final_url="http://h/#/search?q=test")
    recs = records_from_capture(cap, source="browser_crawl")
    eps = {e["path"] for e in recs.get("endpoints", [])}
    assert "/#/search" in eps
    frag_params = [p for p in recs.get("parameters", [])
                   if p["location"] == M.LOC_FRAGMENT]
    assert any(p["name"] == "q" and p["endpoint_id"] == "GET /#/search"
               for p in frag_params)


def test_capture_emits_fragment_endpoint_from_hash_route_link():
    cap = PageCapture(url="http://h/", final_url="http://h/",
                      links=["http://h/#/profile?id=5"])
    recs = records_from_capture(cap)
    assert "/#/profile" in {e["path"] for e in recs.get("endpoints", [])}


def test_capture_ignores_plain_anchor_links():
    cap = PageCapture(url="http://h/", final_url="http://h/",
                      links=["http://h/docs#intro"])
    recs = records_from_capture(cap)
    assert not any(e["path"].startswith("/#") for e in recs.get("endpoints", []))


# ─────────────────────────── harvest ───────────────────────────

def test_points_from_webgraph_harvests_fragment_location(tmp_path):
    ndir = tmp_path / "normalized"
    ndir.mkdir()
    (ndir / "endpoints.jsonl").write_text(
        json.dumps({"method": "GET", "path": "/#/search"}) + "\n", encoding="utf-8")
    (ndir / "parameters.jsonl").write_text(
        json.dumps({"endpoint_id": "GET /#/search", "name": "q",
                    "location": "fragment"}) + "\n", encoding="utf-8")
    points = points_from_webgraph(ndir)
    frag = [p for p in points if p.location == "fragment"]
    assert len(frag) == 1
    assert frag[0].path == "/#/search" and frag[0].param == "q"


# ─────────────────────────── URL build ───────────────────────────

def test_build_target_url_splices_into_fragment_query():
    pt = InjectionPoint(method="GET", path="/#/search", param="q", location="fragment")
    url = build_target_url("http://h", pt, "<iframe>")
    assert url == "http://h/#/search?q=%3Ciframe%3E"


def test_build_target_url_query_still_uses_real_query_string():
    pt = InjectionPoint(method="GET", path="/rest/products", param="q", location="query")
    url = build_target_url("http://h", pt, "x")
    assert url == "http://h/rest/products?q=x"     # fragment path untouched
