"""Tests for core.webgraph.scope — URL/endpoint canonicalisation."""

from core.webgraph.scope import (
    canonical_origin, canonical_url, endpoint_id, in_scope, normalise_path,
    split_url, strip_query,
)


def test_canonical_origin_lowercases_and_drops_default_port():
    assert canonical_origin("HTTPS://Example.com:443/a?b=1") == "https://example.com"
    assert canonical_origin("http://Example.com:80/") == "http://example.com"


def test_canonical_origin_keeps_nondefault_port():
    assert canonical_origin("https://x.com:8443/a") == "https://x.com:8443"


def test_canonical_origin_empty_for_relative():
    assert canonical_origin("/just/a/path") == ""


def test_normalise_path_templatises_numeric_and_uuid_and_hexblob():
    assert normalise_path("/api/Users/42/orders/7") == "/api/Users/{id}/orders/{id}"
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert normalise_path(f"/o/{uuid}") == "/o/{id}"
    assert normalise_path("/t/deadbeefdeadbeef01") == "/t/{id}"


def test_normalise_path_preserves_route_case_and_strips_trailing_slash():
    assert normalise_path("/API/Health/") == "/API/Health"
    assert normalise_path("/") == "/"
    assert normalise_path("") == "/"


def test_endpoint_id_uppercases_method_and_templatises():
    assert endpoint_id("get", "/api/users/1") == "GET /api/users/{id}"
    # different object ids collapse to one endpoint id — the BOLA-enabling merge
    assert endpoint_id("GET", "/api/users/2") == endpoint_id("get", "/api/users/9")


def test_endpoint_id_defaults_method():
    assert endpoint_id("", "/x") == "GET /x"


def test_in_scope_is_same_origin():
    origins = ["https://app.example.com"]
    assert in_scope("https://app.example.com/dash", origins)
    assert not in_scope("https://evil.com/x", origins)
    # different port is a different origin
    assert not in_scope("https://app.example.com:8443/x", origins)


def test_split_url_returns_origin_and_path():
    assert split_url("https://x.com/a/b?c=1") == ("https://x.com", "/a/b")
    assert split_url("https://x.com") == ("https://x.com", "/")


def test_strip_query_removes_query_and_fragment():
    assert strip_query("https://x.com/a?b=1#frag") == "https://x.com/a"


def test_canonical_url_joins_origin_and_path_drops_query():
    assert canonical_url("https://X.com:443/a/?q=1#f") == "https://x.com/a"
    assert canonical_url("/relative") is None
