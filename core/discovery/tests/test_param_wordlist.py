"""Q5 — bare-path endpoints get a common-param wordlist so `/inject` can test them.

A path mined with no observed query params is otherwise a dead end for injection
(no parameter nodes → no injection points). The discovery runner attaches a
curated wordlist to such endpoints — bounded, deduped, and tagged
``source="discovery-wordlist"`` so it stays auditable and never masquerades as an
observed param. Endpoints that already expose a param, and static assets, are
left alone.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.discovery.config import from_dict
from core.discovery.runner import _COMMON_PARAMS, _is_asset, run_discovery
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized fixture"


def _cfg(**kw):
    base = {"base_url": "https://app.test", "authorization": _AUTH, "probe_exposed": False}
    base.update(kw)
    return from_dict(base)


# A base page that references: a bare-path endpoint (no params), an endpoint that
# already carries a query param, and a static asset — all as fetch() strings so
# extract_endpoints harvests them without a separate script fetch.
_INDEX = (
    b'<html><script>'
    b'fetch("/api/lookup");'
    b'fetch("/search?q=hello");'
    b'fetch("/static/vendor.js");'
    b'</script></html>'
)


def _handler(method, url, headers, body):
    if url.rstrip("/").endswith("app.test") or url.endswith("/"):
        return resp(200, body=_INDEX)
    return resp(404, body=b"nope")


def _params(tmp_path) -> list:
    f = Path(tmp_path) / "normalized" / "parameters.jsonl"
    if not f.exists():
        return []
    return [json.loads(l) for l in f.read_text().splitlines() if l.strip()]


def test_bare_path_endpoint_gets_wordlist(tmp_path):
    run = run_discovery(_cfg(), out_dir=tmp_path, active=True,
                        client_factory=lambda hosts: FakeClient(_handler))
    assert run.endpoints_found >= 2
    params = _params(tmp_path)
    by_ep = {}
    for p in params:
        by_ep.setdefault(p["endpoint_id"], []).append(p)

    # the bare path picked up the full wordlist, all tagged as speculative
    lookup = by_ep["GET /api/lookup"]
    assert set(_COMMON_PARAMS) <= {p["name"] for p in lookup}
    assert all(p["source"] == "discovery-wordlist" and p["location"] == "query"
               for p in lookup)

    # the endpoint that already exposed a param is observed-only — no wordlist
    search = by_ep["GET /search"]
    assert {p["name"] for p in search} == {"q"}
    assert all(p["source"] == "discovery" for p in search)


def test_asset_paths_are_skipped():
    assert _is_asset("/static/vendor.js")
    assert _is_asset("/img/logo.PNG")
    assert _is_asset("/app.css?v=2")
    assert not _is_asset("/api/lookup")
    assert not _is_asset("/download")


def test_wordlist_disabled(tmp_path):
    run = run_discovery(_cfg(param_wordlist=False), out_dir=tmp_path, active=True,
                        client_factory=lambda hosts: FakeClient(_handler))
    assert run.endpoints_found >= 2
    assert all(p.get("source") != "discovery-wordlist" for p in _params(tmp_path))


def test_wordlist_cap_bounds_fanout(tmp_path):
    # Many distinct bare paths, cap=2 → only two endpoints get augmented.
    many = b"<html><script>" + b"".join(
        f'fetch("/p{i}");'.encode() for i in range(10)) + b"</script></html>"

    def h(method, url, headers, body):
        if url.rstrip("/").endswith("app.test") or url.endswith("/"):
            return resp(200, body=many)
        return resp(404, body=b"nope")

    run_discovery(_cfg(param_wordlist_cap=2), out_dir=tmp_path, active=True,
                  client_factory=lambda hosts: FakeClient(h))
    wl = [p for p in _params(tmp_path) if p.get("source") == "discovery-wordlist"]
    augmented_eps = {p["endpoint_id"] for p in wl}
    assert len(augmented_eps) == 2
