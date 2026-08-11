"""Offline tests for the passive URL-history (archive.org) web source."""

from __future__ import annotations

import pytest

from core.webgraph.source import Profile, PROFILES, RunContext, Surface
from core.webgraph.url_history import ARCHIVE_HOST, UrlHistorySource


class _StubHttp:
    def __init__(self, payload, *, expect_hosts=None):
        self.payload = payload
        self.calls = []
        self.expect_hosts = expect_hosts

    def get_json(self, url, timeout=None, *, headers=None, max_bytes=None, **kw):
        self.calls.append(url)
        return self.payload


def _ctx(tmp_path, origins, stub):
    raw = tmp_path / "raw"
    norm = tmp_path / "normalized"
    raw.mkdir(parents=True, exist_ok=True)
    norm.mkdir(parents=True, exist_ok=True)
    captured = {}

    def factory(hosts):
        captured["hosts"] = list(hosts)
        return stub

    ctx = RunContext(
        origins=tuple(origins), surface=Surface(origins=set(origins)),
        profile=PROFILES["passive"], raw_dir=raw, normalized_dir=norm,
        http_factory=factory,
    )
    ctx._captured = captured  # type: ignore[attr-defined]
    return ctx


def test_contract_is_passive_and_allowlisted(tmp_path):
    src = UrlHistorySource()
    assert src.active is False
    assert src.egress_hosts == (ARCHIVE_HOST,)
    assert src.produces == ("origins", "pages", "endpoints", "parameters")
    stub = _StubHttp([["original"]])
    ctx = _ctx(tmp_path, ["https://app.example.com"], stub)
    src.run(ctx)
    # the HttpClient was allowlisted to exactly archive.org
    assert ctx._captured["hosts"] == [ARCHIVE_HOST]


def test_cdx_rows_become_endpoints_params_pages(tmp_path):
    stub = _StubHttp([
        ["original"],   # header row, skipped
        ["https://app.example.com/api/users/42?tab=orders"],
        ["https://app.example.com/api/users/99?tab=profile"],   # merges: same endpoint
        ["https://app.example.com/login"],
        ["https://evil.other.com/x"],   # out of scope -> dropped
    ])
    ctx = _ctx(tmp_path, ["https://app.example.com"], stub)
    r = UrlHistorySource().run(ctx)

    eids = {e["path"] for e in r.records["endpoints"]}
    # /api/users/42 and /99 collapse to one templated endpoint node id
    ep_ids = r.discovered.endpoints
    assert "GET /api/users/{id}" in ep_ids
    assert "GET /login" in ep_ids
    # both query params captured on the users endpoint
    params = {(p["endpoint_id"], p["name"]) for p in r.records["parameters"]}
    assert ("GET /api/users/{id}", "tab") in params
    # out-of-scope url did not leak in
    assert all("evil.other.com" not in e.get("origin", "") for e in r.records["endpoints"])
    # pages emitted, origin recorded
    assert any(p["url"] == "https://app.example.com/login" for p in r.records["pages"])
    assert r.records["origins"][0]["origin"] == "https://app.example.com"


def test_http_error_is_recorded_not_raised(tmp_path):
    from core.http import HttpError

    class _BoomHttp:
        def get_json(self, *a, **k):
            raise HttpError("boom")

    ctx = _ctx(tmp_path, ["https://app.example.com"], _BoomHttp())
    r = UrlHistorySource().run(ctx)
    assert "app.example.com" in r.failed
    assert "endpoints" not in r.records


def test_not_auto_registered():
    # url_history must NOT be in the global registry (explicit opt-in only)
    from core.webgraph.source import all_sources
    assert "url_history" not in all_sources()
