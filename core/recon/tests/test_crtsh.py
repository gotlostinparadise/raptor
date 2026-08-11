"""Tests for core.recon.crtsh — fully offline via a stub HttpClient."""

import pytest

from core.http import HttpError
from core.recon import crtsh as C
from core.recon.source import Assets, PROFILES, RunContext


class StubHttp:
    """Minimal HttpClient stand-in: maps a URL to a payload or an exception."""

    def __init__(self, responses=None, default=None):
        self.responses = responses or {}
        self.default = default
        self.calls = []

    def get_json(self, url, timeout=30, *, headers=None, max_bytes=None, **kwargs):
        self.calls.append({"url": url, "max_bytes": max_bytes, "timeout": timeout})
        outcome = self.responses.get(url, self.default)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome is None:
            raise HttpError("stub: no response", status=404)
        return outcome


def _ctx(http, roots=("x.com",), profile="home"):
    captured = {}

    def factory(hosts):
        captured["hosts"] = hosts
        return http

    ctx = RunContext(
        roots=roots,
        assets=Assets(),
        profile=PROFILES[profile],
        raw_dir="/tmp/raw",
        normalized_dir="/tmp/norm",
        http_factory=factory,
    )
    ctx._captured = captured   # for the egress-allowlist assertion
    return ctx


def _crtsh_row(name_value):
    return {"name_value": name_value, "common_name": name_value.split("\n")[0]}


# ─────────────────────────── declarations ───────────────────────────

def test_source_declares_egress_and_no_credentials():
    assert C.CrtShSource.egress_hosts == ("crt.sh",)
    assert C.CrtShSource.credential_env_vars == ()
    assert C.CrtShSource.produces == ("subdomains",)
    assert C.CrtShSource.active is False


def test_registered_in_registry():
    from core.recon import source as S
    assert S.get_source("crtsh") is C.CrtShSource


def test_http_client_is_allowlisted_to_crtsh():
    http = StubHttp(default=[])
    ctx = _ctx(http)
    C.CrtShSource().run(ctx)
    assert ctx._captured["hosts"] == ["crt.sh"]


# ─────────────────────────── parsing / scope ───────────────────────────

def test_extracts_in_scope_names_and_populates_discovered():
    url = "https://crt.sh/?q=%25.x.com&output=json"
    http = StubHttp(responses={url: [
        _crtsh_row("a.x.com"),
        _crtsh_row("b.x.com\nc.x.com"),   # multi-SAN, newline-joined
        _crtsh_row("*.wild.x.com"),        # wildcard normalised
    ]})
    res = C.CrtShSource().run(_ctx(http))
    names = {r["name"] for r in res.records["subdomains"]}
    assert names == {"a.x.com", "b.x.com", "c.x.com", "wild.x.com"}
    assert res.discovered.names == names
    assert all(r["sources"] == ["crtsh"] for r in res.records["subdomains"])


def test_out_of_scope_and_lookalike_names_are_dropped():
    url = "https://crt.sh/?q=%25.x.com&output=json"
    http = StubHttp(responses={url: [
        _crtsh_row("a.x.com"),
        _crtsh_row("evil.com"),
        _crtsh_row("notx.com"),     # label-aware: must NOT match x.com
    ]})
    res = C.CrtShSource().run(_ctx(http))
    names = {r["name"] for r in res.records["subdomains"]}
    assert names == {"a.x.com"}


def test_apex_is_not_emitted_as_subdomain():
    url = "https://crt.sh/?q=%25.x.com&output=json"
    http = StubHttp(responses={url: [_crtsh_row("x.com"), _crtsh_row("a.x.com")]})
    res = C.CrtShSource().run(_ctx(http))
    names = {r["name"] for r in res.records["subdomains"]}
    assert names == {"a.x.com"}


def test_dedupes_repeated_names_across_certs():
    url = "https://crt.sh/?q=%25.x.com&output=json"
    http = StubHttp(responses={url: [_crtsh_row("a.x.com")] * 5})
    res = C.CrtShSource().run(_ctx(http))
    assert len(res.records.get("subdomains", [])) == 1


# ─────────────────────────── request shape / failure ───────────────────────────

def test_request_lifts_size_cap():
    http = StubHttp(default=[])
    C.CrtShSource().run(_ctx(http))
    assert http.calls[0]["max_bytes"] == C.MAX_RESPONSE_BYTES


def test_http_error_records_failure_without_aborting_other_roots():
    good = "https://crt.sh/?q=%25.good.com&output=json"
    bad = "https://crt.sh/?q=%25.bad.com&output=json"
    http = StubHttp(responses={
        good: [_crtsh_row("a.good.com")],
        bad: HttpError("boom", status=503),
    })
    res = C.CrtShSource().run(_ctx(http, roots=("good.com", "bad.com")))
    assert res.failed == ["bad.com"]
    assert res.error is not None
    assert {r["name"] for r in res.records["subdomains"]} == {"a.good.com"}
    assert res.requested == 2


def test_multiple_roots_queried_independently():
    http = StubHttp(default=[])
    res = C.CrtShSource().run(_ctx(http, roots=("a.com", "b.com")))
    queried = {c["url"] for c in http.calls}
    assert queried == {
        "https://crt.sh/?q=%25.a.com&output=json",
        "https://crt.sh/?q=%25.b.com&output=json",
    }
    assert res.requested == 2
