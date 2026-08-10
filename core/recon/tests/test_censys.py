"""Tests for core.recon.censys — fully offline.

Every test injects a stub HttpClient, so nothing here starts the egress
proxy or touches the network. The stub records the requests it was
handed, which is how the UA / auth / URL-shape assertions work.
"""

import json

import pytest

from core.http import HttpError
from core.recon import censys as C


class StubHttp:
    """Minimal HttpClient stand-in.

    ``responses`` maps a URL to either a payload dict (returned) or an
    exception instance (raised). ``default`` covers anything unmapped.
    """

    def __init__(self, responses=None, default=None):
        self.responses = responses or {}
        self.default = default
        self.calls = []

    def get_json(self, url, timeout=30, *, headers=None, **kwargs):
        self.calls.append({"url": url, "headers": dict(headers or {}),
                           "timeout": timeout, "kwargs": kwargs})
        outcome = self.responses.get(url, self.default)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome is None:
            raise HttpError("stub: no response configured", status=404)
        return outcome


def _host_payload(**overrides):
    payload = {
        "result": {
            "resource": {
                "ip": "203.0.113.10",
                "services": [
                    {"port": 443, "protocol": "HTTPS",
                     "software": [{"product": "nginx", "vendor": "F5"}],
                     "tls": {"certificates": {"leaf_data": {"names": [
                         "*.example.com", "api.example.com",
                         "notexample.com", "other.net"]}}}},
                    {"port": 22, "transport_protocol": "TCP",
                     "software": [{"vendor": "OpenBSD"}]},
                ],
                "autonomous_system": {"asn": 64496, "name": "EXAMPLE-AS"},
                "whois": {"organization": {"name": "Whois Org"}},
                "location": {"country": "Germany", "city": "Berlin"},
            }
        }
    }
    payload["result"]["resource"].update(overrides)
    return payload


def _client(stub, key="censys_secret_key"):
    return C.CensysClient(key, http=stub)


# --- request shape ---------------------------------------------------

def test_sends_non_default_user_agent():
    """Cloudflare 403s the stdlib UA (error 1010) — ours must be sent."""
    stub = StubHttp(default=_host_payload())
    _client(stub).lookup_host("203.0.113.10")
    ua = stub.calls[0]["headers"]["User-Agent"]
    assert ua == C.CENSYS_USER_AGENT
    assert "urllib" not in ua.lower()


def test_sends_bearer_auth_and_no_org_id():
    stub = StubHttp(default=_host_payload())
    _client(stub, "censys_abc123").lookup_host("203.0.113.10")
    call = stub.calls[0]
    assert call["headers"]["Authorization"] == "Bearer censys_abc123"
    assert call["headers"]["Accept"] == "application/json"
    # Free tier: lookups take no organization ID anywhere.
    assert not any("org" in k.lower() for k in call["headers"])
    assert "organization" not in call["url"]


def test_uses_free_tier_lookup_endpoints_not_search():
    stub = StubHttp(default={"result": {}})
    client = _client(stub)
    client.lookup_host("203.0.113.10")
    client.lookup_certificate("a" * 64)
    client.lookup_web_property("example.com:443")
    urls = [c["url"] for c in stub.calls]
    assert urls[0] == f"{C.CENSYS_BASE}/asset/host/203.0.113.10"
    assert urls[1] == f"{C.CENSYS_BASE}/asset/certificate/{'a' * 64}"
    assert urls[2] == f"{C.CENSYS_BASE}/asset/web-property/example.com%3A443"
    # /search/query is paid + needs an org ID; we must never call it.
    assert not any("search" in u for u in urls)


def test_path_segment_is_encoded():
    """A dirty asset id from a run artifact must not reshape the URL."""
    stub = StubHttp(default={"result": {}})
    _client(stub).lookup_host("../../admin")
    segment = stub.calls[0]["url"].split("/asset/host/")[1]
    # Separators encoded away, so the traversal can't climb the path.
    assert "/" not in segment
    assert segment == "..%2F..%2Fadmin"


# --- parsing ---------------------------------------------------------

def test_parse_host_extracts_services_asn_org_country():
    record, _ = C.parse_host(_host_payload(), "203.0.113.10", ["example.com"])
    assert record["ip"] == "203.0.113.10"
    assert record["asn"] == 64496
    assert record["org"] == "EXAMPLE-AS"
    assert record["country"] == "Germany"
    assert record["city"] == "Berlin"
    assert record["services"] == [
        {"port": 443, "proto": "HTTPS", "software": "nginx"},
        {"port": 22, "proto": "TCP", "software": "OpenBSD"},
    ]


def test_parse_host_extracts_in_scope_cert_sans_only():
    record, names = C.parse_host(
        _host_payload(), "203.0.113.10", ["example.com"])
    # Wildcard stripped, in-scope kept; the lookalike and the unrelated
    # domain are both dropped.
    assert names == ["api.example.com", "example.com"]
    assert record["names"] == names
    assert "notexample.com" not in names
    assert "other.net" not in names


def test_presents_domain_cert_flag():
    in_scope, _ = C.parse_host(_host_payload(), "1.1.1.1", ["example.com"])
    assert in_scope["presents_domain_cert"] is True
    out_of_scope, _ = C.parse_host(_host_payload(), "1.1.1.1", ["elsewhere.io"])
    assert out_of_scope["presents_domain_cert"] is False
    assert out_of_scope["names"] == []


def test_parse_host_tolerates_missing_location():
    payload = _host_payload(location={})
    record, _ = C.parse_host(payload, "1.1.1.1", [])
    assert record["country"] is None
    assert record["city"] is None


def test_parse_host_falls_back_to_whois_org():
    payload = _host_payload(autonomous_system={"asn": 64496})
    record, _ = C.parse_host(payload, "1.1.1.1", [])
    assert record["org"] == "Whois Org"


def test_parse_host_accepts_flat_result_shape():
    """Some responses omit the `resource` wrapper."""
    payload = {"result": {"ip": "198.51.100.5",
                          "services": [{"port": 80, "protocol": "HTTP"}]}}
    record, _ = C.parse_host(payload, "198.51.100.5", [])
    assert record["ip"] == "198.51.100.5"
    assert record["services"] == [{"port": 80, "proto": "HTTP",
                                   "software": None}]


def test_parse_host_tolerates_empty_and_malformed_payloads():
    for payload in ({}, {"result": None}, {"result": {"services": None}},
                    {"result": {"resource": {"services": ["not-a-dict"]}}}):
        record, names = C.parse_host(payload, "192.0.2.1", ["example.com"])
        assert record["ip"] == "192.0.2.1"
        assert record["services"] == []
        assert names == []


def test_certificate_names_alternate_shapes():
    for tls in ({"leaf_data": {"names": ["a.example.com"]}},
                {"names": ["a.example.com"]},
                {"certificates": {"leaf_data": {"names": ["a.example.com"]}}}):
        payload = {"result": {"resource": {"services": [
            {"port": 443, "protocol": "HTTPS", "tls": tls}]}}}
        _, names = C.parse_host(payload, "1.1.1.1", ["example.com"])
        assert names == ["a.example.com"]


def test_in_scope_is_label_aware():
    assert C.in_scope("example.com", ["example.com"])
    assert C.in_scope("a.b.example.com", ["example.com"])
    assert not C.in_scope("notexample.com", ["example.com"])
    assert not C.in_scope("example.com.evil.net", ["example.com"])


# --- failure handling ------------------------------------------------

@pytest.mark.parametrize("status,message", [
    (403, "Forbidden"),
    (429, "Too Many Requests"),
    (404, "Not Found"),
    (500, "Server Error"),
])
def test_lookup_returns_none_on_http_error(status, message):
    stub = StubHttp(default=HttpError(message, status=status))
    client = _client(stub)
    assert client.lookup_host("203.0.113.10") is None
    assert client.last_error and message in client.last_error


def test_enrichment_continues_past_a_failed_lookup():
    ok = f"{C.CENSYS_BASE}/asset/host/203.0.113.10"
    stub = StubHttp(responses={ok: _host_payload()},
                    default=HttpError("Forbidden", status=403))
    result = C.enrich_hosts(
        ["198.51.100.1", "203.0.113.10", "198.51.100.2"],
        ["example.com"],
        client=_client(stub), delay=0)
    assert result.requested == 3
    assert [h["ip"] for h in result.hosts] == ["203.0.113.10"]
    assert result.failed == ["198.51.100.1", "198.51.100.2"]


def test_enrich_hosts_unions_names_and_paces_calls():
    slept = []
    stub = StubHttp(default=_host_payload())
    result = C.enrich_hosts(["1.1.1.1", " ", "2.2.2.2"], ["example.com"],
                            client=_client(stub), delay=0.6,
                            sleep=slept.append)
    assert result.requested == 2
    assert result.names == ["api.example.com", "example.com"]
    assert result.service_count == 4
    # Free tier: serial, paced — one sleep per lookup.
    assert slept == [0.6, 0.6]


def test_client_rejects_empty_key():
    with pytest.raises(C.MissingCredential):
        C.CensysClient("", http=StubHttp())


# --- credentials -----------------------------------------------------

def test_resolve_api_key_prefers_environment(monkeypatch):
    monkeypatch.setenv("CENSYS_API_KEY", "censys_from_env")
    assert C.resolve_api_key() == "censys_from_env"


def test_resolve_api_key_reads_credentials_file(monkeypatch, tmp_path):
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_CENSYS_CREDENTIALS", raising=False)
    monkeypatch.delenv("RAPTOR_DIR", raising=False)
    creds = tmp_path / ".censys"
    creds.write_text('API_KEY="censys_from_file"\n')
    monkeypatch.setenv("RAPTOR_CENSYS_CREDENTIALS", str(creds))
    assert C.resolve_api_key() == "censys_from_file"


def test_resolve_api_key_reads_raptor_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_CENSYS_CREDENTIALS", raising=False)
    (tmp_path / ".censys").write_text('export API_KEY=censys_unquoted\n')
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    assert C.resolve_api_key() == "censys_unquoted"


def test_missing_key_raises_with_locations_not_values(monkeypatch, tmp_path):
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_CENSYS_CREDENTIALS", raising=False)
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    monkeypatch.setattr(C.Path, "home", staticmethod(lambda: tmp_path))
    with pytest.raises(C.MissingCredential) as exc:
        C.resolve_api_key()
    assert "CENSYS_API_KEY" in str(exc.value)
    assert str(tmp_path / ".censys") in str(exc.value)


def test_key_never_appears_in_records_or_errors():
    key = "censys_super_secret_value"
    stub = StubHttp(default=_host_payload())
    result = C.enrich_hosts(["1.1.1.1"], ["example.com"],
                            client=_client(stub, key), delay=0)
    assert key not in json.dumps(result.hosts)

    failing = _client(StubHttp(default=HttpError("Forbidden", status=403)), key)
    failing.lookup_host("1.1.1.1")
    assert key not in (failing.last_error or "")


def test_key_is_not_in_the_safe_env_allowlist():
    """get_safe_env() must not hand the key to subprocesses."""
    from core.config import RaptorConfig
    assert "CENSYS_API_KEY" not in RaptorConfig.SAFE_ENV_ALLOWLIST
    env = RaptorConfig.get_safe_env()
    assert "CENSYS_API_KEY" not in env


# --- egress + output -------------------------------------------------

def test_default_client_is_egress_allowlisted_to_censys(monkeypatch):
    """The client must route via the proxy with a one-host allowlist."""
    captured = {}

    class FakeEgress:
        def __init__(self, hosts, user_agent=None):
            captured["hosts"] = list(hosts)
            captured["user_agent"] = user_agent

    import core.http.egress_backend as backend
    monkeypatch.setattr(backend, "EgressClient", FakeEgress)
    C.default_client()
    assert captured["hosts"] == [C.CENSYS_HOST]
    assert captured["user_agent"] == C.CENSYS_USER_AGENT


def test_jsonl_round_trip_matches_documented_schema(tmp_path):
    record, _ = C.parse_host(_host_payload(), "203.0.113.10", ["example.com"])
    out = tmp_path / "censys-hosts.jsonl"
    assert C.write_jsonl(out, [record]) == 1
    loaded = [json.loads(l) for l in out.read_text().splitlines()]
    assert loaded == [record]
    assert set(loaded[0]) == {"ip", "services", "names", "asn", "org",
                              "country", "city", "presents_domain_cert"}
    assert set(loaded[0]["services"][0]) == {"port", "proto", "software"}


def test_read_ips_skips_blanks_and_comments(tmp_path):
    f = tmp_path / "ips.txt"
    f.write_text("1.1.1.1\n\n# a comment\n  2.2.2.2  \n")
    assert C.read_ips(f) == ["1.1.1.1", "2.2.2.2"]


# --- source plugin ---------------------------------------------------

from pathlib import Path  # noqa: E402

from core.recon import source as S  # noqa: E402
from core.recon.model import RECORD_KINDS  # noqa: E402


def _source(delay=0):
    """CensysSource with the free-tier pace disabled — tests must not sleep."""
    src = C.CensysSource()
    src.delay = delay
    return src


def _ctx(tmp_path, ips=("203.0.113.10",), roots=("example.com",),
         credentials=None, stub=None, profile="passive"):
    """RunContext wired to a stub HttpClient — never touches the network."""
    return S.RunContext(
        roots=tuple(roots),
        assets=S.Assets(ips=set(ips)),
        profile=S.PROFILES[profile],
        raw_dir=tmp_path / "raw",
        normalized_dir=tmp_path / "normalized",
        credentials=credentials if credentials is not None
        else {"CENSYS_API_KEY": "censys_ctx_key"},
        http_factory=lambda hosts: stub if stub is not None else StubHttp(),
    )


def test_source_is_registered_with_declared_contract():
    cls = S.get_source("censys")
    assert cls is C.CensysSource
    assert cls.egress_hosts == (C.CENSYS_HOST,)
    assert cls.credential_env_vars == ("CENSYS_API_KEY",)
    assert cls.consumes == ("ips",)
    assert cls.produces == ("hosts", "ports", "certs")
    # Passive: traffic goes to Censys, never to the target.
    assert cls.active is False
    assert all(kind in RECORD_KINDS for kind in cls.produces)


def test_source_runs_in_every_profile():
    src = C.CensysSource()
    for name in S.PROFILES:
        assert src.enabled_for(S.PROFILES[name]) is True


def test_source_http_client_is_allowlisted_to_censys(tmp_path):
    captured = {}
    stub = StubHttp(default=_host_payload())

    def factory(hosts):
        captured["hosts"] = list(hosts)
        return stub

    ctx = _ctx(tmp_path, stub=stub)
    ctx.http_factory = factory
    _source().run(ctx)
    assert captured["hosts"] == [C.CENSYS_HOST]


def test_source_emits_normalized_records(tmp_path):
    stub = StubHttp(default=_host_payload())
    result = _source().run(_ctx(tmp_path, stub=stub))

    assert result.source == "censys"
    assert result.error is None
    assert result.requested == 1
    # Assert the fields Censys populates, not exact dict equality: the
    # model is owned by the framework and grows additively (edge_kind /
    # edge_name arrived from the cdncheck path), and a source must not
    # break every time a field it doesn't fill is added.
    (host,) = result.records["hosts"]
    assert {k: host[k] for k in ("ip", "asn", "org", "country", "city")} == {
        "ip": "203.0.113.10", "asn": "AS64496", "org": "EXAMPLE-AS",
        "country": "Germany", "city": "Berlin"}
    # Fields Censys has no data for stay at their model defaults.
    assert host.get("edge_kind", "") == ""
    assert host.get("edge_name", "") == ""
    assert result.records["ports"] == [
        {"ip": "203.0.113.10", "port": 443, "proto": "HTTPS",
         "software": "nginx", "source": "censys"},
        {"ip": "203.0.113.10", "port": 22, "proto": "TCP",
         "software": "OpenBSD", "source": "censys"},
    ]
    assert result.records["certs"] == [
        {"source": "censys", "names": ["api.example.com", "example.com"],
         "ip": "203.0.113.10", "sha256": None, "issuer": None},
    ]


def test_source_feeds_cert_names_back_into_discovery(tmp_path):
    stub = StubHttp(default=_host_payload())
    result = _source().run(_ctx(tmp_path, stub=stub))
    # In-scope SANs are new subdomain surface for the next round.
    assert result.discovered.names == {"api.example.com", "example.com"}
    assert result.discovered.ips == {"203.0.113.10"}


def test_source_omits_cert_record_when_nothing_in_scope(tmp_path):
    stub = StubHttp(default=_host_payload())
    result = _source().run(_ctx(tmp_path, stub=stub,
                                       roots=("elsewhere.io",)))
    assert "certs" not in result.records
    assert result.discovered.names == set()
    assert result.records["ports"]  # ports still land


def test_source_writes_raw_provenance(tmp_path):
    stub = StubHttp(default=_host_payload())
    result = _source().run(_ctx(tmp_path, stub=stub))
    assert result.raw_path == tmp_path / "raw" / "censys-hosts.jsonl"
    rows = [json.loads(l) for l in result.raw_path.read_text().splitlines()]
    # Raw file keeps the documented host schema, unchanged by normalisation.
    assert set(rows[0]) == {"ip", "services", "names", "asn", "org",
                            "country", "city", "presents_domain_cert"}


def test_source_looks_up_ips_in_deterministic_order(tmp_path):
    stub = StubHttp(default=_host_payload())
    ctx = _ctx(tmp_path, ips=("198.51.100.9", "203.0.113.10", "192.0.2.1"),
               stub=stub)
    _source().run(ctx)
    looked_up = [c["url"].rsplit("/", 1)[1] for c in stub.calls]
    assert looked_up == sorted(looked_up)


def test_source_records_failures_without_raising(tmp_path):
    stub = StubHttp(default=HttpError("Forbidden", status=403))
    result = _source().run(_ctx(tmp_path, ips=("1.1.1.1", "2.2.2.2"),
                                       stub=stub))
    assert result.requested == 2
    assert result.failed == ["1.1.1.1", "2.2.2.2"]
    assert result.records == {}
    assert result.error is None  # per-asset failure, not source failure


def test_source_reports_missing_key_instead_of_raising(tmp_path, monkeypatch):
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_CENSYS_CREDENTIALS", raising=False)
    monkeypatch.delenv("RAPTOR_DIR", raising=False)
    monkeypatch.setattr(C.Path, "home", staticmethod(lambda: tmp_path))
    result = _source().run(_ctx(tmp_path, credentials={}))
    assert result.error and "API key" in result.error
    assert result.records == {}


def test_availability_sees_the_file_based_credential(tmp_path, monkeypatch):
    """A key in $RAPTOR_DIR/.censys must not read as 'unavailable'."""
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_CENSYS_CREDENTIALS", raising=False)
    monkeypatch.setattr(C.Path, "home", staticmethod(lambda: tmp_path))
    src = _source()

    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    ctx = _ctx(tmp_path, credentials={})
    assert src.available(ctx) is False          # no env var, no file yet

    (tmp_path / ".censys").write_text('API_KEY="censys_from_file"\n')
    assert src.available(ctx) is True           # file alone is enough


def test_source_key_never_reaches_records_or_raw(tmp_path):
    key = "censys_super_secret_value"
    stub = StubHttp(default=_host_payload())
    ctx = _ctx(tmp_path, stub=stub, credentials={"CENSYS_API_KEY": key})
    result = _source().run(ctx)
    assert key not in json.dumps(result.records)
    assert key not in result.raw_path.read_text()
