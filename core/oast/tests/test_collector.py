"""Q6 — the bundled self-hosted OAST collector, exercised over real loopback sockets.

The collector plays both collaborator roles: it receives the victim's callback
and serves the poll JSON :class:`~core.oast.backend.HttpPollBackend` reads. This
test drives the whole blind-confirmation chain over genuine sockets — callback
reception → collector storage → real-socket poll → token correlation → confirmed
:data:`~core.webgraph.model.PROOF_OAST_CALLBACK` proof — for both the host-label
callback scheme (``<token>.<domain>``) and a path-token callback (``/<token>``).
"""

from __future__ import annotations

import urllib.request

from core.oast.client import OastClient
from core.oast.collector import OastCollector, running_collector
from core.oast.interaction import PROTO_HTTP
from core.oast.outcome import vuln_record
from core.webgraph import model as M


def _fire(url: str, host_header: str = "") -> None:
    """Simulate the vulnerable target fetching the attacker's callback URL."""
    headers = {"Host": host_header} if host_header else {}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback)
        r.read()


def test_no_callback_no_proof():
    with running_collector("oast.lab") as col:
        client = OastClient(col.backend())
        client.new_interaction(finding_id="blind-ssrf")
        assert client.poll() == []          # a real poll never fabricates a hit


def test_host_label_callback_confirms():
    with running_collector("oast.lab") as col:
        client = OastClient(col.backend())
        c = client.new_interaction(finding_id="blind-ssrf-1")
        # host = <token>.oast.lab per the interactsh scheme; the target resolves
        # it to us and the HTTP request carries it in the Host header.
        assert c.host == f"{c.token}.oast.lab"
        _fire(f"http://127.0.0.1:{col.port}/", host_header=c.host)

        hits = client.poll()
        assert len(hits) == 1
        assert hits[0].token == c.token
        assert hits[0].protocol == PROTO_HTTP
        assert hits[0].remote_addr in ("127.0.0.1", "::1")
        assert client.finding_for(hits[0].token) == "blind-ssrf-1"

        row = vuln_record(hits, vuln_id="OAST-1", vuln_class="blind_ssrf",
                          endpoint_id="POST /fetch", owasp="API7")
    assert row["status"] == M.STATUS_CONFIRMED
    assert row["proof_kind"] == M.PROOF_OAST_CALLBACK
    assert row["evidence"]["callback_count"] == 1


def test_path_token_callback_confirms():
    # When the target can only reach a bare ip:port, the token rides in the path.
    with running_collector("oast.lab") as col:
        client = OastClient(col.backend())
        c = client.new_interaction(finding_id="blind-rce")
        _fire(f"http://127.0.0.1:{col.port}/{c.token}/rce")

        hits = client.poll()
        assert len(hits) == 1 and hits[0].token == c.token
        assert client.finding_for(hits[0].token) == "blind-rce"


def test_only_matching_token_returned():
    # Two findings; only the one that actually called home confirms.
    with running_collector("oast.lab") as col:
        client = OastClient(col.backend())
        a = client.new_interaction(finding_id="A")
        client.new_interaction(finding_id="B")
        _fire(f"http://127.0.0.1:{col.port}/", host_header=a.host)

        grouped = client.confirmations()
        assert set(grouped) == {"A"}


def test_advertise_domain_defaults_to_bind_addr():
    col = OastCollector().start()
    try:
        assert col.domain == f"127.0.0.1:{col.port}"
        assert col.poll_url == f"http://127.0.0.1:{col.port}/poll"
    finally:
        col.stop()
