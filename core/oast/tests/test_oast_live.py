"""Live loopback proof for core.oast — a real out-of-band callback, end to end.

The other OAST tests inject interactions synthetically (``backend.record(...)`` /
a fake poll client), which pins the correlation *logic* but never exercises a
real network round-trip. Blind-vulnerability confirmation is the one place where
"the callback IS the proof", so the transport deserves a genuine test.

This stands up a loopback HTTP *collaborator* that plays both roles a real one
does: it receives the victim's callback (a real HTTP request carrying the
correlation token) and it serves the collector JSON that
:class:`~core.oast.backend.HttpPollBackend` polls. The whole chain then runs over
real sockets — callback reception → collector storage → real-socket poll →
token correlation → confirmed :class:`VulnRecord` proof → graph edge.

Loopback only (127.0.0.1, ephemeral port); deterministic and self-contained, so
it runs in the normal gate rather than being gated behind ``integration``.
"""

import json
import threading
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import count
from urllib.parse import parse_qs, urlparse

from core.oast.backend import HttpPollBackend
from core.oast.client import OastClient
from core.oast.interaction import PROTO_HTTP
from core.oast.outcome import vuln_record
from core.webgraph import model as M
from core.webgraph.builder import build_graph

_COLLAB_DOMAIN = "oast.local"


def _seq_tokens():
    c = count(1)
    return lambda: f"tok{next(c)}"


class _Collaborator(BaseHTTPRequestHandler):
    """A network-real OAST collaborator: records callbacks, serves the collector.

    - ``GET /poll?token=<t>`` → ``{"interactions": [<rows carrying t>]}`` — the
      shape :class:`HttpPollBackend` expects.
    - any other path ``/<token>`` → treat as the victim calling home; record it
      as an HTTP interaction keyed by ``<token>.<domain>``.
    """

    def log_message(self, *a):  # silence the default stderr spam
        pass

    def _json(self, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/poll":
            wanted = parse_qs(parsed.query).get("token", [""])[0]
            rows = [r for r in self.server.recorded  # type: ignore[attr-defined]
                    if wanted and wanted in r["host"]]
            self._json({"interactions": rows})
            return
        # A callback: the token is the first path label the "SSRF victim" fetched.
        token = parsed.path.strip("/").split("/", 1)[0]
        self.server.recorded.append({  # type: ignore[attr-defined]
            "protocol": "http",
            "host": f"{token}.{_COLLAB_DOMAIN}",
            "remote-address": self.client_address[0],
            "timestamp": "2026-01-01T00:00:00Z",
            "raw-request": f"GET {self.path}",
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


@contextmanager
def _collaborator():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Collaborator)
    srv.recorded = []  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


class _UrllibClient:
    """A REAL http client (loopback socket round-trip).

    The point of this test is to exercise :class:`HttpPollBackend`'s actual poll
    transport, so this is a genuine ``urlopen`` rather than a fake ``get_json``.
    """

    def get_json(self, url, retries=0):
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))


def _fire_callback(base, token):
    """Simulate the vulnerable server fetching the attacker's callback URL."""
    with urllib.request.urlopen(f"{base}/{token}", timeout=5) as r:
        r.read()


def test_live_http_callback_correlates_to_confirmed_proof():
    with _collaborator() as base:
        backend = HttpPollBackend(_COLLAB_DOMAIN, base + "/poll", _UrllibClient())
        client = OastClient(backend, token_gen=_seq_tokens())
        c = client.new_interaction(finding_id="blind-ssrf-1")   # tok1

        # No callback has arrived yet: a real poll must not fabricate a hit.
        assert client.poll() == []

        _fire_callback(base, c.token)                            # victim calls home

        hits = client.poll()                                     # real-socket poll
        assert len(hits) == 1
        hit = hits[0]
        assert hit.token == "tok1"
        assert hit.protocol == PROTO_HTTP
        assert hit.remote_addr in ("127.0.0.1", "::1")           # observed egress IP
        assert client.finding_for(hit.token) == "blind-ssrf-1"

        row = vuln_record(hits, vuln_id="OAST-LIVE-1", vuln_class="blind_ssrf",
                          endpoint_id="POST /fetch", owasp="API7")

    # The callback is the verdict: confirmed, with the OAST proof kind.
    assert row["status"] == M.STATUS_CONFIRMED
    assert row["proof_kind"] == M.PROOF_OAST_CALLBACK
    assert row["evidence"]["callback_count"] == 1
    assert row["evidence"]["protocols"] == ["http"]

    g = build_graph({M.VulnRecord.KIND: [row]})
    assert ("vuln", "OAST-LIVE-1") in g.nodes
    assert (("endpoint", "POST /fetch"), ("vuln", "OAST-LIVE-1"),
            M.REL_VULNERABLE_TO) in g.edges


def test_live_poll_drops_callback_for_an_unminted_token():
    """A real callback whose token we never minted must not correlate — the
    collector may see anyone's traffic; only our tokens are our proof."""
    with _collaborator() as base:
        backend = HttpPollBackend(_COLLAB_DOMAIN, base + "/poll", _UrllibClient())
        client = OastClient(backend, token_gen=_seq_tokens())
        client.new_interaction(finding_id="blind-ssrf-1")        # tok1 (ours)

        _fire_callback(base, "somebodyelse")                     # not our token

        assert client.poll() == []                               # dropped
