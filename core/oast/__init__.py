"""OAST — out-of-band application security testing (the collaborator primitive).

A huge fraction of high-severity web/API bugs are *blind*: the payload fires but
the response body shows nothing. Blind SSRF, blind RCE, blind XXE, out-of-band
SQLi, and DNS exfiltration are detectable only by a callback server that the
target reaches out to. This subsystem is that primitive, and it is deliberately
"server optional":

  - :mod:`core.oast.client` — mints correlation tokens (``<token>.<domain>``),
    hands out payloads, and correlates observed interactions back to findings.
  - :mod:`core.oast.backend` — the pluggable collaborator: :class:`InMemoryBackend`
    (network-free; tests + a local self-hosted listener) or :class:`HttpPollBackend`
    (polls a self-hosted JSON collector over the egress-allowlisted HttpClient).
    A full interactsh-protocol backend slots in as one more subclass.
  - :mod:`core.oast.payloads` — blind-injection payloads embedding the callback.
  - :mod:`core.oast.interaction` — the :class:`Interaction` record.
  - :mod:`core.oast.outcome` — adapter to a :mod:`core.webgraph` proof
    (``PROOF_OAST_CALLBACK``): the callback is the verdict.

No mandatory public domain to start: the in-memory backend works offline, and
the HTTP-poll backend points at whatever collector the operator runs.
"""

from core.oast.backend import HttpPollBackend, InMemoryBackend, OastBackend
from core.oast.client import Correlation, OastClient
from core.oast.interaction import Interaction

__all__ = [
    "OastClient", "Correlation", "OastBackend", "InMemoryBackend",
    "HttpPollBackend", "Interaction",
]
