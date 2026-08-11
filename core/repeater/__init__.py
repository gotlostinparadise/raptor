"""Repeater / replay + PoC generation — findings as runnable artifacts.

A Burp-repeater analog on top of the RAPTOR HTTP stack: send a
:class:`~core.repeater.request.RequestSpec`, tamper it (headers, query params,
method, body), resend, and diff — plus turn any request into a **runnable PoC**
(a curl one-liner, a self-contained stdlib Python script, or a raw HTTP request),
carrying RAPTOR's exploit-generation ethos to the web layer.

Pieces: :mod:`core.repeater.request` (the tamperable spec),
:mod:`core.repeater.repeater` (send/tamper/diff), :mod:`core.repeater.poc`
(PoC generators), :mod:`core.repeater.cli`.
"""

from core.repeater.poc import generate, to_curl, to_http_raw, to_python
from core.repeater.repeater import Exchange, Repeater
from core.repeater.request import RequestSpec

__all__ = [
    "RequestSpec", "Repeater", "Exchange", "to_curl", "to_python",
    "to_http_raw", "generate",
]
