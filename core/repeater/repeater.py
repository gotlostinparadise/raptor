"""A Burp-repeater analog — send a request spec, tamper, resend, diff.

Wraps the HTTP client so a request can be sent, modified, and resent, returning
the response as data (status/headers/body) even on non-2xx — the same
statuses-as-data posture the session engine uses. Tampering lives on
:class:`~core.repeater.request.RequestSpec` (immutable ``with_*`` / ``tamper``),
so a repeat is just "send a tweaked copy".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Optional

from core.http import HttpError, Response
from core.repeater.request import RequestSpec


@dataclass
class Exchange:
    """One send: the spec and the response fingerprint."""

    spec: RequestSpec
    status: Optional[int]
    length: int
    body_sha256: str
    response: Response


class Repeater:
    def __init__(self, client: Any) -> None:
        self.client = client
        self.history: list = []

    def send(self, spec: RequestSpec, *, follow_redirects: bool = False) -> Exchange:
        body = spec.body.encode("utf-8") if spec.body else None
        try:
            resp = self.client.request(spec.method.upper(), spec.url, body=body,
                                       headers=spec.headers or None,
                                       follow_redirects=follow_redirects, retries=0)
        except HttpError as exc:
            resp = Response(status=int(exc.status or 0), headers={}, body=b"", url=spec.url)
        rbody = resp.body or b""
        ex = Exchange(spec=spec, status=resp.status, length=len(rbody),
                      body_sha256=hashlib.sha256(rbody).hexdigest(), response=resp)
        self.history.append(ex)
        return ex

    @staticmethod
    def diff(a: Exchange, b: Exchange) -> dict:
        """Compare two exchanges — the repeater's before/after view of tampering."""
        return {"status_changed": a.status != b.status,
                "length_delta": b.length - a.length,
                "body_changed": a.body_sha256 != b.body_sha256,
                "a": {"status": a.status, "length": a.length},
                "b": {"status": b.status, "length": b.length}}


__all__ = ["Exchange", "Repeater"]
