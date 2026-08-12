"""A scriptable fake HttpClient for session-engine tests — no network.

The engine only calls :meth:`request`; the other :class:`core.http.HttpClient`
protocol methods are stubbed so the fake still satisfies the type. A test passes
a ``handler(method, url, headers, body) -> Response`` and inspects ``calls``.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

from core.http import Response


class FakeClient:
    def __init__(self, handler: Callable[[str, str, Dict[str, str], Any], Response]) -> None:
        self.handler = handler
        self.calls: List[Tuple[str, str, Dict[str, str]]] = []

    def request(self, method: str, url: str, *, body=None, headers=None,
                timeout: int = 30, max_bytes: int = 0, total_timeout: int = 600,
                retries: int = 0, follow_redirects: bool = True,
                raise_on_status: bool = True) -> Response:
        # raise_on_status accepted to match the HttpClient protocol (the pentest
        # session passes it through); the handler returns any status as data.
        h = dict(headers or {})
        self.calls.append((method.upper(), url, h))
        return self.handler(method.upper(), url, h, body)

    # --- unused protocol surface (engine never calls these) ---
    def get_json(self, *a, **k): raise NotImplementedError
    def post_json(self, *a, **k): raise NotImplementedError
    def get_bytes(self, *a, **k): raise NotImplementedError
    def stream_bytes(self, *a, **k): raise NotImplementedError


def resp(status: int, body: bytes = b"", url: str = "", **headers) -> Response:
    """Build a Response with lowercased headers (as the real backend stores)."""
    return Response(status=status, headers={k.lower(): v for k, v in headers.items()},
                    body=body, url=url)


__all__ = ["FakeClient", "resp"]
