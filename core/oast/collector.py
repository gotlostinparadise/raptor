"""A bundled, self-hosted OAST collector — turn-key out-of-band confirmation.

The blind-injection classes (SSRF / XXE / blind cmdi / OOB SQLi / RFI) confirm
*only* when the target calls home: the callback is the proof. That needs a
collaborator to receive the callback and a poll endpoint to read it back. The
hosted interactsh service is one option; this module is the **zero-dependency,
self-hosted** one — a stdlib :class:`~http.server.ThreadingHTTPServer` that plays
both roles at once, so a run can stand up its own collaborator with no external
service:

  - any inbound request is treated as a victim calling home; the correlation
    token is recovered from the ``Host`` header label (``<token>.<domain>`` — the
    scheme :class:`core.oast.client.Correlation` mints), else the first path
    label (``/<token>/…``), else a ``?token=`` / ``?id=`` query param, so both
    host-based and path-based callbacks correlate;
  - ``GET <poll_path>?token=<t>`` returns ``{"interactions": [...]}`` in the exact
    shape :class:`core.oast.backend.HttpPollBackend` expects.

The **advertised callback domain is decoupled from the local poll endpoint**: the
poll always happens on loopback, while ``domain`` is whatever address the target
can reach (a wildcard DNS name pointed at this host, the Docker-bridge ip:port for
a container lab, etc.). Point ``*.<domain>`` at the box running RAPTOR and blind
findings confirm end-to-end.

Reachability caveat: a host-label callback (``http://<token>.<domain>/``) needs
``<token>.<domain>`` to *resolve* to this collector — i.e. wildcard DNS. When the
target can only be given a bare ip:port, use a path-token payload (the collector
correlates ``/<token>`` too). Loopback confirmation is exercised end to end by
``core/oast/tests/test_collector.py``.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import parse_qs, urlparse

from core.oast.backend import HttpPollBackend
from core.oast.interaction import PROTO_HTTP


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class _CollectorHandler(BaseHTTPRequestHandler):
    """Receives victim callbacks; serves the collector JSON on ``poll_path``."""

    # silence the default one-line-per-request stderr spam
    def log_message(self, *a: Any) -> None:  # pragma: no cover - noise control
        return

    # server carries: recorded (list), lock, poll_path, advertise_domain
    def _server(self) -> Any:
        return self.server

    def _json(self, obj: Any) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _host_header(self) -> str:
        return (self.headers.get("Host") or "").split(":", 1)[0].lower()

    def _token_from(self, parsed: Any) -> str:
        """Recover a correlation token from host label, path, or query."""
        srv = self._server()
        domain = (srv.advertise_domain or "").lower().split(":", 1)[0]
        # 1. Host header: <token>.<domain> — the label left of the domain.
        host = self._host_header()
        if domain and host.endswith("." + domain):
            return host[: -(len(domain) + 1)].rsplit(".", 1)[-1]
        # 2. first path segment: /<token>/...
        seg = parsed.path.strip("/").split("/", 1)[0]
        if seg:
            return seg
        # 3. explicit ?token= / ?id=
        q = parse_qs(parsed.query)
        for k in ("token", "id"):
            if q.get(k):
                return q[k][0]
        return ""

    def _record(self, parsed: Any) -> None:
        srv = self._server()
        token = self._token_from(parsed)
        host = self._host_header() or srv.advertise_domain
        # Reconstruct the interactsh-style host so OastClient.token_of() can pull
        # the token from the host label even for a path/query callback.
        if token and (not srv.advertise_domain or token not in host):
            host = f"{token}.{srv.advertise_domain}"
        row = {
            "protocol": PROTO_HTTP,
            "token": token,
            "host": host,
            "remote-address": self.client_address[0],
            "timestamp": _now_iso(),
            "raw-request": f"{self.command} {self.path}",
        }
        with srv.lock:
            srv.recorded.append(row)

    def _serve_poll(self, parsed: Any) -> None:
        srv = self._server()
        wanted = parse_qs(parsed.query).get("token", [""])[0]
        with srv.lock:
            if not wanted:
                rows = list(srv.recorded)
            else:
                rows = [r for r in srv.recorded
                        if r.get("token") == wanted
                        or wanted in (r.get("host") or "")
                        or wanted in (r.get("raw-request") or "")]
        self._json({"interactions": rows})

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == self._server().poll_path:
            self._serve_poll(parsed)
            return
        # Anything else is a callback: record it, then 200 so the victim's fetch
        # completes cleanly (a hung request could mask the injection).
        self._record(parsed)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_HEAD = _handle


class _LoopbackPollClient:
    """A plain loopback poll client for :class:`HttpPollBackend`.

    The production :class:`core.http.urllib_backend.UrllibClient` is egress-
    allowlisted and would refuse 127.0.0.1, so the self-poll uses a direct
    ``urlopen`` — the collector and the poll live in the same process on loopback.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def get_json(self, url: str, retries: int = 0) -> Dict[str, Any]:
        import urllib.request
        with urllib.request.urlopen(url, timeout=self.timeout) as r:  # noqa: S310 (loopback)
            return json.loads(r.read().decode("utf-8"))


class OastCollector:
    """Self-hosted OAST collaborator + poll endpoint (context manager).

    ``advertise_domain`` is the callback domain payloads embed (what the target
    reaches); it defaults to the loopback ``host:port`` when unset. The poll
    endpoint is always local. Use as a context manager::

        with OastCollector(advertise_domain="oast.lab") as col:
            client = OastClient(col.backend())
            ...   # run injection with this client; blind hits confirm
    """

    def __init__(
        self,
        advertise_domain: Optional[str] = None,
        *,
        bind_host: str = "127.0.0.1",
        port: int = 0,
        poll_path: str = "/poll",
    ) -> None:
        self.bind_host = bind_host
        self.poll_path = poll_path
        self._requested_domain = advertise_domain
        self._srv: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._port = port

    # ------------------------------------------------------------------
    def start(self) -> "OastCollector":
        if self._srv is not None:
            return self
        srv = ThreadingHTTPServer((self.bind_host, self._port), _CollectorHandler)
        srv.recorded = []                       # type: ignore[attr-defined]
        srv.lock = threading.Lock()             # type: ignore[attr-defined]
        srv.poll_path = self.poll_path          # type: ignore[attr-defined]
        self._port = srv.server_address[1]
        srv.advertise_domain = (                # type: ignore[attr-defined]
            self._requested_domain or f"{self.bind_host}:{self._port}")
        self._srv = srv
        self._thread = threading.Thread(target=srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None
            self._thread = None

    def __enter__(self) -> "OastCollector":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ------------------------------------------------------------------
    @property
    def port(self) -> int:
        return self._port

    @property
    def domain(self) -> str:
        """The advertised callback domain payloads embed."""
        if self._srv is not None:
            return self._srv.advertise_domain      # type: ignore[attr-defined]
        return self._requested_domain or f"{self.bind_host}:{self._port}"

    @property
    def poll_url(self) -> str:
        return f"http://{self.bind_host}:{self._port}{self.poll_path}"

    def recorded(self) -> List[Dict[str, Any]]:
        """Snapshot of interactions received so far (for tests / diagnostics)."""
        if self._srv is None:
            return []
        with self._srv.lock:                      # type: ignore[attr-defined]
            return list(self._srv.recorded)       # type: ignore[attr-defined]

    def backend(self, client: Any = None) -> HttpPollBackend:
        """An :class:`HttpPollBackend` polling this collector over loopback."""
        return HttpPollBackend(self.domain, self.poll_url, client or _LoopbackPollClient())


@contextmanager
def running_collector(advertise_domain: Optional[str] = None,
                      **kw: Any) -> Iterator[OastCollector]:
    """Convenience context manager yielding a started :class:`OastCollector`."""
    col = OastCollector(advertise_domain, **kw)
    try:
        yield col.start()
    finally:
        col.stop()


__all__ = ["OastCollector", "running_collector"]
