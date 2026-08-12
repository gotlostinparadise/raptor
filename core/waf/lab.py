"""A self-contained WAF-fronted vulnerable app, for exercising evasion (N3).

A single loopback HTTP server that first applies a naive WAF rule (403 on a bare
SQL keyword) and, for requests that slip through, runs a boolean-SQLi-vulnerable
handler (the ``q`` param branches the response). Front it with ``/inject --adapt``
(or drive it from a test) to confirm **end-to-end over real sockets** that
WAF-evasion — the mixed-case / comment-split transforms in
:mod:`core.waf.evasion` — lets a blocked payload through where the raw one is
rejected. No external infra, no system packages; 127.0.0.1 only.

Run as a lab:  ``python -m core.waf.lab``  → prints a URL to point ``/inject`` at.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlsplit

# A naive signature WAF: blocks a bare, space-delimited SQL keyword. The
# evasion transforms (mixed-case ``aNd``, comment-split ``AN/**/D``, tabbed
# whitespace) all defeat it — which is exactly the point.
_WAF_RE = re.compile(r"\b(?:AND|OR|UNION|SELECT)\b")


def _blocked(q: str) -> bool:
    return bool(_WAF_RE.search(q)) and "/**/" not in q and "\t" not in q


def _handler_class():
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):        # keep the lab quiet
            pass

        def do_GET(self):                     # noqa: N802 (http.server API)
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            if _blocked(q):
                return self._send(403, "Request blocked by WAF")
            # Vulnerable past the WAF: a quote + boolean keyword that reached the
            # DB breaks the query (error-based), and the FALSE predicate diverges
            # from the baseline (boolean). The keyword is what the WAF blocks —
            # so only an evasion-encoded variant gets here to trigger either.
            if "'" in q and re.search(r"\b(?:or|and|union|select)\b", q, re.I):
                return self._send(500, "SQLITE_ERROR: near syntax error")
            if "1'='2" in q or "1=2" in q:
                return self._send(200, "no results")
            return self._send(200, "RESULT " * 60)

        def _send(self, code: int, body: str):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return _Handler


class WafLab:
    """A threaded WAF-fronted vulnerable server on loopback (context manager)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.server = ThreadingHTTPServer((host, port), _handler_class())
        self.host = host
        self.port = self.server.server_address[1]
        self.url = f"http://{host}:{self.port}"
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "WafLab":
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def main() -> int:  # pragma: no cover - manual lab entry point
    lab = WafLab(port=0)
    print(f"WAF lab (naive keyword WAF + boolean-SQLi backend) on {lab.url}")
    print(f"  blocked raw:   {lab.url}/?q=1'%20AND%20'1'='1   -> 403")
    print(f"  drive it:      /inject --url {lab.url} --active --authorization '...' "
          f"--classes sqli --adapt")
    print("Ctrl-C to stop.")
    with lab:
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            return 0
    return 0


__all__ = ["WafLab", "main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
