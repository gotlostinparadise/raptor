"""Proof-of-concept generation — turn a request spec into a runnable PoC.

RAPTOR's exploit-generation ethos, at the web layer: a finding is more useful as a
*runnable* artifact than as prose. :func:`to_curl` emits a copy-paste curl;
:func:`to_python` emits a self-contained stdlib script (no third-party deps, so it
runs anywhere). Both are pure string builders — no network.
"""

from __future__ import annotations

import shlex

from core.repeater.request import RequestSpec


def to_curl(spec: RequestSpec) -> str:
    """A single-line ``curl`` command reproducing the request."""
    parts = ["curl", "-i", "-s", "-X", spec.method, shlex.quote(spec.url)]
    for k, v in spec.headers.items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if spec.body:
        parts += ["--data-raw", shlex.quote(spec.body)]
    return " ".join(parts)


def to_python(spec: RequestSpec) -> str:
    """A self-contained Python 3 stdlib PoC script (urllib)."""
    body_line = (f"data = {spec.body!r}.encode()" if spec.body else "data = None")
    header_lines = "\n".join(
        f"req.add_header({k!r}, {v!r})" for k, v in spec.headers.items())
    return f'''#!/usr/bin/env python3
"""Auto-generated PoC — reproduces one request. Review before running."""
import urllib.request, urllib.error

{body_line}
req = urllib.request.Request({spec.url!r}, data=data, method={spec.method!r})
{header_lines}
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print("status:", r.status)
        print(r.read().decode("utf-8", "replace")[:2000])
except urllib.error.HTTPError as e:
    print("status:", e.code)
    print(e.read().decode("utf-8", "replace")[:2000])
'''


def to_http_raw(spec: RequestSpec) -> str:
    """A raw HTTP/1.1 request (Burp-repeater style), for reference/replay."""
    from urllib.parse import urlsplit
    parts = urlsplit(spec.url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    lines = [f"{spec.method} {path} HTTP/1.1", f"Host: {parts.hostname}"]
    for k, v in spec.headers.items():
        # Strip CR/LF so a header value can't inject extra request lines into
        # the generated raw-HTTP artifact.
        safe_k = str(k).replace("\r", "").replace("\n", "")
        safe_v = str(v).replace("\r", "").replace("\n", "")
        lines.append(f"{safe_k}: {safe_v}")
    body = spec.body or ""
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def generate(spec: RequestSpec, fmt: str = "curl") -> str:
    return {"curl": to_curl, "python": to_python, "http": to_http_raw}[fmt](spec)


__all__ = ["to_curl", "to_python", "to_http_raw", "generate"]
