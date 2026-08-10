"""HTTP fingerprint primitive for the exposed-origin and vhost probes.

Both bespoke probes work by hitting ``scheme://host/`` while forcing the
connection to a specific backend IP (``curl --resolve host:port:ip``) and
comparing the response. This module owns that one primitive —
:func:`fingerprint` — so the two sources share it and differ only in their
verdict logic (which lives in the source and is unit-tested with a fake
prober). ``fingerprint`` itself is the network boundary: it shells ``curl``
through :func:`core.recon.toolrunner.run_net_tool` (connecting to an arbitrary
IP means the HTTPS egress proxy's hostname model does not apply, so this uses
the network-open / read-restricted mode with a TCP-port pin of 80/443).

Ported from the prototype ``vhost-sweep.sh`` ``fp()`` helper, field-for-field.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

_TITLE_RE = re.compile(rb"<title[^>]*>([^<]*)", re.IGNORECASE)
_SERVER_RE = re.compile(r"^server:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
# A response whose title/server matches this is an edge/WAF challenge, not the
# real backend — never counts as a reachable vhost or an exposed origin.
CHALLENGE_RE = re.compile(
    r"ddos-guard|just a moment|attention required|challenge|cloudflare",
    re.IGNORECASE,
)


@dataclass
class ProbeResult:
    """One fingerprint of ``scheme://host/`` forced to a backend ``ip``."""

    status: int = 0
    body_sha256: str = ""
    content_length: int = 0
    title: str = ""
    server: str = ""

    @property
    def is_challenge(self) -> bool:
        return bool(CHALLENGE_RE.search(f"{self.title} {self.server}"))


def _port(scheme: str) -> int:
    return 80 if scheme == "http" else 443


def fingerprint(
    scheme: str,
    ip: str,
    host: str,
    *,
    output: Path,
    env: Optional[Mapping[str, str]] = None,
    timeout: int = 10,
    runner: Optional[Any] = None,
) -> ProbeResult:
    """Fetch ``scheme://host/`` with the connection forced to ``ip``.

    Returns a :class:`ProbeResult` (``status`` 0 on connection failure). ``curl``
    writes the header block and body to per-cell temp files under ``output``
    (writable in the sandbox); we read them back, hash the body, and extract the
    title/server, then delete them.
    """
    from core.recon.toolrunner import run_net_tool

    run = runner or run_net_tool
    port = _port(scheme)
    stem = hashlib.sha1(f"{scheme}:{ip}:{host}".encode()).hexdigest()[:16]
    body_file = output / f".probe-{stem}.body"
    hdr_file = output / f".probe-{stem}.hdr"

    cmd = [
        "curl", "-sk", "--max-time", str(timeout),
        "--resolve", f"{host}:{port}:{ip}",
        "-D", str(hdr_file), "-o", str(body_file),
        "-w", "%{http_code}",
        f"{scheme}://{host}/",
    ]
    tr = run(cmd, output=output, tcp_ports=[port], timeout=timeout + 5, env=env)

    try:
        status = int((tr.stdout or "").strip() or 0)
    except ValueError:
        status = 0

    body = body_file.read_bytes() if body_file.exists() else b""
    header = hdr_file.read_text(encoding="utf-8", errors="ignore") if hdr_file.exists() else ""
    for f in (body_file, hdr_file):
        try:
            f.unlink()
        except OSError:
            pass

    sha = hashlib.sha256(body).hexdigest() if body else ""
    title = ""
    m = _TITLE_RE.search(body)
    if m:
        title = m.group(1).decode("utf-8", "ignore").strip()[:80]
    server = ""
    ms = _SERVER_RE.search(header)
    if ms:
        server = ms.group(1).strip()[:80]

    return ProbeResult(status=status, body_sha256=sha, content_length=len(body),
                       title=title, server=server)


__all__ = ["ProbeResult", "fingerprint", "CHALLENGE_RE"]
