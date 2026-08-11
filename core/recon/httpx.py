"""httpx source — active HTTP probing + fingerprint of known names.

Takes the in-scope names a run knows about and probes them over HTTP(S):
live-or-not, status, title, server, detected technologies, and the TLS leaf
certificate. This is the stage that populates the ``service`` / ``tech`` layer of
the graph and — via TLS SANs — can surface further in-scope names.

It sends real requests to the target's own services, so it is ``active = True``
and the ``passive`` profile blocks it. Being an HTTP-layer tool, it runs behind
the hostname-allowlisted HTTPS egress proxy
(:func:`core.recon.toolrunner.run_http_tool`): the allowlist is exactly the set
of in-scope names being probed, so the child can reach nothing else. The request
rate comes off the safety :class:`Profile`'s ``http_rate`` knob.

Emits :class:`~core.recon.model.HttpRecord` per live service and
:class:`~core.recon.model.TlsRecord` when a certificate is grabbed; in-scope SAN
names feed ``discovered.names``.

.. note::
   Verification item for the first live run: confirm httpx honours the injected
   ``HTTPS_PROXY``/``http_proxy`` for both name resolution and the request. Under
   the egress proxy the child's own UDP/DNS is blocked, so httpx must resolve via
   the proxy's CONNECT-by-hostname. If a build does not, the fix is local to
   :mod:`core.recon.toolrunner` (fall back to the read-restricted net mode with
   pre-resolved IPs) — the source contract does not change.
"""

from __future__ import annotations

from typing import Any, List, Optional, Set

from core.recon.model import HttpRecord, TlsRecord
from core.recon.scope import in_scope, normalise_name, root_of
from core.recon.source import RunContext, Source, SourceResult, register
from core.recon.toolrunner import parse_jsonl, run_http_tool, tool_available

BINARY = "httpx"
TIMEOUT_SECONDS = 900


def _hostname(row: dict) -> str:
    """Best-effort hostname for an httpx row (``input`` is the fed name)."""
    for key in ("input", "url", "host"):
        val = row.get(key) or ""
        if not val:
            continue
        val = str(val)
        if "://" in val:
            val = val.split("://", 1)[1]
        val = val.split("/", 1)[0].split(":", 1)[0]
        name = normalise_name(val)
        if name:
            return name
    return ""


@register
class HttpxSource(Source):
    name = "httpx"
    egress_hosts = ()
    credential_env_vars = ()
    consumes = ("names",)
    produces = ("http", "tls")
    active = True

    binary = BINARY

    def __init__(self, runner: Optional[Any] = None) -> None:
        self._run = runner or run_http_tool

    def available(self, ctx: RunContext) -> bool:
        return super().available(ctx) and tool_available(self.binary)

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        names = sorted(
            n for n in ctx.assets.names if in_scope(normalise_name(n), ctx.roots)
        )
        if not names:
            return result

        targets_file = ctx.raw_path("httpx-targets.txt")
        targets_file.write_text("\n".join(names) + "\n", encoding="utf-8")
        result.requested = len(names)

        knobs = ctx.profile.knobs
        cmd = [
            self.binary, "-list", str(targets_file),
            "-json", "-silent", "-no-color",
            "-title", "-status-code", "-tech-detect", "-web-server",
            "-tls-grab", "-content-length",
            "-rate-limit", str(knobs.get("http_rate", 10)),
        ]
        # Egress allowlist = exactly the hosts we are probing.
        tr = self._run(cmd, output=ctx.raw_dir, proxy_hosts=names,
                       timeout=TIMEOUT_SECONDS, env=ctx.env)
        if tr.timed_out:
            result.error = "httpx timed out"
        if not tr.stdout:
            if tr.returncode and not result.error:
                result.error = f"httpx exit {tr.returncode}: {tr.stderr[:200]}"
            return result

        raw = ctx.raw_path("httpx.jsonl")
        raw.write_text(tr.stdout, encoding="utf-8")
        result.raw_path = raw

        seen_san: Set[str] = set()
        for row in parse_jsonl(tr.stdout):
            host = _hostname(row)
            if not host:
                continue
            ips: List[str] = list(row.get("a") or [])
            tech = list(row.get("tech") or row.get("technologies") or [])
            status = row.get("status_code") or row.get("status-code")
            result.add(HttpRecord(
                host=host, url=str(row.get("url") or ""),
                status=int(status) if isinstance(status, (int, str)) and str(status).isdigit() else None,
                title=str(row.get("title") or ""),
                server=str(row.get("webserver") or row.get("web_server") or ""),
                tech=tech,
                content_length=row.get("content_length") if isinstance(row.get("content_length"), int) else None,
                ip=ips[0] if ips else None,
            ))

            tls = row.get("tls") or {}
            if isinstance(tls, dict) and tls:
                san = [normalise_name(s) for s in (tls.get("subject_an") or []) if s]
                result.add(TlsRecord(
                    host=host,
                    cn=str(tls.get("subject_cn") or ""),
                    san=[s for s in san if s],
                    issuer=str(tls.get("issuer_cn") or tls.get("issuer_org") or ""),
                ))
                # In-scope SAN names are further subdomains to chase.
                for s in san:
                    if s and s not in seen_san and in_scope(s, ctx.roots) and s not in ctx.roots:
                        seen_san.add(s)
                        result.discovered.names.add(s)

        return result


__all__ = ["HttpxSource", "BINARY"]
