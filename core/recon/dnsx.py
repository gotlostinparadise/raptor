"""dnsx source — active DNS resolution of known names.

Takes the names a run already knows about (roots + passively-discovered
subdomains) and resolves them: A / AAAA / CNAME, plus the response status. This
is the stage that turns a name list into IPs the rest of the pipeline (Censys
enrichment, naabu port scan, httpx probe) can act on.

It sends real DNS queries *about the target's names*, so it is ``active = True``
and the ``passive`` profile blocks it. Resolution uses UDP/53, which cannot
traverse the HTTPS egress proxy, so this runs under
:func:`core.recon.toolrunner.run_net_tool` (network-open, read-restricted). The
per-run rate and concurrency come off the safety :class:`Profile`'s knobs
(``dns_rate`` / ``dns_threads``) — the enum-lite envelope that keeps a home
router's NAT table intact.

Every emitted :class:`~core.recon.model.DnsRecord` is stamped
``discovery = DISCOVERY_ACTIVE`` so the builder labels these findings correctly
without any filename inference (see :mod:`core.recon.model` design note).
"""

from __future__ import annotations

from typing import Any, List, Optional

from core.recon.model import DISCOVERY_ACTIVE, DnsRecord
from core.recon.scope import in_scope, normalise_name
from core.recon.source import RunContext, Source, SourceResult, register
from core.recon.toolrunner import parse_jsonl, run_net_tool, tool_available

BINARY = "dnsx"
TIMEOUT_SECONDS = 900
# DNS is UDP/53; DoH resolvers and TCP-fallback use 443/53 over TCP.
TCP_PORTS = (53, 443)


@register
class DnsxSource(Source):
    name = "dnsx"
    egress_hosts = ()
    credential_env_vars = ()
    consumes = ("names",)
    produces = ("dns",)
    active = True

    binary = BINARY

    def __init__(self, runner: Optional[Any] = None) -> None:
        self._run = runner or run_net_tool

    def available(self, ctx: RunContext) -> bool:
        return super().available(ctx) and tool_available(self.binary)

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        names = sorted(
            n for n in ctx.assets.names if in_scope(normalise_name(n), ctx.roots)
        )
        if not names:
            return result

        names_file = ctx.raw_path("dnsx-names.txt")
        names_file.write_text("\n".join(names) + "\n", encoding="utf-8")
        result.requested = len(names)

        knobs = ctx.profile.knobs
        cmd = [
            self.binary, "-l", str(names_file),
            "-a", "-aaaa", "-cname", "-resp", "-json", "-silent",
            "-rate-limit", str(knobs.get("dns_rate", 300)),
            "-threads", str(knobs.get("dns_threads", 25)),
        ]
        tr = self._run(cmd, output=ctx.raw_dir, tcp_ports=list(TCP_PORTS),
                       timeout=TIMEOUT_SECONDS, env=ctx.env)
        if tr.timed_out:
            result.error = "dnsx timed out"
        if not tr.stdout:
            if tr.returncode and not result.error:
                result.error = f"dnsx exit {tr.returncode}: {tr.stderr[:200]}"
            return result

        raw = ctx.raw_path("dnsx.jsonl")
        raw.write_text(tr.stdout, encoding="utf-8")
        result.raw_path = raw

        for row in parse_jsonl(tr.stdout):
            host = normalise_name(row.get("host") or "")
            if not host:
                continue
            a: List[str] = list(row.get("a") or [])
            aaaa: List[str] = list(row.get("aaaa") or [])
            cname: List[str] = [normalise_name(c) for c in (row.get("cname") or []) if c]
            status = row.get("status_code") or row.get("status")
            result.add(DnsRecord(
                name=host, a=a, aaaa=aaaa, cname=[c for c in cname if c],
                status=str(status) if status else None,
                discovery=DISCOVERY_ACTIVE,
            ))
            result.discovered.ips.update(a)
            result.discovered.ips.update(aaaa)
            # A CNAME target inside scope is another name worth resolving.
            for c in cname:
                if c and in_scope(c, ctx.roots):
                    result.discovered.names.add(c)

        return result


__all__ = ["DnsxSource", "BINARY"]
