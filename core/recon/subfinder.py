"""subfinder source — passive subdomain discovery via a wrapped binary.

subfinder aggregates ~dozens of passive data sources (CT logs, passive-DNS
APIs, search engines) behind one tool. Because every query goes to a *third
party* and never to the target's own infrastructure, this source is
``active = False`` and runs under every safety profile, exactly like the
in-process :mod:`core.recon.crtsh` source — subfinder is simply a much wider
aggregator.

Unlike the passive HTTP sources, subfinder fans out to many upstream API hosts,
so its egress cannot be pinned to a small allowlist through the HTTPS proxy.
It therefore runs under :func:`core.recon.toolrunner.run_net_tool`
(``block_network=False`` + ``restrict_reads=True``): the child can reach the
network but cannot read ``$HOME`` / credentials, and its argv is built here from
the in-scope roots — never from attacker input. Any API keys subfinder uses live
in *its own* config file, not RAPTOR's environment.

Emits :class:`~core.recon.model.SubdomainRecord` per in-scope name and feeds
those into ``discovered.names`` for the resolution / recursion loop.
"""

from __future__ import annotations

from typing import Any, Optional, Set

from core.recon.model import SubdomainRecord
from core.recon.scope import in_scope, normalise_name, root_of
from core.recon.source import RunContext, Source, SourceResult, register
from core.recon.toolrunner import parse_jsonl, run_net_tool, tool_available

BINARY = "subfinder"
TIMEOUT_SECONDS = 600


@register
class SubfinderSource(Source):
    name = "subfinder"
    egress_hosts = ()          # shells out; makes no in-process HTTP calls
    credential_env_vars = ()   # subfinder reads its own provider config
    consumes = ("roots",)
    produces = ("subdomains",)
    active = False

    binary = BINARY

    def __init__(self, runner: Optional[Any] = None) -> None:
        self._run = runner or run_net_tool

    def available(self, ctx: RunContext) -> bool:
        return super().available(ctx) and tool_available(self.binary)

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        if not ctx.roots:
            return result

        domains_file = ctx.raw_path("subfinder-domains.txt")
        domains_file.write_text("\n".join(ctx.roots) + "\n", encoding="utf-8")
        result.requested = len(ctx.roots)

        cmd = [self.binary, "-dL", str(domains_file), "-silent", "-oJ"]
        tr = self._run(cmd, output=ctx.raw_dir, tcp_ports=None,
                       timeout=TIMEOUT_SECONDS, env=ctx.env)
        if tr.timed_out:
            result.error = "subfinder timed out"
        if not tr.stdout:
            if tr.returncode and not result.error:
                result.error = f"subfinder exit {tr.returncode}: {tr.stderr[:200]}"
            return result

        raw = ctx.raw_path("subfinder.jsonl")
        raw.write_text(tr.stdout, encoding="utf-8")
        result.raw_path = raw

        seen: Set[str] = set()
        for row in parse_jsonl(tr.stdout):
            host = normalise_name(row.get("host") or "")
            if not host or host in seen or not in_scope(host, ctx.roots):
                continue
            seen.add(host)
            if host in ctx.roots:
                continue   # the apex itself isn't a subdomain node
            result.add(SubdomainRecord(
                name=host, root=root_of(host, ctx.roots), sources=["subfinder"],
            ))
            result.discovered.names.add(host)

        return result


__all__ = ["SubfinderSource", "BINARY"]
