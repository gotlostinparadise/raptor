"""naabu source — active TCP port scan of known IPs.

Takes the IPs a run has resolved and finds open TCP ports on them, so the graph
carries the non-HTTP surface (SSH, databases, admin panels) a web-only sweep
misses. Uses a **connect** scan (``-s c``) rather than SYN, so it needs no raw
socket / ``CAP_NET_RAW`` and runs unprivileged inside the sandbox.

It connects to the target's own addresses, so it is ``active = True`` and the
``passive`` profile blocks it. A port scanner must reach *arbitrary* TCP ports
by nature, so — unlike dnsx — it cannot be pinned to a small ``allowed_tcp_ports``
set; it runs under :func:`core.recon.toolrunner.run_net_tool` with no TCP-port
restriction. Containment is read-restriction (``$HOME`` denied), resource
rlimits, a sanitised environment, and an argv built here from the in-scope IP
set — never from attacker input.

Emits :class:`~core.recon.model.PortRecord` (``source = "naabu"``). Port findings
add no new identity, so ``discovered`` stays empty.
"""

from __future__ import annotations

from typing import Any, Optional

from core.recon.model import PortRecord
from core.recon.source import RunContext, Source, SourceResult, register
from core.recon.toolrunner import parse_jsonl, run_net_tool, tool_available

BINARY = "naabu"
TIMEOUT_SECONDS = 1200


@register
class NaabuSource(Source):
    name = "naabu"
    egress_hosts = ()
    credential_env_vars = ()
    consumes = ("ips",)
    produces = ("ports",)
    active = True

    binary = BINARY

    def __init__(self, runner: Optional[Any] = None) -> None:
        self._run = runner or run_net_tool

    def available(self, ctx: RunContext) -> bool:
        return super().available(ctx) and tool_available(self.binary)

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        ips = sorted(ctx.assets.ips)
        if not ips:
            return result

        ips_file = ctx.raw_path("naabu-ips.txt")
        ips_file.write_text("\n".join(ips) + "\n", encoding="utf-8")
        result.requested = len(ips)

        knobs = ctx.profile.knobs
        cmd = [
            self.binary, "-list", str(ips_file),
            "-s", "c", "-json", "-silent", "-duc",
            "-rate", str(knobs.get("dns_rate", 300)),
        ]
        tr = self._run(cmd, output=ctx.raw_dir, tcp_ports=None,
                       timeout=TIMEOUT_SECONDS, env=ctx.env)
        if tr.timed_out:
            result.error = "naabu timed out"
        if not tr.stdout:
            if tr.returncode and not result.error:
                result.error = f"naabu exit {tr.returncode}: {tr.stderr[:200]}"
            return result

        raw = ctx.raw_path("naabu.jsonl")
        raw.write_text(tr.stdout, encoding="utf-8")
        result.raw_path = raw

        for row in parse_jsonl(tr.stdout):
            ip = row.get("ip")
            port = row.get("port")
            if not ip or not port:
                continue
            try:
                port_num = int(port)
            except (TypeError, ValueError):
                continue
            result.add(PortRecord(
                ip=str(ip), port=port_num,
                proto=str(row.get("protocol") or "tcp"),
                source="naabu",
            ))

        return result


__all__ = ["NaabuSource", "BINARY"]
