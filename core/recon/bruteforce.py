"""bruteforce source — active DNS bruteforce of wordlist-generated names.

Where :mod:`core.recon.dnsx` resolves names the run already *knows*, this source
*guesses* them: it expands a wordlist against every scope root (optionally
augmented with ``alterx`` permutations of the live hosts found so far), then
resolves the candidate set through ``dnsx`` with a hard rate cap and a small,
trusted resolver set. It is the framework port of the prototype's
``enum-lite.sh`` (home profile) — the home-router-safe bruteforce envelope.

It sends a large volume of DNS queries about the target, so it is
``active = True`` and needs a non-passive profile. The wordlist path is
configuration (an operator asset, not shipped): set ``RAPTOR_DNS_WORDLIST`` or
pass ``wordlist=`` — :meth:`available` returns ``False`` when it is absent, so
the source silently no-ops rather than erroring. Rate / concurrency / permutation
cap come off the profile knobs (``dns_rate`` / ``dns_threads`` / ``perm_cap``).

Sandboxing and JSON parsing mirror :mod:`core.recon.dnsx` (network-open,
read-restricted; the wordlist is added to the read allowlist). Emits
:class:`~core.recon.model.DnsRecord` (``discovery = active``) for each candidate
that resolves and :class:`~core.recon.model.SubdomainRecord` for the new
in-scope names, feeding both into ``discovered``.

.. note::
   No wildcard filtering yet — a domain with a live DNS wildcard will yield
   false positives. The prototype verified its target had none. A ``puredns``
   path with wildcard elimination is the planned upgrade for the ``vps`` profile
   (``allow_massdns``); until then run bruteforce only against wildcard-free
   zones.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List, Optional

from core.recon.model import DISCOVERY_ACTIVE, DnsRecord, SubdomainRecord
from core.recon.scope import in_scope, normalise_name, root_of
from core.recon.source import RunContext, Source, SourceResult, register
from core.recon.toolrunner import parse_jsonl, run_net_tool, tool_available

BINARY = "dnsx"
ALTERX = "alterx"
TIMEOUT_SECONDS = 1800
TCP_PORTS = (53, 443)


@register
class BruteforceSource(Source):
    name = "bruteforce"
    egress_hosts = ()
    credential_env_vars = ()
    consumes = ("roots", "names")
    produces = ("subdomains", "dns")
    active = True

    binary = BINARY

    def __init__(self, wordlist: Optional[str] = None, runner: Optional[Any] = None) -> None:
        self._wordlist = wordlist or os.environ.get("RAPTOR_DNS_WORDLIST")
        self._run = runner or run_net_tool

    def available(self, ctx: RunContext) -> bool:
        return (
            super().available(ctx)
            and tool_available(self.binary)
            and bool(self._wordlist)
            and Path(self._wordlist).is_file()
        )

    def _candidates(self, ctx: RunContext, cap: int) -> List[str]:
        """Wordlist × roots (bounded by ``cap``), de-duplicated."""
        words: List[str] = []
        with open(self._wordlist, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip().lower()
                if w and not w.startswith("#"):
                    words.append(w)
        out: List[str] = []
        for root in ctx.roots:
            for w in words:
                out.append(f"{w}.{root}")
                if len(out) >= cap:
                    return list(dict.fromkeys(out))
        return list(dict.fromkeys(out))

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        if not ctx.roots or not self._wordlist:
            return result

        knobs = ctx.profile.knobs
        cap = int(knobs.get("perm_cap", 15000)) or 15000
        candidates = self._candidates(ctx, cap)
        if not candidates:
            return result

        cand_file = ctx.raw_path("bruteforce-candidates.txt")
        cand_file.write_text("\n".join(candidates) + "\n", encoding="utf-8")
        result.requested = len(candidates)

        cmd = [
            self.binary, "-l", str(cand_file),
            "-a", "-aaaa", "-cname", "-resp", "-json", "-silent",
            "-rate-limit", str(knobs.get("dns_rate", 300)),
            "-threads", str(knobs.get("dns_threads", 25)),
        ]
        tr = self._run(cmd, output=ctx.raw_dir, tcp_ports=list(TCP_PORTS),
                       timeout=TIMEOUT_SECONDS, env=ctx.env,
                       readable_paths=[str(Path(self._wordlist).resolve())])
        if tr.timed_out:
            result.error = "bruteforce (dnsx) timed out"
        if not tr.stdout:
            if tr.returncode and not result.error:
                result.error = f"bruteforce exit {tr.returncode}: {tr.stderr[:200]}"
            return result

        raw = ctx.raw_path("bruteforce.jsonl")
        raw.write_text(tr.stdout, encoding="utf-8")
        result.raw_path = raw

        for row in parse_jsonl(tr.stdout):
            host = normalise_name(row.get("host") or "")
            if not host or not in_scope(host, ctx.roots):
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
            if host not in ctx.roots and host not in ctx.assets.names:
                result.add(SubdomainRecord(
                    name=host, root=root_of(host, ctx.roots),
                    sources=["bruteforce"],
                ))
            result.discovered.names.add(host)
            result.discovered.ips.update(a)
            result.discovered.ips.update(aaaa)

        return result


__all__ = ["BruteforceSource", "BINARY"]
