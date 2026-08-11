"""vhost source — Host-header virtual-host discovery (DNS-less reachability).

Some in-scope hosts have no public DNS record but are still reachable on a
backend IP via Host-header routing. This probe finds them: for each backend IP
and scheme it first fingerprints a **default vhost** (a random, non-existent
Host) to learn what "nothing matched" looks like, then fingerprints each
candidate host forced to that IP. A candidate is a ``reachable_vhost`` iff its
response body differs from that baseline, its status is 2xx/3xx, and it is not an
edge/WAF challenge page — the exact rule ported from the prototype
``vhost-sweep.sh``.

HTTP-only, no DNS, ``active = True`` (it talks to the target's backends). The
per-probe fingerprint runs through :func:`core.recon.probe.fingerprint`
(``curl --resolve`` in the read-restricted net sandbox); the verdict logic lives
here and is unit-tested with an injected ``prober``. Every probe is written to
``raw/vhost.jsonl``; only ``reachable_vhost`` rows become
:class:`~core.recon.model.VhostRecord`\\ s (the builder gates on that verdict),
and each reachable host feeds ``discovered.names``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from core.recon import probe as _probe
from core.recon.model import VhostRecord
from core.recon.scope import in_scope, normalise_name
from core.recon.source import RunContext, Source, SourceResult, register
from core.recon.toolrunner import tool_available

SCHEMES = ("https", "http")
DEFAULT_MAX_PROBES = 4000
BASELINE_LABEL = "zzq9-nope-9931"   # an improbable, non-existent vhost


@register
class VhostSource(Source):
    name = "vhost"
    egress_hosts = ()
    credential_env_vars = ()
    consumes = ("names", "ips")
    produces = ("vhost",)
    active = True

    binary = "curl"

    def __init__(self, prober: Optional[Any] = None, max_probes: int = DEFAULT_MAX_PROBES) -> None:
        self._probe = prober or _probe.fingerprint
        self._max_probes = max_probes

    def available(self, ctx: RunContext) -> bool:
        return super().available(ctx) and tool_available(self.binary)

    def _baseline_host(self, ctx: RunContext) -> str:
        root = ctx.roots[0] if ctx.roots else "invalid"
        return f"{BASELINE_LABEL}.{root}"

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        ips = sorted(ctx.assets.ips)
        names = sorted(
            n for n in ctx.assets.names
            if in_scope(normalise_name(n), ctx.roots) and n not in ctx.roots
        )
        if not ips or not names:
            return result

        # Bound the matrix (names × ips × schemes) to keep the probe count sane.
        budget = self._max_probes // max(1, len(ips) * len(SCHEMES))
        if len(names) > budget:
            names = names[:budget]
            result.error = f"vhost matrix capped to {budget} candidate names"
        result.requested = len(names) * len(ips) * len(SCHEMES)

        baseline_host = self._baseline_host(ctx)
        baseline: Dict[str, str] = {}
        raw_rows: List[Dict[str, Any]] = []

        for scheme in SCHEMES:
            for ip in ips:
                pr = self._probe(scheme, ip, baseline_host,
                                 output=ctx.raw_dir, env=ctx.env)
                baseline[f"{scheme}:{ip}"] = pr.body_sha256

        for host in names:
            for scheme in SCHEMES:
                for ip in ips:
                    pr = self._probe(scheme, ip, host,
                                     output=ctx.raw_dir, env=ctx.env)
                    base_sha = baseline.get(f"{scheme}:{ip}", "")
                    distinct = False
                    if pr.is_challenge:
                        verdict = "challenge"
                    elif pr.status == 0:
                        verdict = "error"
                    elif pr.body_sha256 and pr.body_sha256 != base_sha:
                        if 200 <= pr.status < 400:
                            distinct = True
                            verdict = "reachable_vhost"
                        else:
                            verdict = "default_vhost"
                    else:
                        verdict = "default_vhost"

                    row = {
                        "host": host, "ip": ip, "scheme": scheme,
                        "status": pr.status, "title": pr.title, "server": pr.server,
                        "content_length": pr.content_length,
                        "body_sha256": pr.body_sha256,
                        "distinct_from_default": distinct,
                        "trick": "host_header", "verdict": verdict,
                    }
                    raw_rows.append(row)
                    if verdict == "reachable_vhost":
                        result.add(VhostRecord(**row))
                        result.discovered.names.add(host)

        raw = ctx.raw_path("vhost.jsonl")
        raw.write_text("\n".join(json.dumps(r, sort_keys=True) for r in raw_rows) + "\n",
                       encoding="utf-8")
        result.raw_path = raw
        return result


__all__ = ["VhostSource"]
