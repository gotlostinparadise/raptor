"""exposed_origin source — WAF/CDN-bypass origin discovery.

When a scope root is fronted by a CDN/WAF (Cloudflare, DDoS-Guard, …), the real
backend IP often still answers the origin content directly if you connect to it
with the right Host header — bypassing the edge entirely. This probe looks for
that: for each candidate backend IP and scheme it fingerprints ``scheme://root/``
forced to that IP, and flags the IP as an ``exposed_origin`` when it serves a
real page (2xx, non-empty body) that is **not** an edge/WAF challenge.

Candidate IPs are the ones the run already knows about (``ctx.assets.ips`` — e.g.
addresses Censys tied to a domain certificate, the strongest origin signal). The
probe is ``active = True`` (it connects to the target's backends). Fingerprinting
runs through :func:`core.recon.probe.fingerprint`; the verdict logic here is
unit-tested with an injected ``prober``. Every probe is written to
``raw/origin.jsonl``; only ``exposed_origin`` rows become
:class:`~core.recon.model.OriginRecord`\\ s (the builder gates on that verdict and
draws the ``ip --exposed_origin--> root`` edge).

.. note::
   The verdict is a heuristic (2xx + non-empty + not-a-challenge), so it can
   surface a shared-host default page as a candidate. ``matches_baseline`` is
   left ``None`` — a future refinement can fetch the through-CDN baseline and set
   it to confirm the direct response is the *same* site, not merely *a* site.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from core.recon import probe as _probe
from core.recon.model import OriginRecord
from core.recon.source import RunContext, Source, SourceResult, register
from core.recon.toolrunner import tool_available

SCHEMES = ("https", "http")
DEFAULT_MAX_PROBES = 2000


@register
class ExposedOriginSource(Source):
    name = "exposed_origin"
    egress_hosts = ()
    credential_env_vars = ()
    consumes = ("roots", "ips")
    produces = ("origin",)
    active = True

    binary = "curl"

    def __init__(self, prober: Optional[Any] = None, max_probes: int = DEFAULT_MAX_PROBES) -> None:
        self._probe = prober or _probe.fingerprint
        self._max_probes = max_probes

    def available(self, ctx: RunContext) -> bool:
        return super().available(ctx) and tool_available(self.binary)

    def run(self, ctx: RunContext) -> SourceResult:
        result = SourceResult(source=self.name)
        ips = sorted(ctx.assets.ips)
        roots = list(ctx.roots)
        if not ips or not roots:
            return result

        budget = self._max_probes // max(1, len(roots) * len(SCHEMES))
        if len(ips) > budget:
            ips = ips[:budget]
            result.error = f"exposed_origin matrix capped to {budget} candidate IPs"
        result.requested = len(roots) * len(ips) * len(SCHEMES)

        raw_rows: List[Dict[str, Any]] = []
        for root in roots:
            for scheme in SCHEMES:
                for ip in ips:
                    pr = self._probe(scheme, ip, root,
                                     output=ctx.raw_dir, env=ctx.env)
                    if pr.is_challenge:
                        verdict = "challenge"
                    elif pr.status == 0:
                        verdict = "error"
                    elif 200 <= pr.status < 300 and pr.content_length > 0:
                        verdict = "exposed_origin"
                    else:
                        verdict = "fronted"

                    row = {
                        "ip": ip, "host_header": root, "scheme": scheme,
                        "status": pr.status, "title": pr.title, "server": pr.server,
                        "body_sha256": pr.body_sha256, "matches_baseline": None,
                        "verdict": verdict,
                    }
                    raw_rows.append(row)
                    if verdict == "exposed_origin":
                        result.add(OriginRecord(**row))

        raw = ctx.raw_path("origin.jsonl")
        raw.write_text("\n".join(json.dumps(r, sort_keys=True) for r in raw_rows) + "\n",
                       encoding="utf-8")
        result.raw_path = raw
        return result


__all__ = ["ExposedOriginSource"]
