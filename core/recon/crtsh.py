"""crt.sh source — passive subdomain discovery from Certificate Transparency.

crt.sh indexes the public CT logs. Querying ``?q=%.<root>&output=json`` returns
every certificate whose subject/SAN matches the domain — a high-yield, no-key,
purely passive way to enumerate subdomains an organisation has ever requested a
certificate for. No traffic reaches the target's own infrastructure, so this
runs under every safety profile (``active = False``).

Egress is allowlisted to ``crt.sh`` through :mod:`core.http`, so a compromised
JSON parser can't exfiltrate anywhere else. The response can be large (busy
domains have thousands of certs), so the per-call size cap is raised from the
JSON default.

Emits :class:`~core.recon.model.SubdomainRecord` per in-scope name and feeds
those names into ``discovered.names`` for the resolution/recursion loop. It does
*not* emit ``certs`` records: crt.sh names carry no IP, so there is no
``cert_origin`` / ``tls_san`` edge to draw — subdomain discovery is the whole
value here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from core.http import HttpError
from core.recon.model import SubdomainRecord
from core.recon.scope import in_scope, normalise_name, root_of
from core.recon.source import RunContext, Source, SourceResult, register

CRTSH_HOST = "crt.sh"

# Busy domains return large arrays; lift the cap well above the JSON default
# but keep it bounded so a pathological response can't exhaust memory.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

# crt.sh has been slow/flaky under load; give it a longer per-attempt read and
# let core.http's backoff handle transient 5xx/timeouts.
REQUEST_TIMEOUT = 60


def _names_from_entry(entry: Dict[str, Any]) -> List[str]:
    """Every DNS name in one crt.sh row (name_value is newline-joined SANs)."""
    out: List[str] = []
    for field in ("name_value", "common_name"):
        value = entry.get(field) or ""
        for piece in str(value).split("\n"):
            name = normalise_name(piece)
            if name:
                out.append(name)
    return out


@register
class CrtShSource(Source):
    name = "crtsh"
    egress_hosts = (CRTSH_HOST,)
    credential_env_vars = ()
    consumes = ("roots",)
    produces = ("subdomains",)
    active = False

    def run(self, ctx: RunContext) -> SourceResult:
        http = ctx.http_client(self)
        result = SourceResult(source=self.name)
        seen: Set[str] = set()

        for root in ctx.roots:
            result.requested += 1
            url = f"https://{CRTSH_HOST}/?q=%25.{root}&output=json"
            try:
                data = http.get_json(
                    url, timeout=REQUEST_TIMEOUT, max_bytes=MAX_RESPONSE_BYTES,
                )
            except HttpError as exc:
                # One failed root must not abort the rest. core.http already
                # retried transient errors; record and move on.
                result.failed.append(root)
                result.error = f"{type(exc).__name__}: {exc}"
                continue

            for entry in (data or []):
                if not isinstance(entry, dict):
                    continue
                for name in _names_from_entry(entry):
                    # Label-aware scope check against ALL roots, not just this
                    # query's root — a cert can carry names across sibling roots.
                    if name in seen or not in_scope(name, ctx.roots):
                        continue
                    seen.add(name)
                    if name in ctx.roots:
                        continue   # the apex itself isn't a subdomain node
                    result.add(SubdomainRecord(
                        name=name, root=root_of(name, ctx.roots), sources=["crtsh"],
                    ))
                    result.discovered.names.add(name)

        return result


__all__ = ["CrtShSource", "CRTSH_HOST"]
