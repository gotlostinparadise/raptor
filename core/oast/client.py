"""The OAST client — mint correlation tokens, hand out payloads, correlate hits.

Usage shape::

    client = OastClient(InMemoryBackend("oast.example"))
    c = client.new_interaction(finding_id="ssrf-on-avatar-url")
    param_value = c.ssrf_urls()[0]        # plant this in the target
    ...
    for hit in client.poll():             # later: any callbacks?
        finding_id = client.finding_for(hit.token)   # -> "ssrf-on-avatar-url"

The token→finding map lives here; :mod:`core.oast.outcome` turns a correlated
hit into a web-graph proof / verified outcome. The token generator is injectable
so tests are deterministic; in production it is a cryptographically-random,
DNS-safe label.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from core.oast import payloads as P
from core.oast.backend import OastBackend
from core.oast.interaction import Interaction

# DNS-label-safe alphabet (lowercase letters + digits); tokens are one label.
_ALPHABET = string.ascii_lowercase + string.digits


def _default_token(n: int = 20) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


@dataclass
class Correlation:
    """One minted callback identity + its payload helpers."""

    token: str
    host: str          # <token>.<domain>
    finding_id: str = ""

    @property
    def url(self) -> str:
        return f"http://{self.host}/"

    def ssrf_urls(self) -> List[str]:
        return P.ssrf_urls(self.host)

    def xxe(self) -> str:
        return P.xxe(self.host)

    def rce_commands(self) -> List[str]:
        return P.rce_commands(self.host)

    def sqli_oob(self) -> Dict[str, str]:
        return P.sqli_oob(self.host)

    def dns_exfil(self, data_label: str = "data") -> str:
        return P.dns_exfil(self.host, data_label)

    def all_payloads(self) -> Dict[str, object]:
        return P.all_payloads(self.host)


class OastClient:
    """Mint correlations against a backend and correlate observed interactions."""

    def __init__(
        self,
        backend: OastBackend,
        *,
        token_gen: Optional[Callable[[], str]] = None,
    ) -> None:
        self.backend = backend
        self._token_gen = token_gen or _default_token
        self._finding_by_token: Dict[str, str] = {}

    @property
    def domain(self) -> str:
        return self.backend.domain

    def new_interaction(self, finding_id: str = "") -> Correlation:
        """Mint a unique correlation token + callback host for a finding."""
        token = self._token_gen()
        while token in self._finding_by_token:      # collision guard
            token = self._token_gen()
        self._finding_by_token[token] = finding_id
        self.backend.register(token)
        return Correlation(token=token, host=f"{token}.{self.backend.domain}",
                           finding_id=finding_id)

    def token_of(self, host: str) -> Optional[str]:
        """Extract a known correlation token from an interaction hostname.

        The token is the left-most label of ``<token>.<domain>``; we accept any
        host whose first label is a token we minted (sub-labels for DNS-exfil
        still correlate because the token label remains present).
        """
        host = (host or "").lower().rstrip(".")
        labels = host.split(".")
        for lbl in labels:
            if lbl in self._finding_by_token:
                return lbl
        return None

    def finding_for(self, token: str) -> Optional[str]:
        return self._finding_by_token.get(token)

    def poll(self) -> List[Interaction]:
        """Poll the backend and stamp each interaction with its correlated token.

        Interactions whose host carries no known token are dropped — they are
        someone else's traffic, not a callback we can attribute.
        """
        out: List[Interaction] = []
        for hit in self.backend.poll(list(self._finding_by_token) or None):
            token = hit.token if hit.token in self._finding_by_token else self.token_of(hit.host)
            if not token:
                continue
            hit.token = token
            out.append(hit)
        return out

    def confirmations(self) -> Dict[str, List[Interaction]]:
        """Poll and group confirmed interactions by finding id."""
        grouped: Dict[str, List[Interaction]] = {}
        for hit in self.poll():
            fid = self.finding_for(hit.token) or hit.token
            grouped.setdefault(fid, []).append(hit)
        return grouped


__all__ = ["Correlation", "OastClient"]
