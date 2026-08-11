"""Interaction + correlation-token vocabulary for the OAST subsystem.

An *interaction* is a single out-of-band hit observed by the collaborator: a DNS
lookup or an HTTP(S) request whose hostname carries a correlation token RAPTOR
minted. Because the token is embedded in the hostname, an interaction always
maps back to the exact finding that planted the payload — that mapping is the
whole reason a blind vulnerability becomes *verifiable* rather than suspected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Interaction protocols the collaborator can observe.
PROTO_DNS = "dns"
PROTO_HTTP = "http"
PROTO_SMTP = "smtp"
PROTOCOLS = (PROTO_DNS, PROTO_HTTP, PROTO_SMTP)


@dataclass
class Interaction:
    """One out-of-band callback observed by the collaborator."""

    token: str
    protocol: str
    #: Full hostname queried/requested (``<token>.<domain>`` or a sub-label of it).
    host: str = ""
    #: Source address of the interaction (the SSRF/RCE victim's egress IP).
    remote_addr: str = ""
    #: ISO-8601 timestamp the collaborator recorded, verbatim (never generated here).
    timestamp: str = ""
    #: Raw request line / query for evidence (HTTP path, DNS qname).
    raw: str = ""
    #: Any extra fields the backend surfaced.
    meta: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any], *, token: str = "") -> "Interaction":
        """Build from a backend's JSON row, tolerant of extra/missing keys."""
        proto = (d.get("protocol") or d.get("proto") or "").lower()
        return cls(
            token=d.get("token") or token,
            protocol=proto,
            host=d.get("host") or d.get("full-id") or d.get("hostname") or "",
            remote_addr=d.get("remote-address") or d.get("remote_addr")
            or d.get("source_ip") or d.get("src") or "",
            timestamp=d.get("timestamp") or d.get("time") or "",
            raw=d.get("raw-request") or d.get("raw") or d.get("q") or "",
            meta={k: v for k, v in d.items() if k not in {
                "protocol", "proto", "host", "full-id", "hostname",
                "remote-address", "remote_addr", "source_ip", "src",
                "timestamp", "time", "raw-request", "raw", "q", "token",
            }},
        )


__all__ = ["PROTO_DNS", "PROTO_HTTP", "PROTO_SMTP", "PROTOCOLS", "Interaction"]
