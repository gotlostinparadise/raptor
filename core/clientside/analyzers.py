"""Client-side / configuration analyzers — pure functions over HTTP metadata.

Each takes response headers (or a probe result) and returns a list of finding
dicts. No network, no LLM: a misconfiguration is read directly off the wire
(a reflected CORS origin, an ``unsafe-inline`` CSP, a cookie missing ``Secure``),
which is why these are unit-testable in isolation and the runner just feeds them
real responses.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import urlsplit


# ─────────────────────────── CORS ───────────────────────────

def cors_analysis(sent_origin: str, headers: Dict[str, str]) -> List[dict]:
    """Findings from a CORS probe sent with ``Origin: sent_origin``."""
    h = {k.lower(): v for k, v in headers.items()}
    acao = h.get("access-control-allow-origin", "")
    creds = h.get("access-control-allow-credentials", "").strip().lower() == "true"
    out: List[dict] = []
    if sent_origin and acao == sent_origin:
        out.append({"type": "cors_origin_reflection",
                    "severity": "high" if creds else "medium",
                    "detail": f"Access-Control-Allow-Origin reflects arbitrary origin {sent_origin}",
                    "credentials": creds})
    if acao == "*" and creds:
        out.append({"type": "cors_wildcard_with_credentials", "severity": "high",
                    "detail": "wildcard ACAO combined with credentials (browsers block, but signals misconfig)"})
    if acao == "null":
        out.append({"type": "cors_null_origin", "severity": "medium",
                    "detail": "Access-Control-Allow-Origin: null is bypassable via sandboxed iframes"})
    return out


# ─────────────────────────── CSP ───────────────────────────

def parse_csp(csp: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for directive in (csp or "").split(";"):
        parts = directive.split()
        if parts:
            out[parts[0].lower()] = [p for p in parts[1:]]
    return out


def csp_analysis(csp: Optional[str]) -> List[dict]:
    if not csp:
        return [{"type": "csp_missing", "severity": "low",
                 "detail": "no Content-Security-Policy header"}]
    d = parse_csp(csp)
    out: List[dict] = []
    script_like = d.get("script-src", d.get("default-src", []))
    if "'unsafe-inline'" in script_like:
        out.append({"type": "csp_unsafe_inline", "severity": "medium",
                    "detail": "script-src/default-src allows 'unsafe-inline' (XSS mitigation weakened)"})
    if "'unsafe-eval'" in script_like:
        out.append({"type": "csp_unsafe_eval", "severity": "low",
                    "detail": "script-src/default-src allows 'unsafe-eval'"})
    if "*" in script_like:
        out.append({"type": "csp_wildcard_script_source", "severity": "medium",
                    "detail": "script source allows any host (*)"})
    if "object-src" not in d and "default-src" not in d:
        out.append({"type": "csp_no_object_src", "severity": "low",
                    "detail": "no object-src or default-src (plugin content unrestricted)"})
    return out


# ─────────────────────────── Clickjacking ───────────────────────────

def clickjacking(headers: Dict[str, str], csp_directives: Optional[Dict[str, List[str]]] = None) -> Optional[dict]:
    """A page is framable when it sets neither X-Frame-Options nor frame-ancestors."""
    h = {k.lower(): v for k, v in headers.items()}
    xfo = h.get("x-frame-options", "").strip()
    fa = bool(csp_directives and "frame-ancestors" in csp_directives)
    if not xfo and not fa:
        return {"type": "clickjacking", "severity": "medium",
                "detail": "no X-Frame-Options and no CSP frame-ancestors — page is framable"}
    return None


# ─────────────────────────── Cookie flags ───────────────────────────

def cookie_flags(set_cookie_values: List[str]) -> List[dict]:
    out: List[dict] = []
    for raw in set_cookie_values or []:
        if not raw:
            continue
        # Split into the name=value pair + attribute tokens; match ATTRIBUTE
        # names, not a substring of the whole line (a cookie named
        # ``pref_secure`` must not suppress the Secure warning).
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        missing = [f for f in ("secure", "httponly", "samesite") if f not in attrs]
        if missing:
            out.append({"type": "cookie_flags", "severity": "low", "cookie": name,
                        "missing": missing,
                        "detail": f"cookie {name!r} missing: {', '.join(missing)}"})
    return out


# ─────────────────────────── Open redirect ───────────────────────────

def open_redirect(location: str, final_url: str, marker_host: str) -> Optional[dict]:
    """Confirmed when a redirect (Location or final URL) points at ``marker_host``.

    Handles the common ``//host`` and backslash tricks by inspecting both the raw
    ``Location`` string and the parsed host of the followed final URL.
    """
    if not marker_host:
        return None
    loc = location or ""
    # Normalise backslash tricks and scheme-relative `//host` so the parsed host
    # is the *actual* redirect target — an equality check then avoids matching a
    # marker that merely appears as a subdomain prefix (evil.example.attacker.com).
    normalized = loc.replace("\\", "/")
    loc_host = urlsplit(normalized if "//" in normalized else "//" + normalized).hostname or ""
    final_host = urlsplit(final_url or "").hostname or ""
    if marker_host in (loc_host, final_host):
        return {"type": "open_redirect", "severity": "medium",
                "detail": f"redirect target controllable to external host {marker_host}",
                "location": loc}
    return None


__all__ = [
    "cors_analysis", "parse_csp", "csp_analysis", "clickjacking", "cookie_flags",
    "open_redirect",
]
