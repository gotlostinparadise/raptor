"""Bridge a :mod:`core.session` identity into a browser context.

Authenticated crawling is where the interesting surface lives — a BOLA/BFLA bug
is invisible to an anonymous crawl. The session engine already models identities
(auth headers + an isolated cookie jar); this module converts one into the two
things a Playwright context needs to *be* that identity: extra HTTP headers and a
cookie list. Kept as pure data transforms — no Playwright, no browser — so the
conversion (the part with real logic) is unit-testable in CI even though the
harness wiring that consumes it is not.

Everything here feature-detects its inputs (``engine`` / ``identity`` arrive as
``Any`` through :class:`core.webgraph.source.RunContext.session`) so a missing or
oddly-shaped session degrades to "no auth" rather than raising.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def resolve_identity(engine: Any, name: Optional[str] = None) -> Optional[Any]:
    """Pick the identity to crawl as from a :class:`SessionEngine`-like object.

    ``name`` selects explicitly (returns ``None`` if unknown). With no name, the
    first non-anonymous identity is chosen — the common case of "crawl as the one
    logged-in user configured". Returns ``None`` when there is no engine or no
    authenticated identity, so the caller falls back to an anonymous crawl.
    """
    if engine is None or not hasattr(engine, "identity"):
        return None
    if name:
        try:
            ident = engine.identity(name)
        except Exception:
            return None
        # Even an explicitly-named anonymous identity means "no auth to seed".
        return None if _is_anonymous(ident) else ident
    names = engine.names() if hasattr(engine, "names") else []
    for n in names:
        try:
            ident = engine.identity(n)
        except Exception:
            continue
        if not _is_anonymous(ident):
            return ident
    return None


def _is_anonymous(identity: Any) -> bool:
    fn = getattr(identity, "is_anonymous", None)
    if callable(fn):
        try:
            return bool(fn())
        except Exception:
            pass
    return getattr(identity, "name", "") == "anonymous"


def context_args_for_identity(identity: Any) -> Dict[str, Any]:
    """``{"extra_http_headers": {...}, "cookies": [...]}`` for a Playwright context.

    Auth headers (``Authorization`` / ``X-API-Key`` / …) become context-wide
    extra headers; the identity's jar cookies become Playwright cookie dicts
    (``name``/``value``/``domain``/``path``). A ``Cookie`` header, if somehow
    present in ``auth_headers``, is dropped — cookies flow through the jar path so
    the browser manages them per navigation.
    """
    headers: Dict[str, str] = {
        k: v for k, v in dict(getattr(identity, "auth_headers", {}) or {}).items()
        if k.lower() != "cookie"
    }
    cookies: List[Dict[str, Any]] = []
    jar = getattr(identity, "jar", None)
    jar_cookies = jar.cookies() if jar is not None and hasattr(jar, "cookies") else []
    for c in jar_cookies:
        host = getattr(c, "host", "")
        if not host:
            continue
        cookies.append({
            "name": getattr(c, "name", ""),
            "value": getattr(c, "value", ""),
            "domain": host,
            "path": getattr(c, "path", "/") or "/",
        })
    return {"extra_http_headers": headers, "cookies": cookies}


__all__ = ["resolve_identity", "context_args_for_identity"]
