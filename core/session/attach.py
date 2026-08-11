"""Thread one authenticated session into the HTTP test phases.

The web-pentest orchestrator logs in **once** and must carry that session —
*both* its cookie jar and any bearer/API-key headers — into every active phase,
not just the browser crawl. Two shapes of consumer need it, so there are two
helpers:

  * :func:`engine_for` — for phases that already drive a
    :class:`~core.session.engine.SessionEngine` (injection, graphql). Given a
    live engine it reuses it (returning the identity to send as); given none it
    builds a fresh engine, seeding a tester identity from a static bearer
    (``token_env``) and/or explicit ``cookies`` / ``headers``.
  * :func:`merged_auth_headers` — for phases that send through a plain
    :class:`~core.http.HttpClient` (clientside, discovery, race). It returns the
    static header snapshot (auth headers + a ``Cookie`` header) to attach to each
    request, taken from the live session's chosen identity when present, else from
    explicit ``cookies`` / ``headers``.

Everything feature-detects its inputs (the live session arrives as ``Any``) so a
missing or anonymous session degrades to "no auth" rather than raising — the same
discipline :mod:`core.browser.auth` uses for the browser bridge.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit


def _resolve(session: Any, identity: Optional[str]) -> Optional[Any]:
    """The identity object to act as, or ``None`` (no engine / anonymous only)."""
    if session is None:
        return None
    from core.browser.auth import resolve_identity
    return resolve_identity(session, identity)


def merged_auth_headers(
    url: str,
    *,
    session: Any = None,
    cookies: Optional[Mapping[str, str]] = None,
    headers: Optional[Mapping[str, str]] = None,
    identity: Optional[str] = None,
) -> Dict[str, str]:
    """Static ``{header: value}`` to attach as the authenticated identity.

    A live ``session`` wins: the chosen identity's auth headers + its jar's
    ``Cookie`` header for ``url`` are returned. With no session, explicit
    ``headers`` are used and ``cookies`` are folded into a single ``Cookie``
    header. Returns ``{}`` when there is nothing to attach (anonymous).
    """
    ident = _resolve(session, identity)
    if ident is not None:
        return dict(ident.request_headers(url))
    out: Dict[str, str] = dict(headers or {})
    if cookies:
        cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
        if cookie_hdr:
            out["Cookie"] = cookie_hdr
    return out


def engine_for(
    base_url: str,
    *,
    session: Any = None,
    cookies: Optional[Mapping[str, str]] = None,
    headers: Optional[Mapping[str, str]] = None,
    token_env: str = "",
    env: Optional[Mapping[str, str]] = None,
    client_factory: Any = None,
    identity_name: str = "tester",
) -> Tuple[Any, str, List[str]]:
    """Return ``(engine, identity_name, warnings)`` for an engine-based phase.

    When ``session`` is a live :class:`SessionEngine`, it is reused as-is and the
    identity to send as is the first authenticated one (or ``"anonymous"``). When
    ``session`` is ``None``, a fresh engine is built over ``base_url``'s client
    (via ``client_factory`` when given, else :func:`core.webhttp.pentest_client`)
    with a single ``identity_name`` identity seeded from ``token_env`` (bearer),
    ``headers``, and ``cookies``.
    """
    warnings: List[str] = []
    if session is not None:
        ident = _resolve(session, None)
        return session, (getattr(ident, "name", "anonymous") if ident is not None
                         else "anonymous"), warnings

    from core.session.engine import SessionEngine
    from core.session.identity import Identity

    host = urlsplit(base_url).hostname or ""
    if client_factory is not None:
        client = client_factory([host] if host else [])
    else:
        from core.webhttp import pentest_client
        client = pentest_client(base_url)

    engine = SessionEngine(client)
    ident = Identity(name=identity_name)
    engine.add_identity(ident)

    if token_env:
        from core.session.login import resolve_credential
        tok = resolve_credential(token_env, env)
        if tok:
            ident.set_bearer(tok)
            ident.authenticated = True
        else:
            warnings.append(f"missing ${token_env}; testing unauthenticated")
    for k, v in (headers or {}).items():
        ident.auth_headers[k] = v
    if cookies and host:
        for cname, cval in cookies.items():
            if cname:
                ident.jar.set(cname, cval, host)
                ident.authenticated = True
    return engine, identity_name, warnings


__all__ = ["engine_for", "merged_auth_headers"]
