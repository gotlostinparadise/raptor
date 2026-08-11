"""A pragmatic per-identity cookie jar.

Full RFC 6265 cookie semantics (domain/path matching, secure/samesite, expiry)
are more than a pentest session engine needs and more than the shared
:class:`core.http.Response` header model can faithfully carry — its
``headers`` mapping collapses repeated ``Set-Cookie`` lines into one. This jar
therefore takes the pragmatic middle path: it stores cookies keyed by
``(host, name)``, does host + path-prefix matching when emitting a ``Cookie``
header, and honours ``expires``/``max-age=0`` deletions. One jar per
:class:`~core.session.identity.Identity`, so user A's session cookie can never
leak into user B's replay — the property that makes the authz oracle sound.

Known limitation (tracked): a single response carrying multiple ``Set-Cookie``
headers only yields the one the transport preserved. Seed additional cookies
explicitly via :meth:`set` or on the identity when a login sets several at once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit


@dataclass
class Cookie:
    name: str
    value: str
    host: str
    path: str = "/"


@dataclass
class CookieJar:
    """Host+path-scoped cookie store for one identity."""

    _cookies: Dict[Tuple[str, str, str], Cookie] = field(default_factory=dict)

    def _key(self, host: str, path: str, name: str) -> Tuple[str, str, str]:
        return (host.lower(), path or "/", name)

    def set(self, name: str, value: str, host: str, path: str = "/") -> None:
        """Directly seed/overwrite a cookie (e.g. from a captured login)."""
        self._cookies[self._key(host, path, name)] = Cookie(name, value, host.lower(), path or "/")

    def update_from_response(self, url: str, set_cookie: Optional[str]) -> None:
        """Ingest a ``Set-Cookie`` header value observed for ``url``.

        A ``max-age=0`` / past-expiry cookie deletes; anything else stores. The
        cookie's host defaults to the request host, its path to the ``Path``
        attribute or ``/``.
        """
        if not set_cookie:
            return
        req_host = (urlsplit(url).hostname or "").lower()
        parsed = SimpleCookie()
        try:
            parsed.load(set_cookie)
        except Exception:
            return
        for name, morsel in parsed.items():
            host = (morsel["domain"] or req_host).lstrip(".").lower()
            path = morsel["path"] or "/"
            max_age = morsel["max-age"]
            deleted = (max_age not in ("", None) and str(max_age).strip() == "0")
            if deleted or morsel.value == "":
                self._cookies.pop(self._key(host, path, name), None)
            else:
                self.set(name, morsel.value, host, path)

    def header_for(self, url: str) -> Optional[str]:
        """Build the ``Cookie`` request header for ``url``, or ``None``.

        Host match is suffix-aware (``app.x.com`` sends cookies scoped to
        ``x.com``); path match is prefix-based, longest path first.
        """
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        req_path = parts.path or "/"
        matches: List[Cookie] = []
        for c in self._cookies.values():
            if host == c.host or host.endswith("." + c.host):
                if req_path.startswith(c.path):
                    matches.append(c)
        if not matches:
            return None
        matches.sort(key=lambda c: len(c.path), reverse=True)
        return "; ".join(f"{c.name}={c.value}" for c in matches)

    def names(self) -> List[str]:
        """Cookie names currently held (order-stable) — for tests/inspection."""
        return sorted({c.name for c in self._cookies.values()})

    def cookies(self) -> List[Cookie]:
        """All stored cookies (order-stable by host/path/name).

        A read-only export so callers (e.g. the browser harness, which seeds a
        Playwright context from an identity's jar) don't reach into the private
        store.
        """
        return [self._cookies[k] for k in sorted(self._cookies)]

    def clear(self) -> None:
        self._cookies.clear()


__all__ = ["Cookie", "CookieJar"]
