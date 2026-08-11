"""The multi-identity session engine.

Sits directly on the :class:`core.http.HttpClient` chokepoint's low-level
:meth:`request` (arbitrary method, headers, redirect control) and adds the three
things a pentest needs that a plain client doesn't:

  1. **Per-identity state** — each request is sent *as* a named
     :class:`~core.session.identity.Identity`, injecting that identity's auth
     headers + ``Cookie`` header and folding any ``Set-Cookie`` back into *its*
     jar. Identities never share state.
  2. **CSRF double-submit** — captures a token from a configured cookie
     (e.g. ``XSRF-TOKEN``) and echoes it as a header (e.g. ``X-XSRF-TOKEN``) on
     mutating requests, the common SPA pattern.
  3. **Refresh-on-401** — an optional per-identity refresh callable is invoked
     once on a 401 and the request retried, covering short-lived bearer tokens.

The engine is transport-agnostic: hand it any object satisfying the
:class:`~core.http.HttpClient` protocol (the real ``EgressClient`` in
production, a stub in tests), which is what makes the whole authorization oracle
unit-testable with no network.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from core.http import HttpClient, HttpError, Response
from core.session.identity import Identity

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


class SessionEngine:
    """Send requests as any registered identity, maintaining session state."""

    def __init__(
        self,
        client: HttpClient,
        *,
        csrf_cookie: Optional[str] = None,
        csrf_header: Optional[str] = None,
    ) -> None:
        self.client = client
        self.csrf_cookie = csrf_cookie
        self.csrf_header = csrf_header or "X-CSRF-Token"
        self._identities: Dict[str, Identity] = {}
        self._refresh: Dict[str, Callable[[Identity], None]] = {}
        # Always provide an anonymous identity so unauth replay needs no setup.
        self.add_identity(Identity(name="anonymous"))

    # ------------------------------------------------------------------
    # identity management
    # ------------------------------------------------------------------
    def add_identity(
        self, identity: Identity,
        refresh: Optional[Callable[[Identity], None]] = None,
    ) -> Identity:
        self._identities[identity.name] = identity
        if refresh is not None:
            self._refresh[identity.name] = refresh
        return identity

    def identity(self, name: str) -> Identity:
        if name not in self._identities:
            raise KeyError(f"unknown identity: {name!r}")
        return self._identities[name]

    def names(self) -> list:
        return sorted(self._identities)

    def authenticate(self, name: str, strategy: Any) -> "Response":
        """Run a login ``strategy`` (see :mod:`core.session.login`) for ``name``."""
        return strategy.apply(self, self.identity(name))

    # ------------------------------------------------------------------
    # requests
    # ------------------------------------------------------------------
    def request(
        self,
        identity_name: str,
        method: str,
        url: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        retries: int = 0,
        _allow_refresh: bool = True,
    ) -> Response:
        """Send ``method url`` as ``identity_name`` with full session state.

        Non-idempotent by default (``retries=0``) — a session request replays
        real traffic, so we don't silently repeat it.
        """
        ident = self.identity(identity_name)
        method = method.upper()
        h = ident.request_headers(url, headers)
        if method in _MUTATING and self.csrf_header and ident.csrf:
            # echo the most-recently captured token
            for _k, tok in ident.csrf.items():
                h[self.csrf_header] = tok
                break

        # A pentest session must see every status as DATA — a 401/403/3xx is
        # the oracle's signal, not an error. Clients that raise on non-2xx
        # (UrllibClient/EgressClient with the default raise_on_status) are
        # normalised back to a Response so the engine is client-agnostic.
        try:
            resp = self.client.request(
                method, url, body=body, headers=h,
                follow_redirects=follow_redirects, retries=retries,
            )
        except HttpError as exc:
            resp = Response(status=int(exc.status or 0), headers={}, body=b"", url=url)

        # Fold Set-Cookie into this identity's jar, then capture CSRF.
        ident.jar.update_from_response(url, resp.headers.get("set-cookie"))
        if self.csrf_cookie:
            token = self._read_cookie(ident, url, self.csrf_cookie)
            if token:
                ident.csrf[self.csrf_header] = token

        if resp.status == 401 and _allow_refresh and identity_name in self._refresh:
            self._refresh[identity_name](ident)
            return self.request(
                identity_name, method, url, body=body, headers=headers,
                follow_redirects=follow_redirects, retries=retries,
                _allow_refresh=False,
            )
        return resp

    def _read_cookie(self, ident: Identity, url: str, name: str) -> Optional[str]:
        header = ident.jar.header_for(url) or ""
        for pair in header.split("; "):
            if pair.startswith(name + "="):
                return pair[len(name) + 1:]
        return None


__all__ = ["SessionEngine"]
