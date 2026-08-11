"""An :class:`Identity` — one authenticated (or anonymous) actor.

The app-layer answer to recon's bare role strings and the API workflow's
placeholder ``["anonymous", "user_a", ...]`` list: a first-class object carrying
the actor's own cookie jar, injected auth headers (bearer/API-key), any CSRF
token captured for it, and the *credential references* used to (re)authenticate —
never the raw secrets in code, always env-var names, mirroring recon's
``credential_env_vars`` discipline.

Multiple identities are the whole point: the authorization oracle
(:mod:`core.session.replay`) replays one request as A vs B vs anonymous and
diffs the responses, which only means anything if each identity's session state
is strictly isolated. That isolation lives here — one jar, one token set, per
identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from core.session.jar import CookieJar


@dataclass
class Identity:
    """One actor's session state + how to authenticate it."""

    name: str
    role: str = ""
    #: Static auth headers to inject on every request (e.g. ``Authorization``,
    #: ``X-API-Key``). Populated by a login strategy or seeded directly.
    auth_headers: Dict[str, str] = field(default_factory=dict)
    #: This identity's isolated cookie jar.
    jar: CookieJar = field(default_factory=CookieJar)
    #: Most recently captured CSRF token (name→value), replayed on mutations.
    csrf: Dict[str, str] = field(default_factory=dict)
    #: Env-var names holding this identity's credentials — resolved in-process,
    #: never written to a child env (kept out of ``get_safe_env``).
    credential_env_vars: tuple = ()
    #: True once a login strategy has established a session.
    authenticated: bool = False

    def is_anonymous(self) -> bool:
        return self.name == "anonymous" or (
            not self.authenticated and not self.auth_headers and not self.jar.names()
        )

    def request_headers(self, url: str, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Merge base headers + this identity's auth headers + Cookie header.

        Caller-supplied ``base`` wins over auth headers only where it sets the
        same key explicitly; the ``Cookie`` header is always derived from the
        identity's jar for ``url``.
        """
        headers: Dict[str, str] = {}
        headers.update(self.auth_headers)
        if base:
            headers.update(base)
        cookie = self.jar.header_for(url)
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def set_bearer(self, token: str) -> None:
        self.auth_headers["Authorization"] = f"Bearer {token}"

    def set_api_key(self, header: str, value: str) -> None:
        self.auth_headers[header] = value


__all__ = ["Identity"]
