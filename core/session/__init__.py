"""Multi-identity session engine — the authenticated substrate for web testing.

Almost everything valuable in a web/API pentest lives behind authentication, and
the single highest-impact class — broken access control (IDOR/BOLA/BFLA) — can
only be found by comparing what *different* identities can do. This subsystem
provides both: a session engine that sends requests *as* a named identity
(injecting its cookies + auth, capturing Set-Cookie + CSRF, refreshing on 401),
and an authorization oracle that replays one request as A vs B vs anonymous and
mechanically verdicts the diff.

Pieces:

  - :mod:`core.session.identity` — :class:`Identity`: per-actor cookie jar, auth
    headers, CSRF token, credential env-var refs. Strict per-identity isolation.
  - :mod:`core.session.jar` — a pragmatic host+path cookie jar.
  - :mod:`core.session.engine` — :class:`SessionEngine` over the
    :class:`core.http.HttpClient` chokepoint.
  - :mod:`core.session.login` — login strategies (Bearer/ApiKey/Basic/Form; the
    substrate richer OAuth/OIDC/SAML flows reduce to).
  - :mod:`core.session.replay` — the A/B/anonymous authorization oracle.
  - :mod:`core.session.authz` — adapter to :mod:`core.webgraph` records / proofs.

Transport-agnostic by construction: the engine takes any ``HttpClient``, so the
whole oracle is unit-testable with no network, and in production runs through the
egress-allowlisted ``EgressClient``.
"""

from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.replay import (
    AuthzVerdict, Observation, RequestTemplate, authorization_diff, replay,
)

__all__ = [
    "SessionEngine", "Identity", "RequestTemplate", "Observation",
    "AuthzVerdict", "replay", "authorization_diff",
]
