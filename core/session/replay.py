"""The authorization oracle: replay one request as A vs B vs anonymous, diff.

This is where RAPTOR's "LLM proposes, a tool verifies" discipline meets access
control. The LLM (or a Phase-B driver) proposes a :class:`RequestTemplate` and
says which identity legitimately *owns* the object it touches. This module then
sends that exact request as each identity and compares the responses. The
**verdict is mechanical**: if an identity that should be denied instead gets the
*same resource back* (identical response-body hash as the owner), that is a
confirmed horizontal authorization break (BOLA/IDOR) — not an LLM guess.

Nothing here imports the web graph; it returns neutral observations. The adapter
in :mod:`core.session.authz` turns a verdict into graph records / a proof.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RequestTemplate:
    """One request to replay across identities."""

    method: str
    url: str
    body: Optional[bytes] = None
    headers: Optional[Dict[str, str]] = None
    #: Optional human label / endpoint id for reporting.
    label: str = ""


@dataclass
class Observation:
    """What one identity saw when the template was replayed as it."""

    identity: str
    status: Optional[int]
    resp_len: int
    body_sha256: str
    allowed: bool

    @property
    def denied(self) -> bool:
        return not self.allowed


@dataclass
class AuthzVerdict:
    """Outcome of an A/B/anonymous diff for one request template."""

    label: str
    owner: str
    observations: List[Observation] = field(default_factory=list)
    violation: bool = False
    #: identities that reached the owner's resource but shouldn't have.
    offending: List[str] = field(default_factory=list)

    def observation(self, identity: str) -> Optional[Observation]:
        for o in self.observations:
            if o.identity == identity:
                return o
        return None


def _is_allowed(status: Optional[int]) -> bool:
    """Access was granted only on a 2xx with the resource.

    Deliberately excludes 3xx: a redirect (typically 302 → /login) is a *denial*
    in most apps, not resource access — counting it as allowed would both miss
    real denials and, because redirect bodies are near-identical across
    identities, manufacture false BOLA violations.
    """
    return status is not None and 200 <= status < 300


def replay(engine, template: RequestTemplate, identity_name: str) -> Observation:
    """Send ``template`` as ``identity_name``; return an :class:`Observation`."""
    resp = engine.request(
        identity_name, template.method, template.url,
        body=template.body, headers=template.headers, follow_redirects=False,
    )
    body = resp.body or b""
    return Observation(
        identity=identity_name,
        status=resp.status,
        resp_len=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        allowed=_is_allowed(resp.status),
    )


def authorization_diff(
    engine,
    template: RequestTemplate,
    owner: str,
    others: Optional[List[str]] = None,
) -> AuthzVerdict:
    """Replay ``template`` as ``owner`` and every other identity; verdict the diff.

    ``owner`` is the identity that legitimately accesses the object. ``others``
    defaults to every registered identity except the owner (``anonymous``
    always included). A violation is recorded when a non-owner identity is
    *allowed* and receives a body identical to the owner's — i.e. it read the
    owner's object. Requires the owner itself to be allowed (a valid baseline);
    otherwise the template is mis-specified and no verdict is made.
    """
    if others is None:
        others = [n for n in engine.names() if n != owner]
    if "anonymous" not in others and "anonymous" != owner:
        others = list(others) + ["anonymous"]

    verdict = AuthzVerdict(label=template.label or template.url, owner=owner)
    base = replay(engine, template, owner)
    verdict.observations.append(base)
    if not base.allowed:
        # No valid baseline — can't distinguish "everyone denied" from a break.
        return verdict

    for name in others:
        obs = replay(engine, template, name)
        verdict.observations.append(obs)
        if obs.allowed and obs.body_sha256 == base.body_sha256:
            verdict.violation = True
            verdict.offending.append(name)
    return verdict


__all__ = [
    "RequestTemplate", "Observation", "AuthzVerdict", "replay",
    "authorization_diff",
]
