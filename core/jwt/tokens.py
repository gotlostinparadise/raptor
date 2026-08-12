"""JWT primitives — encode / decode / HMAC-sign, stdlib only (no PyJWT dependency).

A JWS compact token is ``base64url(header).base64url(payload).base64url(sig)``,
base64url *without* padding. This module is deliberately tiny and dependency-free
so the attack capability has no third-party surface; it implements exactly what
the forgery generators and the weak-secret brute need — nothing that would let a
malformed token slip through as valid (verification uses a constant-time compare).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Tuple

# JWA HMAC algorithms → hashlib constructor.
_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _json_segment(obj: Dict[str, Any]) -> str:
    # compact, stable ordering so re-encoding a decoded token is deterministic
    return b64url_encode(json.dumps(obj, separators=(",", ":"),
                                    sort_keys=True).encode("utf-8"))


def signing_input(header: Dict[str, Any], payload: Dict[str, Any]) -> bytes:
    return f"{_json_segment(header)}.{_json_segment(payload)}".encode("ascii")


def encode(header: Dict[str, Any], payload: Dict[str, Any], signature: bytes = b"") -> str:
    """Assemble a compact JWT from its parts (empty signature → ``header.payload.``)."""
    return f"{signing_input(header, payload).decode('ascii')}.{b64url_encode(signature)}"


def decode(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    """Return ``(header, payload, signature, signing_input)`` without verifying.

    Raises ``ValueError`` on a structurally invalid token.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"not a compact JWS (expected 3 segments, got {len(parts)})")
    h_seg, p_seg, s_seg = parts
    try:
        header = json.loads(b64url_decode(h_seg))
        payload = json.loads(b64url_decode(p_seg))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"malformed JWT segment: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header/payload are not JSON objects")
    return header, payload, b64url_decode(s_seg), f"{h_seg}.{p_seg}".encode("ascii")


def sign_hmac(signing_input_bytes: bytes, secret: Any, alg: str = "HS256") -> bytes:
    """HMAC-sign ``signing_input`` with ``secret`` under an HS* algorithm."""
    fn = _HMAC_ALGS.get(alg.upper())
    if fn is None:
        raise ValueError(f"unsupported HMAC alg {alg!r}")
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    return hmac.new(key, signing_input_bytes, fn).digest()


def verify_hmac(token: str, secret: Any) -> bool:
    """True iff ``token``'s signature is a valid HMAC over its own header/payload.

    Reads the algorithm from the token header; a non-HMAC alg is not verifiable
    here and returns False (constant-time compare on the digest).
    """
    try:
        header, _payload, sig, si = decode(token)
    except ValueError:
        return False
    alg = str(header.get("alg", "")).upper()
    if alg not in _HMAC_ALGS:
        return False
    expected = sign_hmac(si, secret, alg)
    return hmac.compare_digest(sig, expected)


__all__ = [
    "b64url_encode", "b64url_decode", "signing_input", "encode", "decode",
    "sign_hmac", "verify_hmac",
]
