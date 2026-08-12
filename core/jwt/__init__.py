"""JWT attack capability — forge tokens, confirm the server accepted the forgery.

A Shape-2 capability (config → runner → oracle → VulnRecord → record_confirmed):
the LLM/operator points it at a protected endpoint plus one valid token, and the
runner mechanically proves whether the server's token validation can be bypassed.
The verdict is a tool's, not a guess: a forged token is a finding only when a
deliberately-corrupted token is *rejected* (proving the endpoint validates at all)
AND the forgery is *accepted* — the forged-token-accepted A/B oracle
(:mod:`core.jwt.oracle`), carrying :data:`core.webgraph.model.PROOF_TOKEN_FORGED`.
"""

from __future__ import annotations

from core.jwt.tokens import decode, encode, sign_hmac, verify_hmac

__all__ = ["decode", "encode", "sign_hmac", "verify_hmac"]
