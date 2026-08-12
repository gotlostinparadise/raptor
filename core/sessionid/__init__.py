"""Weak / predictable session-identifier detection (M4 S5).

Collects several issued session tokens and analyses them for *deterministic*
weaknesses — reuse across sessions, or a predictable sequence (constant-delta
integers, decimal/hex/base64). Those hard signals confirm
(:data:`core.webgraph.model.PROOF_TOKEN_ANALYSIS`); a merely low-entropy token is
reported SUSPECTED, never stamped confirmed on a threshold alone.
"""

from __future__ import annotations

from core.sessionid.analysis import Analysis, analyze

__all__ = ["Analysis", "analyze"]
