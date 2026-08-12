"""Deterministic weakness analysis over a set of issued session tokens.

The verdict is a computation, not a guess. Two weaknesses are *hard* (confirmed):

  * **reuse** — the same identifier is handed to different sessions (session
    fixation / non-unique id): CWE-384;
  * **predictable** — the identifiers form an arithmetic sequence (constant, non-
    zero delta) when parsed as integers in some base (decimal, hex, or the big-
    endian integer of their base64/hex bytes): CWE-330. A constant delta across
    ≥3 samples is not plausibly coincidental for a random id.

A third signal — **low entropy** — is reported but only as *suspected*: an
entropy threshold is a heuristic, and the invariant is that ``confirmed`` never
rests on a threshold. It is surfaced so an operator can follow up.
"""

from __future__ import annotations

import base64
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Analysis:
    tokens: List[str]
    #: hard-confirmed weakness class ("" when none): predictable_session_id /
    #: session_id_reuse.
    confirmed_class: str = ""
    #: soft (suspected) weakness class ("" when none): weak_session_id.
    suspected_class: str = ""
    detail: Dict[str, object] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return bool(self.confirmed_class)


def shannon_entropy(s: str) -> float:
    """Bits of Shannon entropy per character of ``s`` (0 for empty)."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _as_int(token: str) -> Optional[int]:
    """Parse a token to an integer in the most permissive plausible base.

    Tries decimal, then hex, then the big-endian integer of its base64url / hex
    bytes — so ``"1001"``, ``"0x3e9"`` and a base64 counter all become numbers a
    sequence check can compare. Returns None when nothing parses.
    """
    t = token.strip()
    if not t:
        return None
    if t.isdigit():
        return int(t)
    try:
        return int(t, 16)
    except ValueError:
        pass
    for dec in (_b64_bytes, _hex_bytes):
        b = dec(t)
        if b:
            return int.from_bytes(b, "big")
    return None


def _b64_bytes(t: str) -> Optional[bytes]:
    try:
        return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None


def _hex_bytes(t: str) -> Optional[bytes]:
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def _constant_delta(nums: List[int]) -> Optional[int]:
    """Return the constant delta if ``nums`` is a non-trivial arithmetic run."""
    if len(nums) < 3:
        return None
    deltas = {nums[i + 1] - nums[i] for i in range(len(nums) - 1)}
    if len(deltas) == 1:
        d = deltas.pop()
        return d if d != 0 else None
    return None


# Below this per-char entropy AND short, a token is suspiciously guessable. Kept
# conservative — this only drives the SUSPECTED signal, never a confirmation.
_LOW_ENTROPY_BITS = 2.5
_SHORT_LEN = 16


def analyze(tokens: List[str]) -> Analysis:
    """Analyse issued tokens in issue order; see module docstring for the verdicts."""
    toks = [t for t in tokens if t]
    a = Analysis(tokens=list(toks))
    if len(toks) < 2:
        a.detail["note"] = "need >=2 tokens to compare"
        return a

    # (1) reuse — same id to different sessions
    if len(set(toks)) < len(toks):
        a.confirmed_class = "session_id_reuse"
        a.detail["reused"] = sorted({t for t in toks if toks.count(t) > 1})
        return a

    # (2) predictable — arithmetic sequence in some base
    nums = [_as_int(t) for t in toks]
    if all(n is not None for n in nums):
        delta = _constant_delta([n for n in nums if n is not None])
        if delta is not None:
            a.confirmed_class = "predictable_session_id"
            a.detail.update({"delta": delta, "parsed_ints": nums})
            return a

    # (3) low entropy — suspected only
    per_char = min(shannon_entropy(t) for t in toks)
    a.detail["min_entropy_bits_per_char"] = round(per_char, 3)
    a.detail["min_len"] = min(len(t) for t in toks)
    if per_char < _LOW_ENTROPY_BITS and min(len(t) for t in toks) < _SHORT_LEN:
        a.suspected_class = "weak_session_id"
    return a


__all__ = ["Analysis", "analyze", "shannon_entropy"]
