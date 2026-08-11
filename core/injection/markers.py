"""Unique, deterministic injection markers.

Every injection payload carries a marker that is (a) unlikely to occur naturally
in a response and (b) *computed* where possible, so a match proves execution
rather than mere reflection. SSTI is the clearest case: injecting ``{{191*193}}``
and finding ``36863`` in the response proves server-side evaluation — a literal
reflection would echo the braces, not the product.

The factory is seeded, so a run is reproducible and tests are deterministic (no
``random`` on the hot path).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Marker:
    """One injection's marker: a raw token plus an arithmetic pair for SSTI."""

    token: str          # e.g. "rap000001z" — unlikely to appear naturally
    a: int              # arithmetic operands whose product is the SSTI oracle
    b: int

    @property
    def product(self) -> int:
        return self.a * self.b

    def wrap(self, inner: str) -> str:
        """Bracket ``inner`` with the token so a reflected value is unambiguous."""
        return f"{self.token}{inner}{self.token}"

    @property
    def sentinel(self) -> str:
        """A bare, high-entropy token to look for in reflection oracles."""
        return self.token


# A short list of distinct prime-ish pairs, cycled by index so successive
# markers use different products (a coincidental collision on one is unlikely to
# repeat on the next).
_PAIRS = [(191, 193), (211, 223), (233, 239), (251, 257), (263, 269)]


class MarkerFactory:
    def __init__(self, salt: str = "rap") -> None:
        self.salt = salt
        self._n = 0

    def next(self) -> Marker:
        self._n += 1
        a, b = _PAIRS[self._n % len(_PAIRS)]
        return Marker(token=f"{self.salt}{self._n:06d}z", a=a, b=b)


__all__ = ["Marker", "MarkerFactory"]
