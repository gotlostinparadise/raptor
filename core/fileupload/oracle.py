"""Oracle for file-upload findings — executed vs retrievable vs nothing.

The marker file echoes a token-wrapped arithmetic PRODUCT. If the server executes
it, the retrieved body carries ``<tok>PRODUCT<tok>`` (only code execution yields
the computed number). If the server merely serves the file, the body carries the
literal source (``<?php`` … ``a*b`` …) — still an unrestricted upload, but not
executed. Neither can be faked by an unrelated page: the token is unique per run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class UploadMarker:
    token: str
    a: int
    b: int

    @property
    def product(self) -> int:
        return self.a * self.b

    @property
    def executed_signature(self) -> str:
        return f"{self.token}{self.product}{self.token}"

    def php(self) -> str:
        # served-as-source carries the literal token; executed carries the product
        return f"<?php echo '{self.token}'.({self.a}*{self.b}).'{self.token}'; ?>"


def _text(resp: Any) -> str:
    body = getattr(resp, "body", b"") or b""
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)


def classify_upload(resp: Any, marker: UploadMarker) -> str:
    """Return "executed", "retrievable", or "" for a retrieval response."""
    if resp is None:
        return ""
    status = getattr(resp, "status", 0) or 0
    if not (200 <= status < 300):
        return ""
    text = _text(resp)
    if marker.executed_signature in text:
        return "executed"
    # source served back verbatim (token present, but not the computed product)
    if marker.token in text and f"{marker.a}*{marker.b}" in text:
        return "retrievable"
    return ""


__all__ = ["UploadMarker", "classify_upload"]
