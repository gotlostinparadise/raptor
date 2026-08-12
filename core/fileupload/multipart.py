"""Minimal multipart/form-data body builder (stdlib only)."""

from __future__ import annotations

from typing import Dict, Tuple


def build_multipart(field_name: str, filename: str, content: bytes,
                    file_content_type: str, extra_fields: Dict[str, str],
                    boundary: str) -> Tuple[bytes, Dict[str, str]]:
    """Return ``(body_bytes, headers)`` for a multipart upload."""
    crlf = b"\r\n"
    parts = []
    for k, v in (extra_fields or {}).items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'
                     .encode("utf-8"))
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="{field_name}"; '
            f'filename="{filename}"\r\nContent-Type: {file_content_type}\r\n\r\n').encode("utf-8")
    body = b"".join(parts) + head + content + crlf + f"--{boundary}--\r\n".encode("utf-8")
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return body, headers


__all__ = ["build_multipart"]
