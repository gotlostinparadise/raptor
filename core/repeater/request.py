"""A tamperable HTTP request spec — the unit a repeater sends and a PoC encodes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl


@dataclass
class RequestSpec:
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"method": self.method, "url": self.url,
                "headers": dict(self.headers), "body": self.body}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "RequestSpec":
        if not d.get("url"):
            raise ValueError("request spec requires a url")
        return cls(method=d.get("method", "GET"), url=d["url"],
                   headers=dict(d.get("headers") or {}), body=d.get("body", ""))

    @classmethod
    def load(cls, path: Path) -> "RequestSpec":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def with_header(self, name: str, value: str) -> "RequestSpec":
        h = dict(self.headers)
        h[name] = value
        return RequestSpec(self.method, self.url, h, self.body)

    def with_query(self, param: str, value: str) -> "RequestSpec":
        parts = urlsplit(self.url)
        q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
        q.append((param, value))
        new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
        return RequestSpec(self.method, new_url, dict(self.headers), self.body)

    def tamper(self, *, method=None, url=None, body=None, **header_overrides) -> "RequestSpec":
        h = dict(self.headers)
        h.update(header_overrides)
        return RequestSpec(method or self.method, url or self.url, h,
                           self.body if body is None else body)


__all__ = ["RequestSpec"]
