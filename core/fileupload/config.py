"""Configuration for `/fileupload` — unrestricted file-upload testing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping

# Common web-exposed upload directories, tried (with the stored filename) when the
# upload response does not reveal the path itself. DVWA's is first.
DEFAULT_RETRIEVE_PREFIXES = (
    "/hackable/uploads/", "/uploads/", "/upload/", "/files/", "/media/",
    "/static/uploads/", "/assets/uploads/", "/",
)


@dataclass
class FileUploadConfig:
    base_url: str
    authorization: str = ""
    upload_url: str = "/upload"
    method: str = "POST"
    field_name: str = "file"           # multipart file field name
    ext: str = ".php"                  # dangerous extension to attempt
    upload_content_type: str = "application/x-php"
    extra_fields: Dict[str, str] = field(default_factory=dict)  # co-submitted form fields
    #: Where the stored file is served, as a template with {filename}. When empty,
    #: the runner parses the response for the path, else guesses common prefixes.
    retrieve_template: str = ""
    retrieve_prefixes: List[str] = field(default_factory=lambda: list(DEFAULT_RETRIEVE_PREFIXES))
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session: Any = field(default=None, repr=False, compare=False)


def from_dict(data: Mapping[str, Any]) -> FileUploadConfig:
    base_url = (data.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("fileupload config requires a base_url")
    return FileUploadConfig(
        base_url=base_url, authorization=data.get("authorization", ""),
        upload_url=data.get("upload_url", "/upload"), method=data.get("method", "POST"),
        field_name=data.get("field_name", "file"), ext=data.get("ext", ".php"),
        upload_content_type=data.get("upload_content_type", "application/x-php"),
        extra_fields=dict(data.get("extra_fields") or {}),
        retrieve_template=data.get("retrieve_template", ""),
        retrieve_prefixes=list(data.get("retrieve_prefixes") or DEFAULT_RETRIEVE_PREFIXES),
        cookies=dict(data.get("cookies") or {}), headers=dict(data.get("headers") or {}),
    )


def load_config(path: Path) -> FileUploadConfig:
    return from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


__all__ = ["DEFAULT_RETRIEVE_PREFIXES", "FileUploadConfig", "from_dict", "load_config"]
