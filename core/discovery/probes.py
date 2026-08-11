"""Exposed-file probes + source-map recovery.

A curated list of sensitive paths (VCS metadata, env files, backups, framework
debug endpoints), each with a *content signature* so a match is confirmed by what
the file contains — not merely a 200, which a SPA catch-all route returns for
everything. Source maps are recovered by parsing a JS file's
``sourceMappingURL`` and reading the ``sources`` list from the ``.map``.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple

# (relative path, content-signature regex). A hit needs status 200 AND a match.
EXPOSED_PATHS: List[Tuple[str, str]] = [
    (".git/config", r"\[core\]"),
    (".git/HEAD", r"ref:\s*refs/"),
    (".env", r"(?m)^[A-Z][A-Z0-9_]{2,}="),
    (".env.local", r"(?m)^[A-Z][A-Z0-9_]{2,}="),
    (".DS_Store", r"Bud1"),
    ("backup.sql", r"(?i)CREATE TABLE"),
    ("dump.sql", r"(?i)INSERT INTO"),
    ("wp-config.php.bak", r"DB_PASSWORD"),
    ("config.php.bak", r"<\?php"),
    ("actuator/env", r'"activeProfiles"'),
    ("actuator/health", r'"status"\s*:\s*"UP"'),
    (".aws/credentials", r"aws_access_key_id"),
    (".svn/wc.db", r"SQLite format"),
    ("composer.json", r'"require"'),
    ("phpinfo.php", r"phpinfo\(\)|PHP Version"),
    ("server-status", r"Apache Server Status"),
]


def _text(resp) -> str:
    body = getattr(resp, "body", b"") or b""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def check_exposed(path: str, signature: str, resp) -> Optional[dict]:
    """Return a finding dict if ``resp`` confirms ``path`` is exposed, else None."""
    status = getattr(resp, "status", 0) or 0
    if not (200 <= status < 300):
        return None
    if signature and not re.search(signature, _text(resp)):
        return None
    return {"type": "exposed_file", "path": path, "severity": "high",
            "detail": f"sensitive file {path!r} is publicly accessible"}


def recover_sources(map_body: bytes) -> List[str]:
    """Parse a source-map's ``sources`` list (recovered original file paths)."""
    try:
        data = json.loads(map_body.decode("utf-8", errors="replace"))
    except Exception:
        return []
    sources = data.get("sources") if isinstance(data, dict) else None
    return [str(s) for s in sources] if isinstance(sources, list) else []


__all__ = ["EXPOSED_PATHS", "check_exposed", "recover_sources"]
