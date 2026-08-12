"""The `/fileupload` engine — upload a marker file, locate it, read it back.

Uploads a dangerous-extension file whose body echoes a token-wrapped arithmetic
product, discovers where it was stored (parsed from the upload response, an
operator template, or common upload prefixes), retrieves it, and asks the oracle
whether it EXECUTED (computed product returned) or is merely RETRIEVABLE (source
served verbatim). Either is a confirmed unrestricted upload (CWE-434,
``PROOF_REFLECTED_MARKER``).

Safe by default: ``active=False`` uploads nothing. The uploaded payload is benign
(it echoes a number); it neither writes files nor runs commands.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from core.fileupload.config import FileUploadConfig
from core.fileupload.multipart import build_multipart
from core.fileupload.oracle import UploadMarker, classify_upload
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import endpoint_id
from core.webgraph.verified import record_confirmed


@dataclass
class FileUploadRun:
    out_dir: str
    base_url: str
    active: bool
    stored_path: str = ""
    verdict: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "stored_path": self.stored_path, "verdict": self.verdict,
            "finding_count": len(self.findings), "findings": self.findings,
            "warnings": self.warnings, "requests_sent": self.requests_sent,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def _req(client, method, url, body=None, headers=None):
    try:
        return client.request(method, url, body=body, headers=headers or {},
                              follow_redirects=False, raise_on_status=False)
    except TypeError:
        return client.request(method, url, body=body, headers=headers or {},
                              follow_redirects=False)


def _find_stored_path(resp: Any, filename: str) -> str:
    """Parse the upload response for a path/URL that names the stored file."""
    body = getattr(resp, "body", b"") or b""
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    m = re.search(r'(/[^\s"\'<>]*?' + re.escape(filename) + r')', text)
    return m.group(1) if m else ""


def run_fileupload(
    config: FileUploadConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> FileUploadRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = FileUploadRun(out_dir=str(out), base_url=config.base_url, active=active)
    eid = endpoint_id(config.method, config.upload_url)

    marker = UploadMarker(token="rup" + "af17c3", a=7, b=191)
    filename = f"raptor_{marker.token}{config.ext}"

    if not active:
        run.findings = [{"planned": True, "upload": config.upload_url, "filename": filename}]
        _finalize(out, run, {})
        return run
    if profile == "passive":
        raise ValueError("active fileupload cannot use the passive profile")
    if not config.authorization.strip():
        raise ValueError("active fileupload refused: config.authorization is empty")

    from core.session.attach import merged_auth_headers
    auth = dict(merged_auth_headers(config.base_url, session=config.session,
                                    cookies=config.cookies, headers=config.headers) or {})
    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory([host] if host else [])
              if client_factory is not None else _client_for(config.base_url))

    body, mp_headers = build_multipart(
        config.field_name, filename, marker.php().encode("utf-8"),
        config.upload_content_type, config.extra_fields,
        boundary=f"----raptor{marker.token}")
    up_headers = {**auth, **mp_headers}
    run.requests_sent += 1
    up_resp = _req(client, config.method.upper(), f"{config.base_url}{config.upload_url}",
                   body, up_headers)

    # candidate retrieval paths: parsed from the response, an operator template,
    # then common upload prefixes.
    candidates: List[str] = []
    parsed = _find_stored_path(up_resp, filename)
    if parsed:
        candidates.append(parsed)
    if config.retrieve_template:
        candidates.append(config.retrieve_template.replace("{filename}", filename))
    candidates.extend(f"{p}{filename}" for p in config.retrieve_prefixes)

    verdict = ""
    for path in candidates:
        url = path if "://" in path else f"{config.base_url}{path}"
        run.requests_sent += 1
        v = classify_upload(_req(client, "GET", url, None, auth), marker)
        if v:
            verdict, run.stored_path = v, path
            break

    run.verdict = verdict
    vulns: List[Dict[str, Any]] = []
    if verdict:
        vulns.append(M.VulnRecord(
            id="UP-0001", vuln_class="unrestricted_file_upload", endpoint_id=eid,
            severity="high" if verdict == "executed" else "medium", owasp="API8",
            status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_REFLECTED_MARKER,
            evidence={"verdict": verdict, "stored_path": run.stored_path,
                      "filename": filename, "executed": verdict == "executed"},
            source="fileupload").to_row())
        run.findings.append({"id": "UP-0001", "class": "unrestricted_file_upload",
                             "proof": M.PROOF_REFLECTED_MARKER, "verdict": verdict})
    else:
        run.warnings.append("upload not confirmed (rejected, not stored, or path not found)")

    accumulated: Dict[str, List[Dict[str, Any]]] = {}
    if vulns:
        accumulated[M.VulnRecord.KIND] = vulns
    _finalize(out, run, accumulated)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: FileUploadRun, accumulated) -> None:
    graph = build_graph(accumulated, [run.base_url])
    persist_records(out / "normalized", accumulated)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count = stats["node_count"]
    run.edge_count = stats["edge_count"]
    (out / "fileupload-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["FileUploadRun", "run_fileupload"]
