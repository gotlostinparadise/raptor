"""The `/sessionid` engine — sample issued tokens, analyse for weakness.

Collects ``count`` tokens (from the config's pre-observed list, or by hitting the
issuing endpoint that many times and reading a Set-Cookie / JSON-path token), then
runs the deterministic analysis. A hard weakness (reuse / predictable sequence) is
a confirmed :class:`~core.webgraph.model.VulnRecord`
(:data:`~core.webgraph.model.PROOF_TOKEN_ANALYSIS`); low entropy is recorded
SUSPECTED.

Safe by default: ``active=False`` analyses only pre-observed tokens (no requests).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from core.sessionid.analysis import analyze
from core.sessionid.config import SessionIdConfig
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import endpoint_id
from core.webgraph.verified import record_confirmed


@dataclass
class SessionIdRun:
    out_dir: str
    base_url: str
    active: bool
    tokens_collected: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "tokens_collected": self.tokens_collected, "finding_count": len(self.findings),
            "findings": self.findings, "warnings": self.warnings,
            "requests_sent": self.requests_sent, "node_count": self.node_count,
            "edge_count": self.edge_count,
        }


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def _fetch(client, method, url, body, headers):
    """One request, tolerating clients (test fakes) without ``raise_on_status``."""
    try:
        return client.request(method, url, body=body, headers=headers,
                              follow_redirects=False, raise_on_status=False)
    except TypeError:
        return client.request(method, url, body=body, headers=headers,
                              follow_redirects=False)


def _extract_cookie(resp: Any, name: str) -> str:
    """Pull ``name``'s value from a response's Set-Cookie header(s)."""
    headers = getattr(resp, "headers", {}) or {}
    raw = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
    m = re.search(rf"(?:^|[;,\s]){re.escape(name)}=([^;,\s]+)", raw)
    return m.group(1) if m else ""


def _extract_json_path(resp: Any, path: str) -> str:
    body = getattr(resp, "body", b"") or b""
    try:
        cur: Any = json.loads(body.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeDecodeError):
        return ""
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return ""
    return str(cur) if isinstance(cur, (str, int)) else ""


def run_sessionid(
    config: SessionIdConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> SessionIdRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = SessionIdRun(out_dir=str(out), base_url=config.base_url, active=active)
    eid = endpoint_id(config.method, config.collect_url)

    tokens: List[str] = list(config.tokens)

    if not tokens:
        if not active:
            run.warnings.append("no pre-observed tokens and not active; nothing to analyse")
            _finalize(out, run, {})
            return run
        if profile == "passive":
            raise ValueError("active sessionid collection cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError("active sessionid refused: config.authorization is empty")
        if not (config.cookie_name or config.token_path):
            raise ValueError("collection needs cookie_name or token_path to read the token")
        host = urlsplit(config.base_url).hostname or ""
        client = (client_factory([host] if host else [])
                  if client_factory is not None else _client_for(config.base_url))
        from core.session.attach import merged_auth_headers
        base_headers = dict(merged_auth_headers(
            config.base_url, session=config.session,
            cookies=config.cookies, headers=config.headers) or {})
        body = config.body.encode("utf-8") if config.body else None
        if body is not None:
            base_headers.setdefault(
                "Content-Type", "application/json" if config.content_type == "json"
                else "application/x-www-form-urlencoded")
        url = f"{config.base_url}{config.collect_url}"
        for _ in range(max(2, config.count)):
            run.requests_sent += 1
            try:
                resp = _fetch(client, config.method.upper(), url, body, base_headers)
            except Exception as exc:
                run.warnings.append(f"collect failed: {type(exc).__name__}: {exc}")
                continue
            if resp is None:
                continue
            tok = (_extract_cookie(resp, config.cookie_name) if config.cookie_name
                   else _extract_json_path(resp, config.token_path))
            if tok:
                tokens.append(tok)

    run.tokens_collected = len(tokens)
    result = analyze(tokens)

    vulns: List[Dict[str, Any]] = []
    if result.confirmed:
        vulns.append(M.VulnRecord(
            id="SID-0001", vuln_class=result.confirmed_class, endpoint_id=eid,
            severity="high", owasp="API2",
            status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_TOKEN_ANALYSIS,
            evidence={"samples": len(tokens), **result.detail},
            source="sessionid").to_row())
        run.findings.append({"id": "SID-0001", "class": result.confirmed_class,
                             "proof": M.PROOF_TOKEN_ANALYSIS})
    elif result.suspected_class:
        vulns.append(M.VulnRecord(
            id="SID-0001", vuln_class=result.suspected_class, endpoint_id=eid,
            severity="medium", owasp="API2",
            status=M.STATUS_SUSPECTED, proof_kind=M.PROOF_NONE,
            evidence={"samples": len(tokens), **result.detail},
            source="sessionid").to_row())
        run.findings.append({"id": "SID-0001", "class": result.suspected_class,
                             "suspected": True})

    accumulated: Dict[str, List[Dict[str, Any]]] = {}
    if vulns:
        accumulated[M.VulnRecord.KIND] = vulns
    confirmed = [v for v in vulns if v.get("status") == M.STATUS_CONFIRMED]
    _finalize(out, run, accumulated)
    if confirmed:
        record_confirmed(confirmed, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: SessionIdRun, accumulated) -> None:
    graph = build_graph(accumulated, [run.base_url])
    persist_records(out / "normalized", accumulated)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count = stats["node_count"]
    run.edge_count = stats["edge_count"]
    (out / "sessionid-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["SessionIdRun", "run_sessionid"]
