"""The `/csrf` engine — replay a state-change with and without the anti-CSRF token.

Establishes a baseline (the request WITH its token succeeds), then replays it with
the token FIELD REMOVED. If the token-less request also succeeds, the server does
not validate an anti-CSRF token on that request — a confirmed CSRF weakness
(``PROOF_STATE_ORACLE``, CWE-352). If the token-less request is rejected, the
token is enforced — no finding.

Safe by default: ``active=False`` sends nothing. The request is the operator's own
(a benign, reversible state change on an authorized target).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from core.csrf.config import CsrfConfig
from core.csrf.strip import strip_token
from core.racecond.oracle import is_success
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import endpoint_id
from core.webgraph.verified import record_confirmed


@dataclass
class CsrfRun:
    out_dir: str
    base_url: str
    active: bool
    baseline_ok: bool = False
    token_absent_ok: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "baseline_ok": self.baseline_ok, "token_absent_ok": self.token_absent_ok,
            "finding_count": len(self.findings), "findings": self.findings,
            "warnings": self.warnings, "requests_sent": self.requests_sent,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def _send(client, method, url, body, headers):
    b = body.encode("utf-8") if isinstance(body, str) else body
    try:
        return client.request(method, url, body=b, headers=headers,
                              follow_redirects=False, raise_on_status=False)
    except TypeError:
        return client.request(method, url, body=b, headers=headers, follow_redirects=False)


def run_csrf(
    config: CsrfConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> CsrfRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = CsrfRun(out_dir=str(out), base_url=config.base_url, active=active)
    eid = endpoint_id(config.method, config.path)

    if not active:
        run.findings = [{"planned": True, "endpoint": config.path,
                         "token_field": config.token_field}]
        _finalize(out, run, {})
        return run
    if profile == "passive":
        raise ValueError("active csrf cannot use the passive profile")
    if not config.authorization.strip():
        raise ValueError("active csrf refused: config.authorization is empty")
    if not config.body:
        raise ValueError("csrf needs a working request body (incl. the token field)")

    from core.session.attach import merged_auth_headers
    headers = dict(merged_auth_headers(config.base_url, session=config.session,
                                       cookies=config.cookies, headers=config.headers) or {})
    headers.setdefault("Content-Type", "application/json" if config.content_type == "json"
                       else "application/x-www-form-urlencoded")
    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory([host] if host else [])
              if client_factory is not None else _client_for(config.base_url))
    url = f"{config.base_url}{config.path}"

    def ok(resp) -> bool:
        return is_success(resp, success_status=config.success_status,
                          signature=config.success_signature)

    run.requests_sent += 1
    run.baseline_ok = ok(_send(client, config.method.upper(), url, config.body, headers))
    if not run.baseline_ok:
        run.warnings.append("baseline (with token) did not succeed — request/creds "
                            "mis-specified; cannot conclude")
        _finalize(out, run, {})
        return run

    stripped = strip_token(config.body, config.token_field, config.content_type)
    if stripped == config.body:
        run.warnings.append(f"token_field {config.token_field!r} not present in body — "
                            "nothing to strip")
    run.requests_sent += 1
    run.token_absent_ok = ok(_send(client, config.method.upper(), url, stripped, headers))

    vulns: List[Dict[str, Any]] = []
    if run.token_absent_ok:
        vulns.append(M.VulnRecord(
            id="CSRF-0001", vuln_class="csrf", endpoint_id=eid, param=config.token_field,
            severity="medium", owasp="API2",
            status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_STATE_ORACLE,
            evidence={"token_field": config.token_field,
                      "baseline_ok": True, "token_absent_ok": True,
                      "note": "state change succeeded with the anti-CSRF token removed"},
            source="csrf").to_row())
        run.findings.append({"id": "CSRF-0001", "class": "csrf",
                             "proof": M.PROOF_STATE_ORACLE})
    else:
        run.warnings.append("token-less request rejected — anti-CSRF token enforced")

    accumulated: Dict[str, List[Dict[str, Any]]] = {}
    if vulns:
        accumulated[M.VulnRecord.KIND] = vulns
    _finalize(out, run, accumulated)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: CsrfRun, accumulated) -> None:
    graph = build_graph(accumulated, [run.base_url])
    persist_records(out / "normalized", accumulated)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count = stats["node_count"]
    run.edge_count = stats["edge_count"]
    (out / "csrf-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["CsrfRun", "run_csrf"]
