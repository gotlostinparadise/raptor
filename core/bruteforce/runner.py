"""The `/bruteforce` engine — fire N failed logins, verdict via the lockout oracle.

Sends ``attempts`` identical failed-authentication requests and asks the oracle
whether the target ever locked out or throttled. If it never did (and enough
attempts were made), that absence of brute-force protection is a confirmed
finding (``PROOF_STATE_ORACLE``, CWE-307). If a lockout kicked in at attempt K,
protection exists — no finding, K is reported.

Safe by default: ``active=False`` sends nothing. All requests are FAILED logins
(wrong credentials the operator supplies), so no account is actually accessed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from core.bruteforce.config import BruteforceConfig
from core.bruteforce.oracle import DEFAULT_LOCKOUT_SIGNATURES, lockout_index, no_protection
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import endpoint_id
from core.webgraph.verified import record_confirmed


@dataclass
class BruteforceRun:
    out_dir: str
    base_url: str
    active: bool
    attempts_made: int = 0
    lockout_at: Optional[int] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "attempts_made": self.attempts_made, "lockout_at": self.lockout_at,
            "finding_count": len(self.findings), "findings": self.findings,
            "warnings": self.warnings, "requests_sent": self.requests_sent,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def _fetch(client, method, url, body, headers):
    try:
        return client.request(method, url, body=body, headers=headers,
                              follow_redirects=False, raise_on_status=False)
    except TypeError:
        return client.request(method, url, body=body, headers=headers,
                              follow_redirects=False)


def run_bruteforce(
    config: BruteforceConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> BruteforceRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = BruteforceRun(out_dir=str(out), base_url=config.base_url, active=active)
    eid = endpoint_id(config.method, config.login_url)

    if not active:
        run.findings = [{"planned": True, "attempts": config.attempts,
                         "endpoint": config.login_url}]
        _finalize(out, run, {})
        return run
    if profile == "passive":
        raise ValueError("active bruteforce cannot use the passive profile")
    if not config.authorization.strip():
        raise ValueError("active bruteforce refused: config.authorization is empty")

    from core.session.attach import merged_auth_headers
    headers = dict(merged_auth_headers(config.base_url, session=config.session,
                                       cookies=config.cookies, headers=config.headers) or {})
    body = config.body.encode("utf-8") if config.body else None
    if body is not None:
        headers.setdefault("Content-Type", "application/json"
                           if config.content_type == "json"
                           else "application/x-www-form-urlencoded")
    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory([host] if host else [])
              if client_factory is not None else _client_for(config.base_url))
    url = f"{config.base_url}{config.login_url}"
    sigs = DEFAULT_LOCKOUT_SIGNATURES + tuple(s.lower() for s in config.lockout_signatures)

    responses: List[Any] = []
    for _ in range(max(config.min_attempts, config.attempts)):
        run.requests_sent += 1
        try:
            responses.append(_fetch(client, config.method.upper(), url, body, headers))
        except Exception as exc:
            run.warnings.append(f"attempt failed: {type(exc).__name__}: {exc}")
            responses.append(None)
    run.attempts_made = sum(1 for r in responses if r is not None)
    run.lockout_at = lockout_index(responses, sigs)

    vulns: List[Dict[str, Any]] = []
    if no_protection(responses, min_attempts=config.min_attempts, signatures=sigs):
        vulns.append(M.VulnRecord(
            id="BF-0001", vuln_class="no_bruteforce_protection", endpoint_id=eid,
            severity="medium", owasp="API4",
            status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_STATE_ORACLE,
            evidence={"failed_attempts": run.attempts_made, "lockout": False,
                      "note": f"no lockout/throttle within {run.attempts_made} failed attempts"},
            source="bruteforce").to_row())
        run.findings.append({"id": "BF-0001", "class": "no_bruteforce_protection",
                             "proof": M.PROOF_STATE_ORACLE, "attempts": run.attempts_made})
    elif run.lockout_at is not None:
        run.warnings.append(f"lockout/throttle at attempt {run.lockout_at} — protection present")

    accumulated: Dict[str, List[Dict[str, Any]]] = {}
    if vulns:
        accumulated[M.VulnRecord.KIND] = vulns
    _finalize(out, run, accumulated)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: BruteforceRun, accumulated) -> None:
    graph = build_graph(accumulated, [run.base_url])
    persist_records(out / "normalized", accumulated)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count = stats["node_count"]
    run.edge_count = stats["edge_count"]
    (out / "bruteforce-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["BruteforceRun", "run_bruteforce"]
