"""The `/race` engine — fire concurrent requests, verdict via the state oracle.

For each declared test it fires N identical requests simultaneously
(:mod:`core.racecond.harness`) and counts how many succeeded
(:mod:`core.racecond.oracle`). If more succeeded than the operator-declared limit
(``expected_max``), the limit is not atomic — a confirmed race
(``PROOF_STATE_ORACLE``). Requests are sent directly (not through per-identity
session state) to avoid the harness racing on a shared cookie jar; a static auth
header is resolved once up front.

Safe by default: ``active=False`` sends nothing. Concurrency is hard-capped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from core.http import HttpError, Response
from core.racecond import oracle
from core.racecond.config import RaceConfig, RaceTest
from core.racecond.harness import fire_concurrent
from core.session.login import resolve_credential
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import canonical_origin, endpoint_id
from core.webgraph.verified import record_confirmed


@dataclass
class RaceRun:
    out_dir: str
    base_url: str
    active: bool
    tests_planned: int = 0
    tests_run: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    @property
    def violations(self):
        return [f for f in self.findings if f.get("violation")]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "tests_planned": self.tests_planned, "tests_run": self.tests_run,
            "violation_count": len(self.violations), "findings": self.findings,
            "warnings": self.warnings, "requests_sent": self.requests_sent,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def _send_once(client, method, url, body, headers) -> Any:
    """One request, normalising a raised HttpError to a Response (status as data)."""
    try:
        return client.request(method, url, body=body, headers=headers,
                              follow_redirects=False, retries=0)
    except HttpError as exc:
        return Response(status=int(exc.status or 0), headers={}, body=b"", url=url)


def _encode_body(test: RaceTest):
    if not test.body:
        return None, {}
    if test.content_type == "json":
        return test.body.encode("utf-8"), {"Content-Type": "application/json"}
    # already-encoded string bodies pass through; dict-ish would be encoded upstream
    return test.body.encode("utf-8"), {"Content-Type": "application/x-www-form-urlencoded"}


def run_race(
    config: RaceConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> RaceRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = RaceRun(out_dir=str(out), base_url=config.base_url, active=active,
                  tests_planned=len(config.tests))

    if active:
        if profile == "passive":
            raise ValueError("active testing cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError("active testing refused: config.authorization is empty")

    if not active:
        run.findings = [{"id": t.id, "endpoint": t.label, "concurrency": t.concurrency,
                         "expected_max": t.expected_max, "planned": True}
                        for t in config.tests]
        _finalize(out, run, {})
        return run

    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory or (lambda h: _client_for(config.base_url)))(
        [host] if host else [])

    # Shared authenticated session: a static header snapshot (auth headers +
    # Cookie for this origin) from the threaded session / config cookies+headers,
    # attached to every concurrent request. A token_env bearer still wins if set.
    from core.session.attach import merged_auth_headers
    auth_headers: Dict[str, str] = dict(merged_auth_headers(
        config.base_url, session=config.session,
        cookies=config.cookies, headers=config.headers))
    if config.token_env:
        tok = resolve_credential(config.token_env, env)
        if tok:
            auth_headers["Authorization"] = f"Bearer {tok}"
        else:
            run.warnings.append(f"missing ${config.token_env}; testing unauthenticated")

    vulns: List[Dict[str, Any]] = []
    for test in config.tests:
        n = min(test.concurrency, config.max_concurrency)
        if n < 2:
            run.warnings.append(f"test {test.id}: concurrency<2, skipped")
            continue
        body, ct = _encode_body(test)
        headers = {**auth_headers, **ct, **test.headers}
        url = f"{config.base_url}{test.path}"

        def make_request(_i, _m=test.method, _u=url, _b=body, _h=headers):
            return _send_once(client, _m.upper(), _u, _b, _h)

        results = fire_concurrent(make_request, n)
        run.requests_sent += n
        run.tests_run += 1
        successes = oracle.count_successes(
            results, success_status=test.success_status, signature=test.success_signature)
        violated = oracle.race_detected(successes, test.expected_max)
        # A confirmed race needs a reliable success signal. Without a
        # ``success_signature``, a 2xx does NOT prove the operation succeeded —
        # many apps return 200 with a rejection body for the losing racers — so
        # the finding is only SUSPECTED (never a verified outcome). With a
        # signature, real successes are counted and a violation is CONFIRMED.
        confirmed = violated and bool(test.success_signature)
        if violated and not test.success_signature:
            run.warnings.append(
                f"test {test.id}: {successes} apparent successes but no "
                f"success_signature — reporting SUSPECTED (set success_signature "
                f"to confirm; a 200 may be a rejection body)")
        run.findings.append({"id": test.id, "endpoint": test.label,
                             "class": test.vuln_class, "concurrency": n,
                             "successes": successes, "expected_max": test.expected_max,
                             "violation": violated, "confirmed": confirmed})
        if violated:
            vulns.append(M.VulnRecord(
                id=test.id, vuln_class=test.vuln_class,
                endpoint_id=endpoint_id(test.method, test.path), severity="high",
                owasp=test.owasp,
                status=M.STATUS_CONFIRMED if confirmed else M.STATUS_SUSPECTED,
                proof_kind=M.PROOF_STATE_ORACLE if confirmed else M.PROOF_NONE,
                evidence={"concurrency": n, "successes": successes,
                          "expected_max": test.expected_max,
                          "signature_gated": bool(test.success_signature),
                          "detail": f"{successes} concurrent operations succeeded; "
                                    f"limit is {test.expected_max}"},
                source="race").to_row())

    recs = {M.VulnRecord.KIND: vulns} if vulns else {}
    _finalize(out, run, recs)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: RaceRun, recs) -> None:
    origin = canonical_origin(run.base_url)
    graph = build_graph(recs, [origin] if origin else [])
    persist_records(out / "normalized", recs)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count, run.edge_count = stats["node_count"], stats["edge_count"]
    (out / "race-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["RaceRun", "run_race"]
