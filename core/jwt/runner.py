"""The `/jwt` engine — forge tokens, confirm the server accepted them.

For a protected endpoint + one valid token it establishes the baseline (valid →
accepted) and the negative control (corrupted signature → rejected), then fires
each candidate forgery (alg:none, weak-secret) and confirms only those the server
accepts (:mod:`core.jwt.oracle`). A confirmation is a
:class:`~core.webgraph.model.VulnRecord` carrying
:data:`~core.webgraph.model.PROOF_TOKEN_FORGED` — the tool's verdict, not the LLM's.

Safe by default: ``active=False`` analyses the token + plans the forgeries but
sends nothing. ``active=True`` requires a non-empty ``authorization`` (recorded on
every proof) and a non-passive profile.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from core.jwt.attacks import DEFAULT_SECRETS, corrupt_signature, generate_forgeries
from core.jwt.config import JwtConfig
from core.jwt.oracle import forgery_confirmed, is_accepted
from core.jwt.tokens import decode
from core.session.login import resolve_credential
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import endpoint_id
from core.webgraph.verified import record_confirmed


@dataclass
class JwtRun:
    out_dir: str
    base_url: str
    active: bool
    forgeries_tried: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "forgeries_tried": self.forgeries_tried, "finding_count": len(self.findings),
            "findings": self.findings, "warnings": self.warnings,
            "requests_sent": self.requests_sent, "node_count": self.node_count,
            "edge_count": self.edge_count,
        }


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def _status(client, method: str, url: str, headers: Dict[str, str]) -> Optional[int]:
    """Issue one request; return the status (normalising a raised error)."""
    from core.http import HttpError
    try:
        resp = client.request(method, url, headers=headers, follow_redirects=False,
                              raise_on_status=False)
        return getattr(resp, "status", None)
    except TypeError:
        try:
            resp = client.request(method, url, headers=headers, follow_redirects=False)
            return getattr(resp, "status", None)
        except HttpError as exc:
            return int(exc.status or 0)
    except HttpError as exc:
        return int(exc.status or 0)
    except Exception:
        return None


def run_jwt(
    config: JwtConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> JwtRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = JwtRun(out_dir=str(out), base_url=config.base_url, active=active)
    eid = endpoint_id(config.method, config.protected_path)

    token = config.token or (resolve_credential(config.token_env, env) if config.token_env else "")
    if not token:
        run.warnings.append("no token provided (config.token / token_env); nothing to test")
        _finalize(out, run, {})
        return run
    try:
        header, payload, _sig, _si = decode(token)
    except ValueError as exc:
        run.warnings.append(f"invalid JWT: {exc}")
        _finalize(out, run, {})
        return run

    wordlist = list(config.secrets) + [s for s in DEFAULT_SECRETS if s not in config.secrets]
    forgeries = generate_forgeries(token, changes=config.tamper, wordlist=wordlist)
    run.forgeries_tried = len(forgeries)

    if not active:
        run.findings = [{"attack": f.attack, "alg": f.detail.get("alg"), "planned": True}
                        for f in forgeries]
        run.findings.insert(0, {"token_alg": header.get("alg"),
                                "claims": sorted(payload.keys()), "planned": True})
        _finalize(out, run, {})
        return run

    if profile == "passive":
        raise ValueError("active jwt testing cannot use the passive profile")
    if not config.authorization.strip():
        raise ValueError(
            "active jwt testing refused: config.authorization is empty. Declare "
            "written authorization or omit --active for a dry-run plan.")

    # shared cookies/session auth ride alongside the tested token
    from core.session.attach import merged_auth_headers
    base_headers: Dict[str, str] = dict(merged_auth_headers(
        config.base_url, session=config.session,
        cookies=config.cookies, headers=config.headers) or {})

    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory([host] if host else [])
              if client_factory is not None else _client_for(config.base_url))

    def send(tok: str) -> Optional[int]:
        run.requests_sent += 1
        hdrs = dict(base_headers)
        hdrs[config.header_name] = f"{config.scheme} {tok}".strip() if config.scheme else tok
        return _status(client, config.method.upper(), config.url, hdrs)

    # (1) baseline + (2) negative control, up front
    baseline = send(token)
    control = send(corrupt_signature(token))
    if not is_accepted(baseline):
        run.warnings.append(
            f"valid token not accepted at {config.protected_path} (status {baseline}); "
            "cannot establish a baseline — check the endpoint / token")
        _finalize(out, run, {})
        return run
    if is_accepted(control):
        run.warnings.append(
            f"endpoint accepts a corrupted-signature token (status {control}) — it does "
            "not validate signatures; that is broken/absent auth, not a JWT forgery, so "
            "no forgery is confirmed here")
        _finalize(out, run, {})
        return run

    # (3) forgeries — record one confirmation per distinct attack class
    vulns: List[Dict[str, Any]] = []
    seen_class = set()
    n = 0
    for f in forgeries:
        if f.vuln_class in seen_class:
            continue
        forged_status = send(f.token)
        confirmed = forgery_confirmed(baseline, control, forged_status)
        if confirmed:
            seen_class.add(f.vuln_class)
            n += 1
            vid = f"JWT-{n:04d}"
            vulns.append(M.VulnRecord(
                id=vid, vuln_class=f.vuln_class, endpoint_id=eid,
                severity="high", owasp="API2",
                status=M.STATUS_CONFIRMED, proof_kind=M.PROOF_TOKEN_FORGED,
                evidence={
                    "attack": f.attack, **f.detail,
                    "baseline_status": baseline, "control_status": control,
                    "forged_status": forged_status,
                },
                source="jwt").to_row())
            run.findings.append({"id": vid, "attack": f.attack,
                                 "class": f.vuln_class, "proof": M.PROOF_TOKEN_FORGED,
                                 "forged_status": forged_status})

    accumulated: Dict[str, List[Dict[str, Any]]] = {}
    if vulns:
        accumulated[M.VulnRecord.KIND] = vulns
    accumulated.setdefault(M.EndpointRecord.KIND, []).append(
        M.EndpointRecord(method=config.method.upper(), path=config.protected_path,
                         origin=config.base_url, url=config.url,
                         source="jwt").to_row())
    _finalize(out, run, accumulated)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: JwtRun, accumulated) -> None:
    graph = build_graph(accumulated, [run.base_url])
    persist_records(out / "normalized", accumulated)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count = stats["node_count"]
    run.edge_count = stats["edge_count"]
    import json
    (out / "jwt-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["JwtRun", "run_jwt"]
