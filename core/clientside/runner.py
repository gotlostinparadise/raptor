"""The `/clientside` engine — CORS/CSP/clickjacking/cookies/open-redirect.

Fetches the target, sends a CORS probe with an attacker origin, and probes
redirect parameters with an external marker, then runs the pure analyzers on the
real responses. Each confirmed misconfiguration becomes a ``vuln`` node proven by
the response evidence (``PROOF_REFLECTED_MARKER``).

Safe by default: ``active=False`` sends nothing. The probes are benign (a header,
a redirect parameter) but still require ``--active`` + a declared authorization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from core.clientside import analyzers
from core.clientside.config import ClientSideConfig
from core.http import HttpError, Response
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import canonical_origin, endpoint_id
from core.webgraph.verified import record_confirmed

MARKER_HOST = "evil-rap-marker.example"

_OWASP = {
    "cors_origin_reflection": "API8", "cors_wildcard_with_credentials": "API8",
    "cors_null_origin": "API8", "csp_missing": "API8", "csp_unsafe_inline": "API8",
    "csp_unsafe_eval": "API8", "csp_wildcard_script_source": "API8",
    "csp_no_object_src": "API8", "clickjacking": "API8", "cookie_flags": "API8",
    "open_redirect": "API8",
}

# Only findings where we sent a marker/probe and observed a reflected or
# behavioural response are a tool-produced PROOF (reflected_marker): the server
# echoed our attacker Origin, or followed our redirect to the attacker host.
# Everything else here — missing/weak CSP, framable page, insecure cookie flags,
# CORS wildcard/null — is a header OBSERVATION read straight off the wire: a real
# weakness, but not an exploit proof, so it stays `suspected` and out of the
# verified pool (see core/webgraph/verified.py: record_confirmed skips it).
_REFLECTION_PROVEN = frozenset({"cors_origin_reflection", "open_redirect"})


@dataclass
class ClientSideRun:
    out_dir: str
    base_url: str
    active: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "finding_count": len(self.findings), "findings": self.findings,
            "warnings": self.warnings, "requests_sent": self.requests_sent,
            "node_count": self.node_count, "edge_count": self.edge_count,
        }


def _fetch(client, method: str, url: str, *, headers=None, follow_redirects=True) -> Response:
    """Fetch returning a Response for ANY status (headers preserved).

    Uses ``raise_on_status=False`` on clients that support it (Urllib/Egress) so a
    4xx/3xx still yields its headers; falls back for a plain-Protocol client
    (tests), synthesising a Response from a raised HttpError.
    """
    try:
        return client.request(method, url, headers=headers,
                              follow_redirects=follow_redirects, raise_on_status=False)
    except TypeError:
        try:
            return client.request(method, url, headers=headers,
                                  follow_redirects=follow_redirects)
        except HttpError as exc:
            return Response(status=int(exc.status or 0), headers={}, body=b"", url=url)


def _with_query(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    q.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def run_clientside(
    config: ClientSideConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> ClientSideRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = ClientSideRun(out_dir=str(out), base_url=config.base_url, active=active)

    if active:
        if profile == "passive":
            raise ValueError("active testing cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError("active testing refused: config.authorization is empty")

    if not active:
        run.findings = [{"planned": True,
                         "checks": ["cors", "csp", "clickjacking", "cookies", "open_redirect"]}]
        _finalize(out, run, {})
        return run

    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory or (lambda h: _client_for(config.base_url)))(
        [host] if host else [])

    # Shared authenticated session: attach the logged-in identity's headers +
    # cookies (or explicit config cookies/headers) to every probe, so client-side
    # misconfig checks run against the post-login surface too.
    from core.session.attach import merged_auth_headers

    def auth_for(url: str) -> Dict[str, str]:
        return merged_auth_headers(url, session=config.session,
                                   cookies=config.cookies, headers=config.headers)

    vulns: List[Dict[str, Any]] = []
    n = [0]

    def record(vuln_type, endpoint, finding):
        n[0] += 1
        proven = vuln_type in _REFLECTION_PROVEN
        status = M.STATUS_CONFIRMED if proven else M.STATUS_SUSPECTED
        proof = M.PROOF_REFLECTED_MARKER if proven else M.PROOF_NONE
        vulns.append(M.VulnRecord(
            id=f"CS-{n[0]:04d}", vuln_class=vuln_type, endpoint_id=endpoint,
            severity=finding.get("severity", "low"),
            owasp=_OWASP.get(vuln_type, "API8"), status=status,
            proof_kind=proof, evidence=finding,
            source="clientside").to_row())
        run.findings.append({"id": f"CS-{n[0]:04d}", "class": vuln_type,
                             "severity": finding.get("severity", "low"),
                             "endpoint": endpoint})

    base_eid = endpoint_id("GET", "/")
    # --- base page: CSP / clickjacking / cookies ---
    try:
        run.requests_sent += 1
        resp = _fetch(client, "GET", config.base_url, headers=auth_for(config.base_url) or None)
        headers = dict(resp.headers)
        csp = headers.get("content-security-policy")
        directives = analyzers.parse_csp(csp or "")
        for f in analyzers.csp_analysis(csp):
            record(f["type"], base_eid, f)
        cj = analyzers.clickjacking(headers, directives)
        if cj:
            record("clickjacking", base_eid, cj)
        sc = headers.get("set-cookie")
        for f in analyzers.cookie_flags([sc] if sc else []):
            record("cookie_flags", base_eid, f)
    except Exception as exc:
        run.warnings.append(f"base fetch failed: {type(exc).__name__}: {exc}")

    # --- CORS probe with an attacker origin ---
    try:
        run.requests_sent += 1
        origin = f"https://{MARKER_HOST}"
        resp = _fetch(client, "GET", config.base_url, headers={**auth_for(config.base_url), "Origin": origin})
        for f in analyzers.cors_analysis(origin, dict(resp.headers)):
            record(f["type"], base_eid, f)
    except Exception as exc:
        run.warnings.append(f"CORS probe failed: {type(exc).__name__}: {exc}")

    # --- open redirect probes ---
    for path in config.paths:
        for param in config.redirect_params:
            url = _with_query(f"{config.base_url}{path}", param, f"//{MARKER_HOST}/")
            try:
                run.requests_sent += 1
                resp = _fetch(client, "GET", url, headers=auth_for(url) or None,
                              follow_redirects=False)
                loc = dict(resp.headers).get("location", "")
                f = analyzers.open_redirect(loc, resp.url, MARKER_HOST)
                if f:
                    f["param"] = param
                    record("open_redirect", endpoint_id("GET", path), f)
                    break  # one confirmed redirect param per path is enough
            except Exception as exc:
                run.warnings.append(f"redirect probe {param} failed: {type(exc).__name__}")

    recs = {M.VulnRecord.KIND: vulns} if vulns else {}
    _finalize(out, run, recs)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: ClientSideRun, recs) -> None:
    origin = canonical_origin(run.base_url)
    graph = build_graph(recs, [origin] if origin else [])
    persist_records(out / "normalized", recs)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count, run.edge_count = stats["node_count"], stats["edge_count"]
    (out / "clientside-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["ClientSideRun", "run_clientside", "MARKER_HOST"]
