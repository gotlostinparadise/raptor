"""The `/discover` engine — mine JS for endpoints+secrets, probe exposed files.

Fetches the target, harvests its JavaScript (linked + inline), extracts endpoints
and (redacted) secrets, probes a curated list of sensitive paths with content
signatures, and recovers source maps. Discovered endpoints feed the graph;
secrets, exposed files, and source-map leaks become proven findings.

Safe by default: ``active=False`` sends nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urljoin, urlsplit

from core.discovery import extractors, probes
from core.discovery.config import DiscoveryConfig
from core.http import HttpError, Response
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import canonical_origin, endpoint_id, split_url
from core.webgraph.verified import record_confirmed


@dataclass
class DiscoveryRun:
    out_dir: str
    base_url: str
    active: bool
    endpoints_found: int = 0
    secrets_found: int = 0
    exposed_files: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requests_sent: int = 0
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "base_url": self.base_url, "active": self.active,
            "endpoints_found": self.endpoints_found, "secrets_found": self.secrets_found,
            "exposed_files": self.exposed_files, "finding_count": len(self.findings),
            "findings": self.findings, "warnings": self.warnings,
            "requests_sent": self.requests_sent, "node_count": self.node_count,
            "edge_count": self.edge_count,
        }


def _fetch(client, url: str, headers=None) -> Response:
    try:
        return client.request("GET", url, headers=headers, raise_on_status=False,
                              follow_redirects=True)
    except TypeError:
        try:
            return client.request("GET", url, headers=headers, follow_redirects=True)
        except HttpError as exc:
            return Response(status=int(exc.status or 0), headers={}, body=b"", url=url)


def _client_for(base_url: str) -> Any:
    from core.webhttp import pentest_client
    return pentest_client(base_url)


def run_discovery(
    config: DiscoveryConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    client_factory: Optional[Callable[[List[str]], Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> DiscoveryRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = DiscoveryRun(out_dir=str(out), base_url=config.base_url, active=active)
    origin = canonical_origin(config.base_url)

    if active:
        if profile == "passive":
            raise ValueError("active discovery cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError("active discovery refused: config.authorization is empty")

    if not active:
        run.findings = [{"planned": True,
                         "checks": ["js_endpoints", "js_secrets", "exposed_files", "source_maps"]}]
        _finalize(out, run, {})
        return run

    host = urlsplit(config.base_url).hostname or ""
    client = (client_factory or (lambda h: _client_for(config.base_url)))(
        [host] if host else [])

    # Shared authenticated session: one static header snapshot (auth headers +
    # Cookie for this origin) attached to every discovery fetch, so JS mining and
    # exposed-file probes run authenticated when a session was threaded in.
    from core.session.attach import merged_auth_headers
    auth = merged_auth_headers(config.base_url, session=config.session,
                               cookies=config.cookies, headers=config.headers) or None

    recs: Dict[str, List[Dict[str, Any]]] = {}
    vulns: List[Dict[str, Any]] = []
    n = [0]

    def add_rec(rec):
        recs.setdefault(rec.KIND, []).append(rec.to_row())

    def add_vuln(vuln_class, endpoint, severity, owasp, evidence):
        n[0] += 1
        vid = f"DISC-{n[0]:04d}"
        vulns.append(M.VulnRecord(id=vid, vuln_class=vuln_class, endpoint_id=endpoint,
                                  severity=severity, owasp=owasp, status=M.STATUS_CONFIRMED,
                                  proof_kind=M.PROOF_REFLECTED_MARKER, evidence=evidence,
                                  source="discovery").to_row())
        run.findings.append({"id": vid, "class": vuln_class, "severity": severity})

    def harvest(text: str, whence: str):
        for ep in extractors.extract_endpoints(text, same_origin=origin):
            ep_origin = split_url(ep)[0] if "://" in ep else origin
            # Split off the query and store only the PATH — a query value can
            # carry a secret (?token=eyJ…), which must not land in the graph.
            # Query keys become (redacted-value) parameter nodes instead.
            parts = urlsplit(ep)
            path = parts.path or ep.split("?", 1)[0] or "/"
            eid = endpoint_id("GET", path)
            add_rec(M.EndpointRecord(method="GET", path=path, origin=ep_origin or origin,
                                     source="discovery"))
            for pname, _pval in parse_qsl(parts.query, keep_blank_values=True):
                if pname:
                    add_rec(M.ParamRecord(endpoint_id=eid, name=pname,
                                          location=M.LOC_QUERY, source="discovery"))
            run.endpoints_found += 1
        for sec in extractors.extract_secrets(text):
            run.secrets_found += 1
            add_vuln("exposed_secret", endpoint_id("GET", "/"), "high", "API8",
                     {**sec, "location": whence})

    # --- base page + its JavaScript ---
    try:
        run.requests_sent += 1
        base = _fetch(client, config.base_url, auth)
        html = base.body.decode("utf-8", errors="replace") if base.body else ""
        harvest(html, config.base_url)
        for src in extractors.script_srcs(html):
            js_url = urljoin(config.base_url, src)
            if origin and canonical_origin(js_url) and canonical_origin(js_url) != origin:
                continue
            run.requests_sent += 1
            js = _fetch(client, js_url, auth)
            js_text = js.body.decode("utf-8", errors="replace") if js.body else ""
            harvest(js_text, js_url)
            smap = extractors.source_map_url(js_text)
            if smap:
                smap_url = urljoin(js_url, smap)
                smap_origin = canonical_origin(smap_url)
                # Guard the map fetch like the script fetch: a hostile in-scope
                # JS could point sourceMappingURL at an internal host (SSRF).
                if origin and smap_origin and smap_origin != origin:
                    run.warnings.append(f"skipped off-origin source map: {smap}")
                    continue
                run.requests_sent += 1
                mp = _fetch(client, smap_url, auth)
                sources = probes.recover_sources(mp.body or b"")
                if sources:
                    add_vuln("source_map_exposed", endpoint_id("GET", "/"), "medium",
                             "API8", {"js": js_url, "source_count": len(sources),
                                      "sample": sources[:15]})
    except Exception as exc:
        run.warnings.append(f"base/JS fetch failed: {type(exc).__name__}: {exc}")

    # --- exposed-file probes ---
    if config.probe_exposed:
        for path, sig in probes.EXPOSED_PATHS:
            url = urljoin(config.base_url.rstrip("/") + "/", path)
            try:
                run.requests_sent += 1
                f = probes.check_exposed(path, sig, _fetch(client, url, auth))
                if f:
                    run.exposed_files += 1
                    add_vuln("exposed_file", endpoint_id("GET", "/" + path), "high",
                             "API8", f)
            except Exception as exc:
                run.warnings.append(f"probe {path} failed: {type(exc).__name__}")

    if vulns:
        recs[M.VulnRecord.KIND] = vulns
    _finalize(out, run, recs)
    if vulns:
        record_confirmed(vulns, project_dir=out, producing_model=producing_model)
    return run


def _finalize(out: Path, run: DiscoveryRun, recs) -> None:
    origin = canonical_origin(run.base_url)
    graph = build_graph(recs, [origin] if origin else [])
    persist_records(out / "normalized", recs)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count, run.edge_count = stats["node_count"], stats["edge_count"]
    (out / "discovery-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["DiscoveryRun", "run_discovery"]
