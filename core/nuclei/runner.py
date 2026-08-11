"""The `/nuclei` engine — tech→CVE correlation (offline) + nuclei run (active).

Two high-signal, cheap capabilities:

  * **tech → CVE** — cross-reference the recon graph's ``tech`` fingerprints
    against a curated CVE table. Offline, always available; results are
    **suspected** (a version match is an indicator, not a proof).
  * **nuclei** — when the binary is installed and testing is authorized, run
    nuclei (sandboxed, egress-allowlisted) and ingest its matches as
    **confirmed** findings + verified outcomes.

Safe by default: the nuclei run needs ``active`` + a declared authorization; the
tech→CVE correlation runs in dry-run too (it sends nothing).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from core.nuclei import techcve, wrapper
from core.nuclei.config import NucleiConfig
from core.webgraph import model as M
from core.webgraph.builder import build_graph
from core.webgraph.orchestrator import persist_records, serialize_graph
from core.webgraph.scope import canonical_origin
from core.webgraph.verified import record_confirmed


@dataclass
class NucleiRun:
    out_dir: str
    target: str
    active: bool
    nuclei_available: bool = False
    suspected: List[Dict[str, Any]] = field(default_factory=list)
    confirmed: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "out_dir": self.out_dir, "target": self.target, "active": self.active,
            "nuclei_available": self.nuclei_available,
            "suspected_count": len(self.suspected), "confirmed_count": len(self.confirmed),
            "suspected": self.suspected, "confirmed": self.confirmed,
            "warnings": self.warnings, "node_count": self.node_count,
            "edge_count": self.edge_count,
        }


def _load_tech(recon_graph: str, warnings: List[str]) -> List[str]:
    if not recon_graph:
        return []
    try:
        data = json.loads(Path(recon_graph).read_text(encoding="utf-8"))
    except Exception as exc:
        warnings.append(f"could not read recon graph: {type(exc).__name__}")
        return []
    return techcve.tech_from_graph(data)


def run_nuclei_scan(
    config: NucleiConfig,
    *,
    out_dir,
    active: bool = False,
    profile: str = "safe",
    producing_model: str = "",
    run_nuclei_fn=None,     # injection seam for tests
) -> NucleiRun:
    out = Path(out_dir)
    (out / "normalized").mkdir(parents=True, exist_ok=True)
    run = NucleiRun(out_dir=str(out), target=config.target, active=active,
                    nuclei_available=wrapper.available())

    if active:
        if profile == "passive":
            raise ValueError("active nuclei scan cannot use the passive profile")
        if not config.authorization.strip():
            raise ValueError("active scan refused: config.authorization is empty")

    vulns: List[Dict[str, Any]] = []
    n = [0]

    def add_vuln(vuln_class, severity, proof_kind, status, evidence):
        n[0] += 1
        vid = f"NUC-{n[0]:04d}"
        vulns.append(M.VulnRecord(id=vid, vuln_class=vuln_class, endpoint_id="",
                                  severity=severity, owasp="API8", status=status,
                                  proof_kind=proof_kind, evidence=evidence,
                                  source="nuclei").to_row())
        return vid

    # --- tech → CVE (offline, always) ---
    for adv in techcve.correlate(_load_tech(config.recon_graph, run.warnings)):
        vid = add_vuln("known_cve", adv["severity"], M.PROOF_NONE,
                       M.STATUS_SUSPECTED, adv)
        run.suspected.append({"id": vid, "cve": adv["cve"], "tech": adv["tech"],
                              "severity": adv["severity"]})

    # --- nuclei (active only) ---
    if active and config.target:
        if not run.nuclei_available:
            run.warnings.append("nuclei not installed; skipping template scan "
                                "(install nuclei to enable). tech→CVE still ran.")
        else:
            # nuclei needs an absolute URL; a bare host (no scheme) leaves
            # urlsplit().hostname None and the egress host unresolved.
            target = config.target
            if "://" not in target:
                target = "https://" + target
            host = urlsplit(target).hostname or ""
            try:
                fn = run_nuclei_fn or _default_run
                jsonl = fn(target, str(out / "nuclei.jsonl"),
                           proxy_hosts=[host] if host else [], tags=config.tags)
                for r in wrapper.parse_results(jsonl):
                    vid = add_vuln(f"nuclei:{r['template_id']}", r["severity"],
                                   M.PROOF_REFLECTED_MARKER, M.STATUS_CONFIRMED,
                                   {"template_id": r["template_id"], "name": r["name"],
                                    "matched_at": r["matched_at"], "cve": r["cve"]})
                    run.confirmed.append({"id": vid, "template": r["template_id"],
                                          "severity": r["severity"]})
            except Exception as exc:
                run.warnings.append(f"nuclei run failed: {type(exc).__name__}: {exc}")

    recs = {M.VulnRecord.KIND: vulns} if vulns else {}
    _finalize(out, run, recs)
    confirmed_rows = [v for v in vulns if v.get("status") == M.STATUS_CONFIRMED]
    if confirmed_rows:
        record_confirmed(confirmed_rows, project_dir=out, producing_model=producing_model)
    return run


def _default_run(target, output_path, *, proxy_hosts, tags=None):
    return wrapper.run_nuclei(target, output_path, proxy_hosts=proxy_hosts, tags=tags)


def _finalize(out: Path, run: NucleiRun, recs) -> None:
    origin = canonical_origin(run.target) if run.target else ""
    graph = build_graph(recs, [origin] if origin else [])
    persist_records(out / "normalized", recs)
    serialize_graph(out / "graph", graph)
    stats = graph.stats()
    run.node_count, run.edge_count = stats["node_count"], stats["edge_count"]
    (out / "nuclei-findings.json").write_text(
        json.dumps(run.to_dict(), indent=2), encoding="utf-8")


__all__ = ["NucleiRun", "run_nuclei_scan"]
