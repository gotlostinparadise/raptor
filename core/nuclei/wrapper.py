"""Nuclei integration — detection, command construction, result parsing.

Nuclei is an optional external tool. When present, RAPTOR runs it (sandboxed,
egress-allowlisted to the target) and ingests its JSONL output as **confirmed**
findings — nuclei matched a real template against the live target, which is a
tool verdict, not an LLM guess. When absent, the capability degrades cleanly and
the tech→CVE correlation still runs offline.

The JSONL parser is pure and unit-tested; the run itself is integration-only.
"""

from __future__ import annotations

import json
import shutil
from typing import Any, Dict, List, Optional

_SEVERITY = {"info", "low", "medium", "high", "critical"}


def available() -> bool:
    """True when the ``nuclei`` binary is on PATH."""
    return bool(shutil.which("nuclei"))


def build_command(target: str, output: str, *, tags: Optional[List[str]] = None,
                  templates: Optional[List[str]] = None,
                  rate_limit: int = 50, severity: Optional[List[str]] = None) -> List[str]:
    """Construct a nuclei command (list form — never a shell string)."""
    cmd = ["nuclei", "-target", target, "-jsonl", "-output", output,
           "-rate-limit", str(rate_limit), "-no-interactsh", "-disable-update-check"]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if templates:
        for t in templates:
            cmd += ["-t", t]
    if severity:
        cmd += ["-severity", ",".join(s for s in severity if s in _SEVERITY)]
    return cmd


def parse_results(jsonl_text: str) -> List[Dict[str, Any]]:
    """Parse nuclei JSONL output into normalised finding dicts."""
    out: List[Dict[str, Any]] = []
    for line in (jsonl_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info") or {}
        severity = (info.get("severity") or "info").lower()
        if severity not in _SEVERITY:
            severity = "info"
        cve_raw = (info.get("classification", {}) or {}).get("cve-id") or []
        if isinstance(cve_raw, str):   # nuclei sometimes emits a scalar
            cve_raw = [cve_raw]
        out.append({
            "template_id": row.get("template-id") or row.get("templateID") or "",
            "name": info.get("name", ""),
            "severity": severity,
            "matched_at": row.get("matched-at") or row.get("host") or "",
            "type": row.get("type", ""),
            "cve": [str(c).upper() for c in cve_raw],
            "tags": info.get("tags", []),
        })
    return out


def run_nuclei(target: str, output_path: str, *, proxy_hosts: List[str],
               tags: Optional[List[str]] = None, templates: Optional[List[str]] = None,
               timeout: int = 600) -> str:
    """Run nuclei sandboxed against ``target``; return the JSONL output text.

    Egress is constrained to ``proxy_hosts`` via the sandbox egress proxy — the
    same envelope every RAPTOR network tool uses. Raises if nuclei is absent or
    no egress host was resolved.
    """
    if not available():
        raise RuntimeError("nuclei not installed")
    if not proxy_hosts:
        raise RuntimeError("no egress host resolved for nuclei target")
    from pathlib import Path

    from core.sandbox.context import run_untrusted_networked
    out_dir = Path(output_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = build_command(target, output_path, tags=tags, templates=templates)
    # ``output=`` registers the run dir as the Landlock-writable surface (nuclei
    # writes its JSONL there) AND satisfies the helper's target/output guard.
    run_untrusted_networked(cmd, target=target, output=str(out_dir),
                            proxy_hosts=proxy_hosts, restrict_reads=False,
                            timeout=timeout)
    p = Path(output_path)
    return p.read_text(encoding="utf-8") if p.exists() else ""


__all__ = ["available", "build_command", "parse_results", "run_nuclei"]
