"""CLI backing ``/nuclei`` (via ``libexec/raptor-nuclei``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.nuclei.config import NucleiConfig, from_dict, load_config
from core.nuclei.runner import run_nuclei_scan


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-nuclei",
        description="Nuclei template scan + tech→CVE correlation over the recon graph.",
    )
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="nuclei config JSON")
    p.add_argument("--target", default="", help="URL for nuclei to scan")
    p.add_argument("--recon-graph", default="", help="recon.json / web.json for tech→CVE")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--tags", default="", help="comma-separated nuclei tags")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> NucleiConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    else:
        cfg = from_dict({"target": args.target, "recon_graph": args.recon_graph,
                         "authorization": args.authorization,
                         "tags": [t.strip() for t in args.tags.split(",") if t.strip()]})
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    return cfg


def _render(run) -> str:
    lines = [f"Nuclei / tech→CVE — {'ACTIVE' if run.active else 'dry-run'}",
             f"  target:  {run.target or '(tech→CVE only)'}",
             f"  nuclei:  {'available' if run.nuclei_available else 'not installed'}"]
    if run.suspected:
        lines.append(f"  suspected (tech→CVE, indicator only): {len(run.suspected)}")
        for s in run.suspected:
            lines.append(f"    · {s['id']}  {s['cve']}  {s['tech']}  ({s['severity']})")
    if run.confirmed:
        lines.append(f"  confirmed (nuclei): {len(run.confirmed)}")
        for c in run.confirmed:
            lines.append(f"    ⚠ {c['id']}  {c['template']}  ({c['severity']})")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_nuclei_scan(cfg, out_dir=args.out_dir, active=args.active,
                              profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
