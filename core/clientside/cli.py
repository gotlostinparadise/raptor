"""CLI backing ``/clientside`` (via ``libexec/raptor-clientside``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.clientside.config import ClientSideConfig, from_dict, load_config
from core.clientside.runner import run_clientside


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-clientside",
        description="Client-side/config testing — CORS, CSP, clickjacking, cookies, open redirect.",
    )
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="clientside config JSON")
    p.add_argument("--url", default="", help="base URL (shortcut for config)")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> ClientSideConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        cfg = from_dict({"base_url": args.url, "authorization": args.authorization})
    else:
        raise ValueError("provide --config or --url")
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    return cfg


def _render(run) -> str:
    lines = [f"Client-side/config test — {'ACTIVE' if run.active else 'dry-run'}",
             f"  target:  {run.base_url}"]
    if run.active:
        lines.append(f"  sent:    {run.requests_sent} request(s)")
        if run.findings:
            lines.append(f"  findings: {len(run.findings)}")
            for f in run.findings:
                lines.append(f"    ⚠ {f.get('id','')}  {f['class']}  ({f.get('severity','')})")
        else:
            lines.append("  no misconfigurations found")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_clientside(cfg, out_dir=args.out_dir, active=args.active,
                             profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
