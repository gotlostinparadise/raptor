"""CLI backing ``/discover`` (via ``libexec/raptor-discover``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.discovery.config import DiscoveryConfig, from_dict, load_config
from core.discovery.runner import run_discovery


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-discover",
        description="App-layer content discovery — JS endpoints/secrets, exposed files, source maps.",
    )
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="discovery config JSON")
    p.add_argument("--url", default="", help="base URL (shortcut for config)")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--no-exposed", action="store_true", help="skip exposed-file probes")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> DiscoveryConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        cfg = from_dict({"base_url": args.url, "authorization": args.authorization})
    else:
        raise ValueError("provide --config or --url")
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    if args.no_exposed:
        cfg.probe_exposed = False
    return cfg


def _render(run) -> str:
    lines = [f"Content discovery — {'ACTIVE' if run.active else 'dry-run'}",
             f"  target:  {run.base_url}"]
    if run.active:
        lines.append(f"  sent:    {run.requests_sent} request(s)")
        lines.append(f"  found:   {run.endpoints_found} endpoints, "
                     f"{run.secrets_found} secret(s), {run.exposed_files} exposed file(s)")
        for f in run.findings:
            lines.append(f"    ⚠ {f.get('id','')}  {f['class']}  ({f.get('severity','')})")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_discovery(cfg, out_dir=args.out_dir, active=args.active,
                            profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
