"""CLI backing ``/race`` (via ``libexec/raptor-race``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.racecond.config import RaceConfig, load_config
from core.racecond.runner import run_race


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-race",
        description="Business-logic / race-condition testing via concurrent replay.",
    )
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", required=True, help="race config JSON (base_url + tests)")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--token-env", default="")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _render(run) -> str:
    lines = [f"Race / business-logic test — {'ACTIVE' if run.active else 'dry-run'}",
             f"  target:  {run.base_url}"]
    if run.active:
        lines.append(f"  ran:     {run.tests_run}/{run.tests_planned}  "
                     f"({run.requests_sent} requests)")
        if run.violations:
            lines.append(f"  races: {len(run.violations)} finding(s)")
            for f in run.violations:
                tag = "" if f.get("confirmed") else "  (SUSPECTED — set success_signature)"
                lines.append(f"    ⚠ {f['id']}  {f['endpoint']}  "
                             f"{f['successes']} succeeded / limit {f['expected_max']}{tag}")
        else:
            lines.append("  no races confirmed")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = load_config(Path(args.config))
        if args.token_env:
            cfg.token_env = args.token_env
        run = run_race(cfg, out_dir=args.out_dir, active=args.active,
                       profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
