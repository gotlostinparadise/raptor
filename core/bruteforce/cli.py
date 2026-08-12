"""CLI backing ``/bruteforce`` (via ``libexec/raptor-bruteforce``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.bruteforce.config import BruteforceConfig, from_dict, load_config
from core.bruteforce.runner import run_bruteforce


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-bruteforce",
        description="Brute-force / rate-limit testing — no-lockout counting oracle.")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="bruteforce config JSON")
    p.add_argument("--url", default="", help="base URL (shortcut for a minimal config)")
    p.add_argument("--login-url", default="/login")
    p.add_argument("--method", default="POST")
    p.add_argument("--attempts", type=int, default=12)
    p.add_argument("--body", default="", help="a FAILING credential payload (wrong password)")
    p.add_argument("--json-body", action="store_true", help="send --body as application/json")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> BruteforceConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        cfg = from_dict({"base_url": args.url})
    else:
        raise ValueError("provide --config or --url")
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    if args.login_url != "/login":
        cfg.login_url = args.login_url
    if args.method:
        cfg.method = args.method
    if args.attempts:
        cfg.attempts = args.attempts
    if args.body:
        cfg.body = args.body
    if args.json_body:
        cfg.content_type = "json"
    return cfg


def _render(run) -> str:
    lines = [f"Brute-force test — {'ACTIVE' if run.active else 'dry-run (no requests)'}",
             f"  target:   {run.base_url}"]
    if run.active:
        lines.append(f"  attempts: {run.attempts_made} failed login(s)")
        confirmed = [f for f in run.findings if f.get("proof")]
        if confirmed:
            lines.append(f"  CONFIRMED: no brute-force protection "
                         f"({confirmed[0]['attempts']} attempts, no lockout)")
        elif run.lockout_at is not None:
            lines.append(f"  protection present: lockout at attempt {run.lockout_at}")
        else:
            lines.append("  inconclusive")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:    {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_bruteforce(cfg, out_dir=args.out_dir, active=args.active,
                             profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
