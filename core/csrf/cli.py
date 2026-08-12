"""CLI backing ``/csrf`` (via ``libexec/raptor-csrf``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.csrf.config import CsrfConfig, from_dict, load_config
from core.csrf.runner import run_csrf


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-csrf",
        description="Anti-CSRF-token-absence testing — state change without the token.")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="csrf config JSON")
    p.add_argument("--url", default="", help="base URL (shortcut for a minimal config)")
    p.add_argument("--path", default="/", help="state-changing endpoint")
    p.add_argument("--method", default="POST")
    p.add_argument("--body", default="", help="a WORKING request body incl. the token field")
    p.add_argument("--json-body", action="store_true")
    p.add_argument("--token-field", default="user_token")
    p.add_argument("--success-signature", default="", help="marker of a successful state change")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> CsrfConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        cfg = from_dict({"base_url": args.url})
    else:
        raise ValueError("provide --config or --url")
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    if args.path != "/":
        cfg.path = args.path
    if args.method:
        cfg.method = args.method
    if args.body:
        cfg.body = args.body
    if args.json_body:
        cfg.content_type = "json"
    if args.token_field != "user_token":
        cfg.token_field = args.token_field
    if args.success_signature:
        cfg.success_signature = args.success_signature
    return cfg


def _render(run) -> str:
    lines = [f"CSRF test — {'ACTIVE' if run.active else 'dry-run (no requests)'}",
             f"  target:  {run.base_url}"]
    if run.active:
        if any(f.get("proof") for f in run.findings):
            lines.append("  CONFIRMED: state change succeeded with the anti-CSRF token removed")
        elif run.baseline_ok:
            lines.append("  token enforced (token-less request rejected)")
        else:
            lines.append("  inconclusive (baseline did not succeed)")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_csrf(cfg, out_dir=args.out_dir, active=args.active,
                       profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
