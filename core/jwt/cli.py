"""CLI backing ``/jwt`` (via ``libexec/raptor-jwt``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.jwt.config import JwtConfig, from_dict, load_config
from core.jwt.runner import run_jwt


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-jwt",
        description="JWT forgery testing — alg:none + weak-secret, forged-token-accepted oracle.")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="jwt config JSON")
    p.add_argument("--url", default="", help="base URL (shortcut for a minimal config)")
    p.add_argument("--protected-path", default="/", help="endpoint requiring a valid token")
    p.add_argument("--method", default="GET")
    p.add_argument("--token", default="", help="a known-valid JWT to analyse + forge from")
    p.add_argument("--token-env", default="", help="env var holding the valid JWT")
    p.add_argument("--tamper", default="", help="JSON of claim escalations, e.g. '{\"role\":\"admin\"}'")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> JwtConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        cfg = from_dict({"base_url": args.url})
    else:
        raise ValueError("provide --config or --url")
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    if args.protected_path != "/" or not cfg.protected_path:
        cfg.protected_path = args.protected_path
    if args.method:
        cfg.method = args.method
    if args.token:
        cfg.token = args.token
    if args.token_env:
        cfg.token_env = args.token_env
    if args.tamper:
        try:
            cfg.tamper = dict(json.loads(args.tamper))
        except ValueError as exc:
            raise ValueError(f"--tamper must be a JSON object: {exc}") from exc
    return cfg


def _render(run) -> str:
    lines = [f"JWT test — {'ACTIVE' if run.active else 'dry-run (no requests sent)'}",
             f"  target:     {run.base_url}",
             f"  forgeries:  {run.forgeries_tried} candidate(s)"]
    if run.active:
        lines.append(f"  sent:       {run.requests_sent} request(s)")
        confirmed = [f for f in run.findings if f.get("proof")]
        if confirmed:
            lines.append(f"  CONFIRMED:  {len(confirmed)} forgery(ies)")
            for f in confirmed:
                lines.append(f"    ⚠ {f.get('id','')}  {f['class']}  "
                             f"(forged accepted: {f.get('forged_status')})")
        else:
            lines.append("  no forgery confirmed")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:      {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_jwt(cfg, out_dir=args.out_dir, active=args.active,
                      profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
