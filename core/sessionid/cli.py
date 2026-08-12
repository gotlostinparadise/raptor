"""CLI backing ``/sessionid`` (via ``libexec/raptor-sessionid``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.sessionid.config import SessionIdConfig, from_dict, load_config
from core.sessionid.runner import run_sessionid


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-sessionid",
        description="Weak/predictable session-id analysis (reuse + sequence, entropy).")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="sessionid config JSON")
    p.add_argument("--url", default="", help="base URL (shortcut for a minimal config)")
    p.add_argument("--collect-url", default="/", help="endpoint issuing a fresh token")
    p.add_argument("--method", default="GET")
    p.add_argument("--count", type=int, default=6, help="tokens to sample")
    p.add_argument("--cookie-name", default="", help="Set-Cookie name holding the token")
    p.add_argument("--token-path", default="", help="dotted JSON path to the token")
    p.add_argument("--token", action="append", default=[], help="pre-observed token (repeatable)")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> SessionIdConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        cfg = from_dict({"base_url": args.url})
    else:
        raise ValueError("provide --config or --url")
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    if args.collect_url != "/":
        cfg.collect_url = args.collect_url
    if args.method:
        cfg.method = args.method
    if args.count:
        cfg.count = args.count
    if args.cookie_name:
        cfg.cookie_name = args.cookie_name
    if args.token_path:
        cfg.token_path = args.token_path
    if args.token:
        cfg.tokens = list(args.token)
    return cfg


def _render(run) -> str:
    lines = [f"Session-id analysis — {'ACTIVE' if run.active else 'offline'}",
             f"  target:    {run.base_url}",
             f"  samples:   {run.tokens_collected} token(s)"]
    confirmed = [f for f in run.findings if f.get("proof")]
    suspected = [f for f in run.findings if f.get("suspected")]
    if confirmed:
        lines.append(f"  CONFIRMED: {len(confirmed)}")
        for f in confirmed:
            lines.append(f"    ⚠ {f['id']}  {f['class']}  ({f['proof']})")
    if suspected:
        for f in suspected:
            lines.append(f"  suspected: {f['class']} (low entropy — follow up)")
    if not confirmed and not suspected:
        lines.append("  no weakness detected")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:     {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_sessionid(cfg, out_dir=args.out_dir, active=args.active,
                            profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
