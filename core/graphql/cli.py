"""CLI backing ``/graphql`` (via ``libexec/raptor-graphql``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.graphql.config import GraphQLConfig, from_dict, load_config
from core.graphql.runner import run_graphql


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-graphql",
        description="GraphQL security testing — introspection + alias/batching DoS.",
    )
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="graphql config JSON")
    p.add_argument("--url", default="", help="GraphQL endpoint URL (shortcut for config)")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--resource-tests", action="store_true",
                   help="enable the alias/batching DoS check (resource-class)")
    p.add_argument("--token-env", default="")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> GraphQLConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        from urllib.parse import urlsplit
        parts = urlsplit(args.url)
        base = f"{parts.scheme}://{parts.netloc}"
        cfg = from_dict({"base_url": base, "path": parts.path or "/graphql",
                         "authorization": args.authorization})
    else:
        raise ValueError("provide --config or --url")
    if args.resource_tests:
        cfg.resource_tests = True
    if args.token_env:
        cfg.token_env = args.token_env
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    return cfg


def _render(run) -> str:
    lines = [f"GraphQL test — {'ACTIVE' if run.active else 'dry-run'}",
             f"  endpoint: {run.url}"]
    if run.active:
        lines.append(f"  introspection: {'OPEN' if run.introspection_open else 'closed'}"
                     f"  ({run.operation_count} ops)")
        conf = [f for f in run.findings if f.get("proof")]
        if conf:
            lines.append(f"  findings: {len(conf)}")
            for f in conf:
                lines.append(f"    ⚠ {f['id']}  {f['class']}")
        else:
            lines.append("  no findings confirmed")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_graphql(cfg, out_dir=args.out_dir, active=args.active,
                          profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
