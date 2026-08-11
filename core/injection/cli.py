"""CLI backing ``/inject`` (via ``libexec/raptor-inject``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from core.injection.config import (
    ALL_CLASSES, InjectionConfig, from_dict, load_config, points_from_webgraph,
)
from core.injection.runner import run_injection


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-inject",
        description="Deep injection testing with real oracles (SQLi/SSTI/cmdi/SSRF/XXE).",
    )
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="injection config JSON (base_url + points)")
    p.add_argument("--from-webgraph", help="a /webgraph run dir to harvest points from")
    p.add_argument("--base-url", default="", help="base URL (with --from-webgraph)")
    p.add_argument("--classes", default="", help="comma-separated subset of classes")
    p.add_argument("--active", action="store_true", help="send payloads (needs authorization)")
    p.add_argument("--authorization", default="", help="attestation (with --from-webgraph)")
    p.add_argument("--profile", default="safe")
    p.add_argument("--oast-domain", default="", help="OAST callback domain (enables blind classes)")
    p.add_argument("--oast-poll-url", default="", help="OAST collector poll URL")
    p.add_argument("--token-env", default="", help="env var holding a bearer token")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _oast_from(args):
    if not args.oast_domain:
        return None
    from core.oast.backend import HttpPollBackend, InMemoryBackend
    from core.oast.client import OastClient
    if args.oast_poll_url:
        from core.http.urllib_backend import UrllibClient
        backend = HttpPollBackend(args.oast_domain, args.oast_poll_url, UrllibClient())
    else:
        backend = InMemoryBackend(args.oast_domain)
    return OastClient(backend)


def _load(args) -> InjectionConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.from_webgraph:
        pts = points_from_webgraph(Path(args.from_webgraph) / "normalized")
        cfg = from_dict({
            "base_url": args.base_url, "authorization": args.authorization,
            "points": [{"method": p.method, "path": p.path, "param": p.param,
                        "location": p.location} for p in pts],
        })
    else:
        raise ValueError("provide --config or --from-webgraph (+ --base-url)")
    if args.classes:
        cfg.classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    if args.token_env:
        cfg.token_env = args.token_env
    return cfg


def _render(run) -> str:
    lines = [f"Injection test — {'ACTIVE' if run.active else 'dry-run (no payloads sent)'}",
             f"  target:  {run.base_url}",
             f"  points:  {run.points}   classes: {', '.join(run.classes)}"]
    if run.active:
        lines.append(f"  sent:    {run.requests_sent} request(s)")
        confirmed = [f for f in run.findings if f.get("proof")]
        if confirmed:
            lines.append(f"  CONFIRMED: {len(confirmed)} finding(s)")
            for f in confirmed:
                lines.append(f"    ⚠ {f.get('id','')}  {f['class']}  "
                             f"[{f.get('point','')}]  ({f['proof']})")
        else:
            lines.append("  no injection confirmed")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_injection(cfg, out_dir=args.out_dir, active=args.active,
                            profile=args.profile, producing_model=args.model,
                            oast=_oast_from(args))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
