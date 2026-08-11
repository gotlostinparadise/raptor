"""CLI backing ``/webauthz`` (via ``libexec/raptor-webauthz``).

Two modes:

  * ``--init`` — seed an ``authz-config.json`` template from an API inventory /
    authz matrix (offline). The operator fills in real object ids, credential
    env-var names, and the authorization attestation.
  * default — load a config and run the access-control tests. Safe by default:
    it plans + builds the surface graph and sends **nothing** unless ``--active``
    is passed *and* the config declares ``authorization``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-webauthz",
        description="Access-control (IDOR/BOLA/BFLA) testing via multi-identity replay.",
    )
    p.add_argument("--out-dir", required=True, help="run directory")
    p.add_argument("--config", help="authz-config.json (identities + tests)")
    p.add_argument("--active", action="store_true",
                   help="send real requests (requires config.authorization)")
    p.add_argument("--profile", default="safe",
                   help="safety profile (passive forbids active testing)")
    p.add_argument("--model", default="", help="producing-model tag for proofs")
    # init mode
    p.add_argument("--init", action="store_true",
                   help="seed a config template from an inventory/matrix and exit")
    p.add_argument("--inventory", help="api-inventory.json for --init")
    p.add_argument("--matrix", help="authz-matrix.json for --init")
    p.add_argument("--base-url", default="", help="base URL (for --init)")
    p.add_argument("--stdout", action="store_true", help="print JSON to stdout")
    return p


def _run_init(args) -> int:
    from core.webauthz.template import template_from_inventory
    src = args.inventory or args.matrix
    if not src:
        print("error: --init requires --inventory or --matrix", file=sys.stderr)
        return 2
    doc = json.loads(Path(src).read_text(encoding="utf-8"))
    template = template_from_inventory(doc, base_url=args.base_url)
    blob = json.dumps(template, indent=2)
    if args.stdout:
        print(blob)
        return 0
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / "authz-config.json"
    dest.write_text(blob, encoding="utf-8")
    print(f"Wrote config template with {len(template['tests'])} test(s) → {dest}")
    print("Fill in object ids, credential env-vars, and `authorization`, then run "
          "with --config and --active.")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.init:
        return _run_init(args)

    if not args.config:
        print("error: --config is required (or use --init)", file=sys.stderr)
        return 2

    from core.webauthz.config import load_config
    from core.webauthz.report import render
    from core.webauthz.runner import run_authz

    try:
        config = load_config(Path(args.config))
        run = run_authz(config, out_dir=args.out_dir, active=args.active,
                        profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.stdout:
        print(json.dumps(run.to_dict(), indent=2))
    else:
        print(render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
