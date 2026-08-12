"""CLI backing ``/fileupload`` (via ``libexec/raptor-fileupload``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.fileupload.config import FileUploadConfig, from_dict, load_config
from core.fileupload.runner import run_fileupload


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-fileupload",
        description="Unrestricted file-upload testing — upload a marker, retrieve, verdict.")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--config", help="fileupload config JSON")
    p.add_argument("--url", default="", help="base URL (shortcut for a minimal config)")
    p.add_argument("--upload-url", default="/upload")
    p.add_argument("--field-name", default="file")
    p.add_argument("--ext", default=".php")
    p.add_argument("--retrieve-template", default="", help="stored URL with {filename}")
    p.add_argument("--authorization", default="")
    p.add_argument("--active", action="store_true")
    p.add_argument("--profile", default="safe")
    p.add_argument("--model", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _load(args) -> FileUploadConfig:
    if args.config:
        cfg = load_config(Path(args.config))
    elif args.url:
        cfg = from_dict({"base_url": args.url})
    else:
        raise ValueError("provide --config or --url")
    if args.authorization and not cfg.authorization:
        cfg.authorization = args.authorization
    if args.upload_url != "/upload":
        cfg.upload_url = args.upload_url
    if args.field_name != "file":
        cfg.field_name = args.field_name
    if args.ext != ".php":
        cfg.ext = args.ext
    if args.retrieve_template:
        cfg.retrieve_template = args.retrieve_template
    return cfg


def _render(run) -> str:
    lines = [f"File-upload test — {'ACTIVE' if run.active else 'dry-run (no upload)'}",
             f"  target:  {run.base_url}"]
    if run.active:
        confirmed = [f for f in run.findings if f.get("proof")]
        if confirmed:
            lines.append(f"  CONFIRMED: unrestricted upload — {run.verdict} "
                         f"(stored at {run.stored_path})")
        else:
            lines.append("  not confirmed")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = _load(args)
        run = run_fileupload(cfg, out_dir=args.out_dir, active=args.active,
                             profile=args.profile, producing_model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
