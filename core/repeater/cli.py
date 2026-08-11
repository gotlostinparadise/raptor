"""CLI backing ``/repeater`` (via ``libexec/raptor-repeater``).

Two modes:
  * ``--poc {curl,python,http}`` — generate a runnable PoC from a request spec
    (offline, always safe).
  * ``--send --active`` — send the request (requires --active + --authorization),
    print the response summary; ``--set-param`` / ``--set-header`` tamper first.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence
from urllib.parse import urlsplit

from core.repeater import poc as _poc
from core.repeater.repeater import Repeater
from core.repeater.request import RequestSpec


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-repeater",
        description="Burp-repeater analog — send/tamper a request, generate PoCs.")
    p.add_argument("--spec", required=True, help="request spec JSON (method/url/headers/body)")
    p.add_argument("--poc", choices=["curl", "python", "http"],
                   help="generate a PoC and exit (offline)")
    p.add_argument("--send", action="store_true", help="send the request")
    p.add_argument("--active", action="store_true")
    p.add_argument("--authorization", default="")
    p.add_argument("--set-param", action="append", default=[], help="NAME=VALUE query tamper")
    p.add_argument("--set-header", action="append", default=[], help="NAME=VALUE header tamper")
    p.add_argument("--out", default="", help="write the PoC to this file")
    return p


def _apply_tamper(spec: RequestSpec, set_params, set_headers) -> RequestSpec:
    for kv in set_params:
        if "=" in kv:
            k, v = kv.split("=", 1)
            spec = spec.with_query(k, v)
    for kv in set_headers:
        if "=" in kv:
            k, v = kv.split("=", 1)
            spec = spec.with_header(k, v)
    return spec


def _client_for(url: str):
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https" and parts.port in (None, 443) and host:
        from core.http import default_client
        return default_client([host])
    from core.http.urllib_backend import UrllibClient
    return UrllibClient()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        spec = RequestSpec.load(Path(args.spec))
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    spec = _apply_tamper(spec, args.set_param, args.set_header)

    if args.poc:
        poc = _poc.generate(spec, args.poc)
        if args.out:
            Path(args.out).write_text(poc, encoding="utf-8")
            print(f"wrote {args.poc} PoC → {args.out}")
        else:
            print(poc)
        return 0

    if args.send:
        if not args.active:
            print("error: sending a request needs --active (+ --authorization)", file=sys.stderr)
            return 2
        if not args.authorization.strip():
            print("error: active send requires --authorization", file=sys.stderr)
            return 2
        rep = Repeater(_client_for(spec.url))
        ex = rep.send(spec)
        print(json.dumps({"status": ex.status, "length": ex.length,
                          "body_sha256": ex.body_sha256}, indent=2))
        return 0

    # default: show curl PoC
    print(_poc.to_curl(spec))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
