"""CLI backing ``/waf`` (via ``libexec/raptor-waf``).

Two modes:
  * ``--mutate PAYLOAD`` — print WAF-evasion variants (offline, always safe).
  * ``--url URL --active`` — fetch the target and fingerprint any WAF fronting it
    (one benign GET; requires --active + authorization).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence
from urllib.parse import urlsplit

from core.waf import detect as _detect
from core.waf import evasion as _evasion


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-waf",
        description="WAF detection + payload-evasion mutations.")
    p.add_argument("--mutate", default="", help="print evasion variants of a payload (offline)")
    p.add_argument("--url", default="", help="fetch + fingerprint a WAF on this target")
    p.add_argument("--active", action="store_true")
    p.add_argument("--authorization", default="")
    p.add_argument("--stdout", action="store_true")
    return p


def _client_for(base_url: str):
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    if parts.scheme == "https" and parts.port in (None, 443) and host:
        from core.http import default_client
        return default_client([host])
    from core.http.urllib_backend import UrllibClient
    return UrllibClient()


def _detect_waf(url: str):
    from core.http import HttpError, Response
    client = _client_for(url)
    try:
        resp = client.request("GET", url, raise_on_status=False)
    except TypeError:
        try:
            resp = client.request("GET", url)
        except HttpError as exc:
            resp = Response(status=int(exc.status or 0), headers={}, body=b"", url=url)
    return _detect.detect_from_response(resp), getattr(resp, "status", 0)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.mutate:
        variants = _evasion.mutations(args.mutate)
        if args.stdout:
            print(json.dumps({"payload": args.mutate, "variants": variants}, indent=2))
        else:
            print(f"{len(variants)} variant(s) for {args.mutate!r}:")
            for v in variants:
                print(f"  {v}")
        return 0

    if args.url:
        if not args.active:
            print("error: WAF detection sends a request; pass --active (+ --authorization)",
                  file=sys.stderr)
            return 2
        if not args.authorization.strip():
            print("error: active WAF detection requires --authorization", file=sys.stderr)
            return 2
        wafs, status = _detect_waf(args.url)
        result = {"url": args.url, "status": status, "wafs": wafs,
                  "blocked": _detect.is_block(status)}
        if args.stdout:
            print(json.dumps(result, indent=2))
        else:
            print(f"WAF fingerprint for {args.url} (status {status}):")
            print(f"  detected: {', '.join(wafs) if wafs else '(none)'}")
            if _detect.is_block(status):
                print("  note: block-style status — the target may be rate-limiting/blocking")
        return 0

    print("error: provide --mutate PAYLOAD or --url URL --active", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
