"""CLI backing ``/webgraph`` (via ``libexec/raptor-webgraph``).

Builds the application-layer graph into a run directory. Today's offline surface
is API-spec import (``--spec``); as active sources land (browser/HTTP crawl,
proxy capture) they register automatically and are picked up here under a
non-passive profile. ``--rebuild`` re-derives the graph exports from the
persisted ``normalized/*.jsonl`` without re-touching the target.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, Sequence

from core.webgraph.orchestrator import RunSummary, rebuild_from_disk, run_webgraph
from core.webgraph.source import DEFAULT_PROFILE, PROFILES, Source


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-webgraph",
        description="Build the app-layer request/traffic graph.",
    )
    p.add_argument("--out-dir", required=True,
                   help="run directory (raw/ normalized/ graph/ written here)")
    p.add_argument("--spec", default=None,
                   help="OpenAPI/Swagger/Postman/GraphQL-introspection file to import")
    p.add_argument("--base-url", default="",
                   help="base URL for the spec (origin for its endpoints)")
    p.add_argument("--origins", default="",
                   help="comma-separated in-scope origins (seed origin nodes)")
    p.add_argument("--profile", default=DEFAULT_PROFILE, choices=sorted(PROFILES),
                   help="safety profile (passive = no traffic to target)")
    p.add_argument("--browser", action="store_true",
                   help="DOM-aware crawl of --origins with headless Chromium "
                        "(active; requires playwright+chromium)")
    p.add_argument("--allow-unproxied", action="store_true",
                   help="permit browser navigation to a remote host with no "
                        "egress proxy (loopback fixtures / explicit opt-out)")
    p.add_argument("--rebuild", action="store_true",
                   help="re-derive graph exports from persisted records only")
    p.add_argument("--stdout", action="store_true",
                   help="print the run summary as JSON to stdout")
    return p


def _origins(csv: str) -> List[str]:
    return [o.strip() for o in csv.split(",") if o.strip()]


def _render(summary: RunSummary) -> str:
    lines = [
        f"Web graph built: {summary.node_count} nodes, {summary.edge_count} edges",
        f"  profile: {summary.profile}   rounds: {summary.rounds}",
        f"  sources: {', '.join(summary.sources_run) or '(none ran)'}",
    ]
    if summary.record_counts:
        counts = ", ".join(f"{k}={v}" for k, v in sorted(summary.record_counts.items()))
        lines.append(f"  records: {counts}")
    if summary.errors:
        for name, err in summary.errors.items():
            lines.append(f"  ! {name}: {err}")
    lines.append(f"  graph:   {summary.out_dir}/graph/web.json")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    origins = _origins(args.origins)

    if args.rebuild:
        graph = rebuild_from_disk(args.out_dir, origins)
        stats = graph.stats()
        print(f"Rebuilt graph: {stats['node_count']} nodes, "
              f"{stats['edge_count']} edges → {args.out_dir}/graph/web.json")
        return 0

    sources: Optional[List[Source]] = None
    if args.spec or args.browser:
        sources = []
        if args.spec:
            # Lazy import so the spec source registers, and so a missing optional
            # dependency in a future source can't break `--rebuild`.
            from core.webgraph.spec_source import ApiSpecImportSource
            sources.append(ApiSpecImportSource(spec_path=args.spec, base_url=args.base_url))
        if args.browser:
            from core.browser import harness as _bh
            if not _bh.available():
                print("error: --browser needs Playwright + Chromium; install with "
                      "`pip install playwright && playwright install chromium`",
                      file=sys.stderr)
                return 2
            from core.browser.crawl_source import BrowserCrawlSource
            sources.append(BrowserCrawlSource(allow_unproxied=args.allow_unproxied))

    summary = run_webgraph(
        origins, args.out_dir, sources=sources, profile=args.profile,
    )
    if args.stdout:
        print(json.dumps(summary.to_dict(), indent=2))
    else:
        print(_render(summary))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
