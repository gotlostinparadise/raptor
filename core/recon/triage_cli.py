"""CLI backing ``/recon-triage`` (via ``libexec/raptor-recon-triage``).

A read-only advisory pass over a finished recon run: ranks the discovered hosts
into an attack-worthy worklist (``triage.json`` + ``triage.md``). Deterministic
heuristic ranking by default; pass ``--model`` to have an LLM reorder + annotate
the list (it can only reorder a set the engine already found — see
``docs/recon-intelligence.md``). Never touches the target.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from core.recon.triage import run_triage


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-recon-triage",
        description="Rank a recon run's hosts into an attack-worthy worklist.",
    )
    p.add_argument("out_dir", nargs="?", default=None,
                   help="recon run directory (containing graph/recon.json)")
    p.add_argument("--out-dir", dest="out_dir_flag", default=None,
                   help="recon run directory (alternative to the positional arg)")
    p.add_argument("--model", default=None,
                   help="LLM to reorder + annotate the ranking (optional)")
    p.add_argument("--top", type=int, default=None,
                   help="only write the top N targets")
    p.add_argument("--llm-top", type=int, default=50,
                   help="max targets sent to the model (cost bound, default 50)")
    p.add_argument("--stdout", action="store_true",
                   help="print the triage summary as JSON to stdout")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    out_dir = args.out_dir or args.out_dir_flag
    if not out_dir:
        print("error: pass the recon run directory (positional or --out-dir)",
              file=sys.stderr)
        return 2
    try:
        summary = run_triage(out_dir, model=args.model, top=args.top,
                             llm_top=args.llm_top)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.stdout:
        print(json.dumps(summary, indent=2))
    else:
        n = summary["target_count"]
        print(f"Triage: {n} targets ranked ({summary['generated_by']}) "
              f"→ {out_dir}/triage.md")
        for t in summary["targets"][:10]:
            flags = " ".join(f for f, on in (
                ("exposed-origin", t["exposed_origin"]), ("http", t["has_http"]),
                ("behind-edge", t["behind_edge"])) if on)
            print(f"  {t['rank']:>2}. {t['name']}  (score {t['score']:g}) {flags}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
