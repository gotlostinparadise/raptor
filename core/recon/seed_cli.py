"""CLI backing ``/recon-seed`` (via ``libexec/raptor-recon-seed``).

Proposes scope candidates for an org (recon intelligence layer 1) and writes a
reviewable ``scope-proposal.json``. It never scans: the operator confirms
candidates, then feeds the confirmed roots to ``/recon`` (``--scope-file`` /
``--save-scope``). Requires ``--model`` — scope proposal is inherently the LLM's
job.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.recon.seed import propose_scope


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-recon-seed",
        description="Propose recon scope candidates for an org (operator-confirmed).",
    )
    p.add_argument("--out-dir", required=True,
                   help="directory to write scope-proposal.json into")
    p.add_argument("--org", required=True,
                   help="target organisation name")
    p.add_argument("--seed", action="append", default=[],
                   help="a known in-scope domain/brand (repeatable)")
    p.add_argument("--model", required=True,
                   help="LLM to propose scope candidates")
    p.add_argument("--stdout", action="store_true",
                   help="print the proposal as JSON to stdout")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    proposal = propose_scope(args.org, args.seed, args.model)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "scope-proposal.json").write_text(
        json.dumps(proposal.to_dict(), indent=2), encoding="utf-8")

    if args.stdout:
        print(json.dumps(proposal.to_dict(), indent=2))
    else:
        n = len(proposal.candidates)
        print(f"Scope proposal: {n} candidate(s) for {args.org!r} "
              f"→ {out}/scope-proposal.json")
        for c in proposal.candidates:
            conf = f"[{c.confidence}]" if c.confidence else ""
            print(f"  · {c.domain}  ({c.kind}) {conf}  {c.rationale}")
        print("\nPROPOSAL ONLY — confirm ownership/authorization, then feed "
              "confirmed roots to /recon (--scope-file).")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
