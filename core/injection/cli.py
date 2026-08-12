"""CLI backing ``/inject`` (via ``libexec/raptor-inject``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from core.injection.config import (
    InjectionConfig, from_dict, load_config, points_from_webgraph,
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
    p.add_argument("--oast-auto", action="store_true",
                   help="stand up a bundled self-hosted OAST collector (turn-key blind confirmation); "
                        "pass --oast-domain to advertise a target-reachable wildcard domain")
    p.add_argument("--token-env", default="", help="env var holding a bearer token")
    p.add_argument("--model", default="", help="producing-model attribution stamped on findings")
    p.add_argument("--browser", action="store_true",
                   help="also run the DOM-XSS oracle in a real browser (needs Playwright/Chromium)")
    p.add_argument("--llm-model", default="",
                   help="model driving the XSS proposer / DOM-XSS pass (mechanical when unset)")
    p.add_argument("--budget", type=int, default=0,
                   help="cap total requests sent (0 = unbounded); triages the sweep and "
                        "spends the budget on the highest-priority (point, class) pairs first")
    p.add_argument("--triage", action="store_true",
                   help="run the mechanical (point, class) pre-score even without a model/budget")
    p.add_argument("--adapt", action="store_true",
                   help="read responses and adapt: WAF-evasion retries + response-guided "
                        "payload ordering (LLM-driven when --llm-model is set)")
    p.add_argument("--adapt-steps", type=int, default=0,
                   help="cap sends per (point, class) hypothesis in adapt mode (0 = no cap)")
    p.add_argument("--chain", action="store_true",
                   help="chain findings: leaked endpoints/tokens/ids from a confirmed finding "
                        "become new surface tested in the same run")
    p.add_argument("--chain-rounds", type=int, default=0,
                   help="max finding→surface→retest hops to follow (default 2)")
    p.add_argument("--union", action="store_true",
                   help="escalate a confirmed SQLi to reflection-proof UNION data extraction "
                        "(read-only: schema/version, and on a real dump the leaked rows)")
    p.add_argument("--union-extract", action="append", default=[],
                   help="operator-declared scalar SELECT to dump via UNION on a confirmed SQLi "
                        "(repeatable), e.g. 'SELECT group_concat(email) FROM Users'; implies --union")
    p.add_argument("--stdout", action="store_true")
    return p


def _harness_from(args):
    """A real-browser DOM-XSS harness when ``--browser`` is set and available.

    Mirrors ``orchestrator._inject`` (core/webpentest/orchestrator.py): loopback
    targets run unproxied; a remote host is pinned into the proxy allowlist. The
    returned object is a context manager the caller enters around the run; None
    when ``--browser`` is off or Playwright/Chromium is absent.
    """
    # Match orchestrator._inject: the browser only launches for an active run
    # (a dry-run sends nothing, so there is no DOM to confirm against).
    if not args.browser or not args.active:
        return None
    from core.browser import harness as _bh
    if not _bh.available():
        return None
    from urllib.parse import urlsplit
    base = args.base_url or (load_config(Path(args.config)).base_url if args.config else "")
    host = urlsplit(base).hostname or ""
    local = host in ("localhost", "127.0.0.1", "::1")
    return _bh.BrowserHarness(allow_unproxied=local,
                              proxy_hosts=() if local else [host])


def _oast_from(args, stack=None):
    """Build the OAST client for this run (None disables blind classes).

    ``--oast-auto`` stands up the bundled self-hosted collector on ``stack``
    (kept alive for the run); ``--oast-domain [+ --oast-poll-url]`` uses an
    external collector; otherwise an in-memory backend (tests / no real OOB).
    """
    from core.oast.client import OastClient
    if args.oast_auto:
        if not args.active:
            return None          # dry-run sends nothing → no collector to stand up
        from core.oast.collector import OastCollector
        col = OastCollector(args.oast_domain or None)
        if stack is not None:
            stack.enter_context(col)
        else:                                  # pragma: no cover - defensive
            col.start()
        return OastClient(col.backend())
    if not args.oast_domain:
        return None
    from core.oast.backend import HttpPollBackend, InMemoryBackend
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
            # Preserve content_type + others (sibling form-context): dropping
            # them here re-breaks the submit-gated classes the orchestrator fix
            # restored — standalone /inject must round-trip the same fields.
            "points": [{"method": p.method, "path": p.path, "param": p.param,
                        "location": p.location, "content_type": p.content_type,
                        "others": p.others} for p in pts],
        })
    else:
        raise ValueError("provide --config or --from-webgraph (+ --base-url)")
    if args.classes:
        cfg.classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    if args.token_env:
        cfg.token_env = args.token_env
    if getattr(args, "budget", 0):
        cfg.request_budget = args.budget
    if getattr(args, "triage", False):
        cfg.triage = True
    if getattr(args, "adapt", False):
        cfg.adapt = True
    if getattr(args, "adapt_steps", 0):
        cfg.adapt_steps = args.adapt_steps
    if getattr(args, "chain", False):
        cfg.chain = True
    if getattr(args, "chain_rounds", 0):
        cfg.chain_rounds = args.chain_rounds
    if getattr(args, "union", False):
        cfg.union = True
    if getattr(args, "union_extract", None):
        cfg.union_extract = list(args.union_extract)
        cfg.union = True
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
    from contextlib import ExitStack
    try:
        with ExitStack() as stack:
            cfg = _load(args)
            llm = args.llm_model or None
            harness = _harness_from(args)
            common = dict(out_dir=args.out_dir, active=args.active, profile=args.profile,
                          producing_model=args.model, oast=_oast_from(args, stack),
                          llm_model=llm)
            if harness is not None:
                h = stack.enter_context(harness)
                run = run_injection(cfg, dom_xss_harness=h, **common)
            else:
                if args.browser:
                    print("warning: --browser requested but Playwright/Chromium absent; "
                          "running HTTP oracles only", file=sys.stderr)
                run = run_injection(cfg, **common)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(run.to_dict(), indent=2) if args.stdout else _render(run))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
