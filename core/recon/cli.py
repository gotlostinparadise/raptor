"""CLI backing ``/recon`` (via ``libexec/raptor-recon``).

Builds the infrastructure-layer graph into a run directory: passive discovery
(crt.sh, Censys, subfinder) plus — under a non-passive profile with explicit
authorization — active enumeration (dnsx resolve, naabu ports, httpx probe),
driven through the :mod:`core.recon.orchestrator` discovery loop. ``--web`` hands
the discovered live origins to the application-layer :mod:`core.webgraph`
pipeline in the same run directory. ``--rebuild`` re-derives the graph exports
from persisted ``normalized/*.jsonl`` without re-touching the target.

Safety: passive sources run under every profile. Active sources are gated twice —
by the safety :class:`~core.recon.source.Profile` (the ``passive`` profile drops
them) *and* by an explicit ``--active`` + non-empty ``--authorization``
attestation here, mirroring the access-control gate the web capabilities use.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from core.recon.orchestrator import RunSummary, rebuild_from_disk, run_recon
from core.recon.registry import load_sources
from core.recon.source import DEFAULT_PROFILE, PROFILES, registered_credential_env_vars


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-recon",
        description="Build the infrastructure-layer recon graph.",
    )
    p.add_argument("roots", nargs="*",
                   help="in-scope apex domain(s), e.g. example.com")
    p.add_argument("--out-dir", required=True,
                   help="run directory (raw/ normalized/ graph/ written here)")
    p.add_argument("--scope-file", default=None,
                   help="file of in-scope roots, one per line (# comments ok)")
    p.add_argument("--profile", default=None, choices=sorted(PROFILES),
                   help="safety profile (passive = zero traffic to the target); "
                        "defaults to the active project's recon_scope, else 'home'")
    p.add_argument("--active", action="store_true",
                   help="permit active sources (required for home/vps profiles)")
    p.add_argument("--authorization", default="",
                   help="written-authorization attestation; required with --active")
    p.add_argument("--seed-ips", default="",
                   help="comma-separated IPs to seed enrichment (skip active DNS)")
    p.add_argument("--save-scope", action="store_true",
                   help="persist the resolved roots + profile on the active "
                        "project so a later bare `/recon` reuses them")
    p.add_argument("--web", action="store_true",
                   help="also build the app-layer graph from discovered origins")
    p.add_argument("--url-history", action="store_true",
                   help="with --web, mine archive.org for historical endpoints "
                        "(passive third-party lookup)")
    p.add_argument("--browser", action="store_true",
                   help="with --web, DOM-aware crawl of discovered origins "
                        "(active; needs Playwright+Chromium)")
    p.add_argument("--authz-config", default=None,
                   help="with --web --browser, a /webauthz identity config so the "
                        "crawl runs authenticated (reaches the logged-in surface)")
    p.add_argument("--max-rounds", type=int, default=3,
                   help="max discovery-loop rounds (default 3)")
    p.add_argument("--rebuild", action="store_true",
                   help="re-derive graph exports from persisted records only")
    p.add_argument("--stdout", action="store_true",
                   help="print the run summary as JSON to stdout")
    return p


def _roots(args: argparse.Namespace) -> List[str]:
    roots = [r.strip() for r in (args.roots or []) if r.strip()]
    if args.scope_file:
        for line in Path(args.scope_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                roots.append(line)
    # de-dup, preserve order
    return list(dict.fromkeys(roots))


def _project_scope() -> tuple:
    """(roots, profile) persisted on the active project, or ([], None).

    Lets ``/recon`` (no args) reuse a project's ``recon_scope``. Every step is
    guarded — no active project, no ProjectManager, or a malformed scope all fall
    back to "nothing persisted" rather than erroring.
    """
    try:
        from core.project.project import ProjectManager
        proj = ProjectManager().get_active()
        if proj and isinstance(proj.recon_scope, dict):
            roots = [str(r) for r in (proj.recon_scope.get("roots") or [])
                     if isinstance(r, str) and r.strip()]
            profile = proj.recon_scope.get("profile")
            return roots, (profile if profile in PROFILES else None)
    except Exception:
        pass
    return [], None


def _save_scope(roots: List[str], profile: str) -> Optional[str]:
    """Persist ``roots`` + ``profile`` on the active project (the writer for the
    ``recon_scope`` the fallback in :func:`_project_scope` reads).

    Returns the project name on success, or ``None`` when there is no active
    project / persistence failed (guarded — never aborts a run).
    """
    try:
        from core.project.project import ProjectManager
        pm = ProjectManager()
        proj = pm.get_active()
        if not proj:
            return None
        pm.set_recon_scope(proj.name, roots, profile)
        return proj.name
    except Exception:
        return None


def _resolve_credentials() -> Dict[str, str]:
    """In-process credential values for every registered source's declared vars.

    Read straight from ``os.environ`` (the trusted orchestrator process), never
    from ``get_safe_env`` — these are deliberately excluded from the subprocess
    allowlist. Sources with a richer resolution order (Censys: env → file) apply
    it themselves; passing the env value through is enough for the rest.
    """
    creds: Dict[str, str] = {}
    for var in registered_credential_env_vars():
        val = os.environ.get(var)
        if val:
            creds[var] = val
    return creds


def _render(summary: RunSummary) -> str:
    lines = [
        f"Recon graph built: {summary.node_count} nodes, {summary.edge_count} edges",
        f"  profile: {summary.profile}   rounds: {summary.rounds}",
        f"  assets:  " + ", ".join(f"{k}={v}" for k, v in sorted(summary.asset_counts.items())),
        f"  sources: {', '.join(summary.sources_run) or '(none ran)'}",
    ]
    if summary.record_counts:
        counts = ", ".join(f"{k}={v}" for k, v in sorted(summary.record_counts.items()))
        lines.append(f"  records: {counts}")
    if summary.errors:
        for name, err in summary.errors.items():
            lines.append(f"  ! {name}: {err}")
    lines.append(f"  graph:   {summary.out_dir}/graph/recon.json")
    return "\n".join(lines)


def _authorization_ok(profile: str, args: argparse.Namespace) -> Optional[str]:
    """Return an error string if the active-testing gate is not satisfied."""
    prof = PROFILES[profile]
    if not prof.allow_active:
        return None  # passive profile: always permitted
    if not args.active:
        return (f"profile {profile!r} runs active sources; pass --active "
                f"to confirm, or use --profile passive for zero target traffic")
    if not args.authorization.strip():
        return ("--active requires --authorization \"<written authorization>\" — "
                "active recon sends real traffic to the target's infrastructure")
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    roots = _roots(args)

    # Fall back to the active project's persisted scope when none was passed.
    proj_profile = None
    if not roots:
        roots, proj_profile = _project_scope()
    profile = args.profile or proj_profile or DEFAULT_PROFILE

    if args.rebuild:
        graph = rebuild_from_disk(args.out_dir, roots)
        stats = graph.stats()
        print(f"Rebuilt graph: {stats['node_count']} nodes, "
              f"{stats['edge_count']} edges → {args.out_dir}/graph/recon.json")
        return 0

    if not roots:
        print("error: no in-scope roots (pass positional roots, --scope-file, "
              "or set the active project's recon_scope)", file=sys.stderr)
        return 2

    gate_err = _authorization_ok(profile, args)
    if gate_err:
        print(f"error: {gate_err}", file=sys.stderr)
        return 2

    if args.save_scope:
        saved = _save_scope(roots, profile)
        if saved:
            print(f"Saved recon scope ({len(roots)} roots, profile {profile}) "
                  f"to project {saved!r}", file=sys.stderr)
        else:
            print("warning: --save-scope had no active project to save to",
                  file=sys.stderr)

    load_sources()

    from core.config import RaptorConfig
    env = dict(RaptorConfig.get_safe_env())
    credentials = _resolve_credentials()
    seed_ips = [ip.strip() for ip in args.seed_ips.split(",") if ip.strip()]

    summary = run_recon(
        roots, args.out_dir, profile=profile, max_rounds=args.max_rounds,
        env=env, credentials=credentials, seed_ips=seed_ips,
    )

    web_summary = None
    if args.web:
        from core.recon.webbridge import build_web_graph
        web_summary = build_web_graph(
            args.out_dir, roots, profile=profile,
            authorization=args.authorization,
            include_url_history=args.url_history,
            browser=args.browser,
            authz_config=args.authz_config,
        )

    if args.stdout:
        payload = {"recon": summary.to_dict()}
        if web_summary is not None:
            payload["web"] = web_summary.to_dict()
        print(json.dumps(payload, indent=2))
    else:
        print(_render(summary))
        if web_summary is not None:
            print(f"  web:     {web_summary.node_count} nodes, "
                  f"{web_summary.edge_count} edges → {args.out_dir}/web/graph/web.json")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
