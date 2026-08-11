"""Human-readable rendering of a `/webauthz` run."""

from __future__ import annotations

from core.webauthz.runner import AuthzRun


def render(run: AuthzRun) -> str:
    lines = []
    mode = "ACTIVE" if run.active else "dry-run (no requests sent)"
    lines.append(f"Access-control test — {mode}")
    lines.append(f"  target:  {run.base_url}")
    if not run.active:
        lines.append(f"  planned: {run.tests_planned} test(s) — run with --active to execute")
    else:
        lines.append(f"  ran:     {run.tests_run}/{run.tests_planned} test(s)")
        viols = run.violations
        if viols:
            lines.append(f"  broken access control: {len(viols)} finding(s)")
            for f in viols:
                who = ", ".join(f.get("offending") or [])
                tag = "" if f.get("confirmed") else "  (SUSPECTED — add control_path)"
                lines.append(f"    ⚠ {f['id']}  {f['endpoint']}  [{f['class']}/"
                             f"{f.get('owasp','')}]  reachable by: {who}{tag}")
        else:
            lines.append("  no access-control violations confirmed")
    for w in run.warnings:
        lines.append(f"  ! {w}")
    lines.append(f"  graph:   {run.out_dir}/graph/web.json")
    if run.active and run.violations:
        lines.append(f"  proofs:  surfaced via `libexec/raptor-verified-outcomes {run.out_dir}`")
    return "\n".join(lines)


__all__ = ["render"]
