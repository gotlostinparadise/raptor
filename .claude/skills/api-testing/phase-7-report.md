---
name: api-testing-phase-7-report
description: Reporting and regression — assemble findings mapped to OWASP API Top 10 with CVSS, record coverage honestly, and convert confirmed bugs into regression tests and a /validate handoff.
user-invocable: false
---

# [PHASE 7] Reporting & Regression

**LLM-driven.** GATE-A5 (honest coverage). See `SKILL.md`.

## Goal

Produce an operator report that is evidence-backed, OWASP-mapped, and honest
about coverage — then turn confirmed bugs into regression tests and a
`/validate` handoff.

## Assemble the report — `api-report.md`

1. **Summary** — 2–3 sentences: what was tested, headline findings, residual
   risk. Facts from `api-findings.json` only.
2. **Coverage (GATE-A5)** — endpoints in inventory vs endpoints actually
   tested per phase. List untested endpoints explicitly; never imply full
   coverage you did not achieve. Include the shadow endpoints found (API9).
3. **Findings** — ranked most-severe first. Each: OWASP id, title, affected
   endpoint (`METHOD /path` + `EP-id`), severity + CVSS 3.1 vector, confidence,
   reproduction steps, the request/response evidence (secrets redacted), and
   remediation.
4. **Authorization matrix result** — summarise `authz-matrix.json`: rows run,
   BOLA/BFLA/property confirmed vs denied. This is the core-phase scorecard.
5. **Passive/unverified items** — consumption/DoS analyses not executed, marked
   `suspected` with reasoning.

## Status & style

- snake_case in JSON, Title Case in prose; no red/green indicators.
- `confirmed` requires reproducible evidence (GATE-A4). Everything else is
  `suspected` and goes to the handoff, not the confirmed list.

## Handoffs

- **`/validate`** — pass confirmed (and high-value suspected) findings for
  exploitability proof. Share the same `--out` dir so `api-findings.json`
  bridges automatically.
- **Regression** — for each confirmed bug, describe the deterministic check
  that would catch a regression: a contract test (schema/authz assertion), a
  saved request that must return 403, or a Schemathesis/CI rule. This is how
  the finding stops recurring.
- **`/understand` / `/threat-model`** — feed confirmed authz gaps back so the
  project threat model reflects the real trust boundaries.

## Complete the run

Return to `.claude/commands/api.md` Step 4 to complete the lifecycle with your
model id.

## Output

- `api-report.md` — the operator report.
- Finalised `api-findings.json` and `authz-matrix.json`.
