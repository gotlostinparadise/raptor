---
description: API security testing workflow — spec-grounded, OWASP API Top 10 (2023) coverage across authn, authz (BOLA/BFLA), input, business logic, and config.
dispatch: skill
---

# /api - RAPTOR API Security Testing

A structured, phase-driven API penetration-testing workflow. It grounds
the LLM in a **mechanically parsed endpoint inventory** (Phase 0) and then
walks the OWASP API Security Top 10 (2023) in the order real attacks
progress: inventory → recon → authentication → **authorization** → input
→ business logic → config → report.

The core insight this workflow is built around: the API bugs that matter
most (BOLA/API1, property-level/API3, BFLA/API5, sensitive-flow abuse/API6)
are **authorization and business-logic** flaws that scanners cannot find.
This workflow makes the tedious, high-value authorization matrix mechanical
and the logic testing systematic.

## Execution Model

**You (Claude) ARE the tester for this pipeline.** Phase 0 is mechanical
(`libexec/raptor-api-inventory` parses the spec). Phases 1–7 are LLM-driven
— you follow the skill files, drive the tools, and record findings.

`dispatch: skill` — this file plus the phase skill files are the source of
truth. Read them; do not improvise CLI flags from memory.

## AUTHORIZATION GATE (read first, every run)

Active API testing sends real requests to a live target. Before any phase
past 0 that touches a network target:

1. Confirm the operator has **written authorization** to test the target
   (in-scope hosts, endpoints, accounts, and time window).
2. Confirm rate/DoS-class tests (API4, API6) are permitted, or mark them
   **passive-only** (analyse, do not execute) in the plan.
3. If the target is only a spec file (no base URL), all phases are
   **static/passive** by definition — no gate needed, but say so.

If authorization is unclear, STOP and ask. Do not send active requests on
assumption. Static spec analysis (Phases 0, and the passive parts of 6/9)
is always safe.

## Usage

```
/api <target> [--spec <file>] [--base-url <url>] [--phase <0-7|all>]
              [--roles a,b,...] [--scope-file <f>] [--out <dir>]
```

`<target>` may be:
- a **spec file** (OpenAPI/Swagger JSON/YAML, Postman collection, or a
  GraphQL introspection JSON) — Phase 0 parses it directly;
- a **base URL** — no spec; Phase 1 recon builds the surface dynamically;
- a **directory** — searched for a spec (`openapi.*`, `swagger.*`,
  `*.postman_collection.json`); falls back to URL/recon if none found.

Flags:
- `--spec <file>` — explicit description file (overrides target discovery).
- `--base-url <url>` — live API root for active phases.
- `--phase <n>` — run one phase only (default: `all`, phases 0→7 in order).
- `--roles a,b,c` — role names for the authz matrix (default
  `anonymous,user_a,user_b,admin`).
- `--scope-file <f>` — file of in-scope host/path globs; out-of-scope
  endpoints are dropped from active testing.
- `--out <dir>` — explicit output dir (share with `/understand`/`/validate`).

## Execution

**Step 1 — Start the run.** Resolve the target per DEFAULT TARGET
DIRECTORY, then:
```bash
libexec/raptor-run-lifecycle start api --target <resolved_target>
```
The last line is `OUTPUT_DIR=<path>` — use it for every output file below.

**Step 2 — Phase 0 (mechanical inventory).** If a spec is available:
```bash
libexec/raptor-api-inventory --spec <spec> --out-dir "$OUTPUT_DIR" [--base-url <url>] [--roles <roles>]
```
This writes `api-inventory.json` + `authz-matrix.json`. If no spec exists,
skip the parser and build the inventory during Phase 1 recon instead.

**Step 3 — Phases 1–7 (LLM-driven).** Load `.claude/skills/api-testing/SKILL.md`
first (gates, config, artifact schemas), then the per-phase file for each
phase you run. Record findings to `$OUTPUT_DIR/api-findings.json` and fill
`result`/`evidence` back into `authz-matrix.json` as you execute rows.

**Step 4 — Complete the run.** Replace `<your-model-id>` with your exact
model ID (RAPTOR's Python can't read it):
```bash
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR" --model <your-model-id>
```

**On failure:**
```bash
libexec/raptor-run-lifecycle fail "$OUTPUT_DIR" "error description"
```

## Phases (OWASP API Top 10 2023 mapping)

| Phase | Focus | OWASP | Skill file |
|-------|-------|-------|------------|
| 0 | Inventory & discovery | API9 | `phase-0-inventory.md` |
| 1 | Recon & data/role modelling | — | `phase-1-recon.md` |
| 2 | Authentication (JWT/OAuth/keys) | API2 | `phase-2-authn.md` |
| 3 | **Authorization (BOLA/BFLA/property)** | API1, API3, API5 | `phase-3-authz.md` |
| 4 | Input validation & injection (+SSRF) | API7 | `phase-4-input.md` |
| 5 | Business logic & resource abuse | API4, API6 | `phase-5-logic.md` |
| 6 | Config & unsafe consumption | API8, API10 | `phase-6-config.md` |
| 7 | Reporting & regression | — | `phase-7-report.md` |

Phase 3 is the core of API pentesting — budget the most time there.

## Skill Files

Load before executing:
- `.claude/skills/api-testing/SKILL.md` — gates, config, artifact schemas
- `.claude/skills/api-testing/phase-<0-7>-*.md` — one per phase

## Integration

- **`/understand`** — run `/understand <spec-or-src> --map` first and share
  `--out` to seed trust boundaries and sinks.
- **`/validate`** — hand confirmed findings to `/validate` for exploitability
  proof; use the same `--out` dir so artifacts bridge automatically.
- **`/web`** — the alpha web scanner covers generic OWASP Top 10; `/api` is
  the API-specific, authorization-first companion.

## Output

Written under `$OUTPUT_DIR`:

| File | Phase | Contents |
|------|-------|----------|
| `api-inventory.json` | 0 | Normalised endpoints + OWASP focus per endpoint |
| `authz-matrix.json` | 0/3 | BOLA/BFLA/property test rows; results filled in Phase 3 |
| `api-findings.json` | 2–6 | Confirmed findings with evidence + OWASP id |
| `api-report.md` | 7 | Operator report, findings ranked, regression notes |

## Notes

- Only test APIs you are authorized to test.
- Scanners find injection/misconfig; **only account-aware manual testing
  finds authorization and business-logic flaws** — this workflow is built
  to make that work systematic, not to replace it.
