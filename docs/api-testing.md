# API Security Testing (`/api`)

A phase-driven API penetration-testing workflow for RAPTOR, built around the
**OWASP API Security Top 10 (2023)** and an **authorization-first** method.
It grounds the LLM in a mechanically parsed endpoint inventory, then walks
the surface in the order real attacks progress.

The design premise: the API bugs that cause breaches — BOLA (API1),
property-level (API3), BFLA (API5), sensitive-flow abuse (API6) — are
**authorization and business-logic** flaws that scanners fundamentally
cannot find. This workflow makes the tedious, high-value authorization
matrix mechanical and the logic testing systematic; it does not pretend a
scanner can replace account-aware manual testing.

## Command

```
/api <target> [--spec <file>] [--base-url <url>] [--phase <0-7|all>]
              [--roles a,b,...] [--scope-file <f>] [--out <dir>]
```

Dispatch: `skill` — the workflow is LLM-driven; the phase files under
`.claude/skills/api-testing/` are authoritative. See `.claude/commands/api.md`.

`<target>` resolves to a **spec file** (OpenAPI/Swagger JSON/YAML, Postman
collection, or GraphQL introspection JSON), a **base URL**, or a **directory**
searched for a spec.

## Authorization

Active testing sends real requests. The workflow enforces **GATE-A1**: no
active request without confirmed written authorization for the target,
accounts, and time window. Spec-only analysis (Phase 0 and passive parts of
Phase 6) is always safe. Resource/DoS-class tests (API4/API6) are passive-only
unless explicitly authorized.

## Phases → OWASP mapping

| Phase | Focus | OWASP 2023 |
|-------|-------|------------|
| 0 | Inventory & discovery (mechanical) | API9 |
| 1 | Recon, account/object/role modelling | — |
| 2 | Authentication (JWT/OAuth/keys) | API2 |
| 3 | **Authorization (BOLA/BFLA/property)** | API1, API3, API5 |
| 4 | Input validation, injection, SSRF | API7 |
| 5 | Business logic & resource abuse | API4, API6 |
| 6 | Configuration & unsafe consumption | API8, API10 |
| 7 | Reporting & regression | — |

Phase 3 is the core of API pentesting and gets the most effort.

## Phase 0 — the mechanical backbone

`libexec/raptor-api-inventory` parses an API description **offline** (no
network, no LLM) into two artefacts:

```bash
libexec/raptor-api-inventory --spec <file> --out-dir <dir> \
    [--base-url <url>] [--roles anonymous,user_a,user_b,admin]
```

Auto-detected inputs: OpenAPI 3.x / Swagger 2.0 (JSON or YAML), Postman
collection v2.x (JSON), GraphQL introspection result (JSON). `--stdout`
prints the inventory and writes no files.

### `api-inventory.json`

Normalised endpoint list. Per endpoint:

| Field | Meaning |
|-------|---------|
| `id` | Stable `EP-NNNN` handle |
| `method`, `path` | HTTP method + templated path (or `QUERY.field` for GraphQL) |
| `operation_id`, `summary` | From the spec |
| `auth_required`, `security` | Whether the endpoint requires auth, and the scheme names |
| `path_params`, `query_params` | Parameter names by location |
| `body_fields` | Request-body property names (one `$ref` hop resolved) — mass-assignment candidates |
| `object_scoped` | Heuristic: references an object id (drives BOLA/API1 tests) |
| `privileged` | Heuristic: admin/internal/mutating-on-object (drives BFLA/API5 tests) |
| `owasp_focus` | The OWASP categories this endpoint most invites (e.g. `API1`, `API7`) |

Plus top-level counts: `endpoint_count`, `object_scoped_count`,
`privileged_count`, `no_auth_count`, `source_kind`, `base_url`.

The object-scope and SSRF heuristics are label-aware (an `id`/`user_id`/`uuid`
parameter or a `{templated}` path segment marks object scope; a
`url`/`webhook`/`callback` parameter marks an SSRF candidate).

### `authz-matrix.json`

Seed authorization test rows generated from the inventory — one BOLA (API1)
row per object-scoped endpoint, one property-level (API3) row per mutating
endpoint with a body, one BFLA (API5) row per privileged endpoint. Each row
carries a `procedure`, `expected: denied`, and null `result`/`evidence` for
Phase 3 to fill during execution.

**Object ids come from the app, not the spec.** The matrix gives you the route
and the test; Phase 1 recon captures the real user_a/user_b ids that make the
cross-account replay possible.

## Outputs (under the run's `$OUTPUT_DIR`)

| File | Phase | Contents |
|------|-------|----------|
| `api-inventory.json` | 0 | Normalised endpoints + OWASP focus |
| `authz-matrix.json` | 0/3 | BOLA/BFLA/property rows; results filled in Phase 3 |
| `api-findings.json` | 2–6 | Confirmed findings with evidence, OWASP id, CVSS |
| `api-report.md` | 7 | Operator report, ranked findings, coverage, regression notes |

## Integration

- **`/understand <spec-or-src> --map`** — run first, share `--out`, to seed
  trust boundaries and sinks.
- **`/validate`** — hand confirmed findings over for exploitability proof;
  same `--out` dir bridges the artefacts.
- **`/web`** — generic OWASP Top 10 web scanning; `/api` is the API-specific,
  authorization-first companion.

## Reference material

- OWASP API Security Top 10 (2023) — the category map this workflow follows.
- OWASP WSTG §4.12 API Testing (`WSTG-APIT-*`) — test-id discipline.
- IETF OAuth 2.0 Security BCP (RFC 9700) / OAuth 2.1 — Phase 2 auth flows.
- Tooling the phases reference: Burp (Autorize, AuthMatrix, Turbo Intruder),
  ZAP, mitmproxy, Schemathesis, RESTler, jwt_tool, Arjun/x8, nuclei,
  graphw00f/clairvoyance (GraphQL).

## Implementation

- Parser logic: `core/apitest/inventory.py` (offline, stdlib + optional PyYAML).
- CLI shim: `libexec/raptor-api-inventory`.
- Workflow: `.claude/commands/api.md` + `.claude/skills/api-testing/`.
- Tests: `core/apitest/tests/test_inventory.py`.
