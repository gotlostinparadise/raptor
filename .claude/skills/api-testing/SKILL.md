---
name: api-testing
description: Phase-driven API security testing grounded in a parsed endpoint inventory, covering the OWASP API Security Top 10 (2023) with an authorization-first methodology (BOLA/BFLA/property-level), plus authentication, input, business logic, and configuration testing.
user-invocable: false
---

# API Security Testing Skill

Structured API penetration testing for the `/api` command. Grounds the LLM
in a mechanically parsed endpoint inventory, then walks the OWASP API
Security Top 10 (2023) in attack order.

## Purpose

Find the API bugs that scanners cannot: **broken authorization** (BOLA/API1,
property-level/API3, BFLA/API5) and **business-logic abuse** (API6),
alongside authentication (API2), injection/SSRF (API7), and configuration
(API8, API10) flaws — with evidence for every finding.

## When to Use

- Testing a REST, GraphQL, or RPC API you are authorized to assess.
- After obtaining an OpenAPI/Swagger spec, Postman collection, or GraphQL
  introspection result (Phase 0 parses any of these).
- As the API-specific companion to `/web` (generic web) and `/validate`
  (exploitability proof).

## OWASP API Security Top 10 (2023) — the map

| ID | Category | Primary phase |
|----|----------|---------------|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | 3 |
| API2 | Broken Authentication | 2 |
| API3 | Broken Object **Property** Level Authorization | 3 |
| API4 | Unrestricted Resource Consumption | 5 |
| API5 | Broken Function Level Authorization (BFLA) | 3 |
| API6 | Unrestricted Access to Sensitive Business Flows | 5 |
| API7 | Server Side Request Forgery (SSRF) | 4 |
| API8 | Security Misconfiguration | 6 |
| API9 | Improper Inventory Management | 0/1 |
| API10 | Unsafe Consumption of APIs | 6 |

---

## [CONFIG] Configuration

```yaml
output_dir: resolved by raptor-run-lifecycle start api (or --out)
default_roles: [anonymous, user_a, user_b, admin]
accounts_required: ">=2 accounts per privilege level (attacker + victim)"
confidence_levels:
  high: "Reproduced with a request/response pair — show it"
  medium: "Strongly indicated by response, not yet reproduced end-to-end"
  low: "Suspected from spec/behaviour — flag, verify before reporting"
severity: CVSS 3.1 base vector per confirmed finding
```

---

## [EXEC] Execution Rules

1. **Read the parsed inventory before testing.** `api-inventory.json` is
   ground truth for surface — do not guess endpoints when the spec lists them.
2. **Evidence or it did not happen.** Every finding needs a concrete
   request→response pair (redact secrets). "Looks vulnerable" is a hypothesis,
   not a finding.
3. **Two accounts minimum.** BOLA/BFLA testing is impossible without an
   attacker account (user_a) and a victim account (user_b) whose object ids
   you captured during recon.
4. **Object ids come from the app, not the spec.** The spec gives you the
   route `/orders/{id}`; you must obtain a real `id` owned by user_b.
5. **Respect scope and rate limits.** Honour `--scope-file`. Treat API4/API6
   (resource/flow abuse) as passive-only unless DoS-class testing is
   explicitly authorized.
6. **libexec scripts run verbatim.** Run `libexec/raptor-*` exactly as shown
   — no `bash` prefix, no absolute paths, no added flags. The permission
   system auto-approves only the exact form.
7. **No red/green status indicators.** Title Case in prose, snake_case in JSON.

---

## [GATES] MUST-GATEs

**GATE-A1 [AUTHORIZED]:** No active request without confirmed written
authorization for the target, accounts, and time window. Spec-only analysis
is always allowed; live testing is not assumed.

**GATE-A2 [INVENTORY-FIRST]:** Do not begin active testing until the endpoint
inventory exists (parsed in Phase 0 or built in Phase 1). You cannot claim
coverage of a surface you never enumerated (API9).

**GATE-A3 [AUTHZ-CORE]:** Phase 3 is mandatory and gets the most effort.
Every object-scoped endpoint gets a BOLA test; every privileged endpoint a
BFLA test; every mutating endpoint with a body a property-level test. The
seed rows are in `authz-matrix.json` — execute them, do not skim them.

**GATE-A4 [EVIDENCE]:** A finding is `confirmed` only with a reproducible
request/response pair. Without it, status is `suspected` and it goes to
`/validate`, not the report's confirmed list.

**GATE-A5 [FULL-COVERAGE]:** Test every endpoint in the inventory, not a
sample. If time-boxed, record which endpoints were not reached rather than
implying full coverage.

**GATE-A6 [NON-DESTRUCTIVE]:** Prefer non-destructive proofs. For DELETE/
mutating endpoints, prove authz failure with the least-damaging method
(e.g. read-after-write by the victim, or a benign field) and never destroy
another tenant's data to "prove" a bug.

---

## [STYLE] Output

- Endpoint references: `METHOD /path` + inventory id (`EP-0007`).
- Findings reference their OWASP id (`API1`) and a CVSS 3.1 vector.
- Evidence blocks: the request line, key headers (auth redacted), and the
  decisive part of the response.
- File references for code-backed findings: `path/to/file:line`.

---

## Artifacts & Schemas

### `api-inventory.json` (Phase 0 — mechanical)

```jsonc
{
  "source_kind": "openapi|postman|graphql",
  "base_url": "https://api.example.com/v1",
  "endpoint_count": 42,
  "object_scoped_count": 18, "privileged_count": 7, "no_auth_count": 3,
  "endpoints": [{
    "id": "EP-0001", "method": "GET", "path": "/users/{id}",
    "operation_id": "getUser", "summary": "...",
    "auth_required": true, "security": ["bearerAuth"],
    "path_params": ["id"], "query_params": ["expand"],
    "body_fields": ["name","role"],
    "object_scoped": true, "privileged": false,
    "owasp_focus": ["API1"]
  }]
}
```

### `authz-matrix.json` (Phase 0 seed → Phase 3 results)

```jsonc
{
  "roles": ["anonymous","user_a","user_b","admin"],
  "test_count": 25,
  "tests": [{
    "id": "AZ-0001", "endpoint_id": "EP-0001",
    "method": "GET", "path": "/users/{id}",
    "owasp": "API1", "test_type": "BOLA",
    "procedure": "As user_a, request an object owned by user_b...",
    "expected": "denied",
    "result": null,       // Phase 3 fills: denied | allowed | error
    "evidence": null      // Phase 3 fills: request/response summary
  }]
}
```

### `api-findings.json` (Phases 2–6)

```jsonc
{
  "findings": [{
    "id": "FIND-0001", "owasp": "API1", "title": "BOLA on GET /orders/{id}",
    "endpoint_id": "EP-0007", "severity": "high",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "status": "confirmed",   // confirmed | suspected | ruled_out
    "confidence": "high",
    "evidence": "GET /orders/8842 with user_a token -> 200, user_b's order body",
    "reproduction": ["step 1", "step 2"],
    "remediation": "Enforce object ownership check server-side..."
  }]
}
```

---

## Stages

| Phase | Skill file | Gate(s) | Output |
|-------|-----------|---------|--------|
| 0 Inventory | `phase-0-inventory.md` | A2 | `api-inventory.json`, `authz-matrix.json` |
| 1 Recon | `phase-1-recon.md` | A1, A2 | role/object model, updated inventory |
| 2 Authn | `phase-2-authn.md` | A1, A4 | findings (API2) |
| 3 Authz | `phase-3-authz.md` | A3, A4, A6 | filled `authz-matrix.json`, findings |
| 4 Input | `phase-4-input.md` | A1, A4 | findings (API7 + injection) |
| 5 Logic | `phase-5-logic.md` | A1, A6 | findings (API4, API6) |
| 6 Config | `phase-6-config.md` | A4 | findings (API8, API10) |
| 7 Report | `phase-7-report.md` | A5 | `api-report.md` |

---

## Notice

This methodology is for authorized security testing, defensive assessment,
and security research only. Test only APIs you own or have explicit written
permission to assess.
