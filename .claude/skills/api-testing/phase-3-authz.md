---
name: api-testing-phase-3-authz
description: Authorization testing — the core of API pentesting. Execute the seed matrix for BOLA (API1), property-level/mass-assignment (API3), and BFLA (API5) using cross-account request replay.
user-invocable: false
---

# [PHASE 3] Authorization — API1, API3, API5 (CORE)

**LLM-driven, active. The highest-value phase — budget the most time here.**
GATE-A1 authorization + GATE-A3 (execute the matrix, don't skim). See `SKILL.md`.

## Why this phase dominates

Authorization is per-object and intent-dependent, so scanners cannot find it —
only cross-account replay with real ids can. BOLA (API1) is the #1 API risk.
These bugs are why APIs get breached.

## Inputs

- `authz-matrix.json` — the seed rows (BOLA/BFLA/property) from Phase 0.
- The account/object model from Phase 1 — tokens and real ids for user_a
  (attacker) and user_b (victim).

Execute every row. Fill `result` (`denied`|`allowed`|`error`) and `evidence`
back into `authz-matrix.json`. `allowed` where `expected: denied` is a finding.

## API1 — BOLA (object-level)

For each object-scoped endpoint: take a request that works for user_a, then
**swap the object id to one owned by user_b** while keeping user_a's token.

- `200` + user_b's data = **BOLA confirmed**.
- Also test: id in path, query, body, and headers; numeric enumeration if ids
  are sequential; UUID leakage via other endpoints; wrapped ids (base64/hashid);
  and the anonymous case (no token at all).
- **Automate** the replay across the whole object-scoped set — this is exactly
  what Burp **Autorize**/**AuthMatrix** do: replay user_a's requests with
  user_b's session and flag anything not rejected.

## API5 — BFLA (function-level)

For each privileged endpoint: call it with a **low-privilege (user_a) token**.

- Expect `403`. A `2xx` = **BFLA confirmed** (vertical privilege escalation).
- **Method tampering:** try `GET`→`PUT`/`DELETE`/`PATCH` on the same route;
  authz is often enforced per-method, unevenly.
- Try admin routes discovered in Phase 1 that the low-priv account should
  never reach.

## API3 — Property-level (mass assignment / excessive exposure)

For each mutating endpoint with a request body:

- **Mass assignment:** add privileged fields the docs omit — `role`,
  `is_admin`, `verified`, `owner_id`, `balance`, `price`. If the server
  honours them, that is **API3**.
- **Excessive data exposure:** inspect responses for fields the client filters
  but the API returns (password hashes, tokens, other users' PII, internal
  flags). The server, not the client, must filter.

## Evidence & safety

- GATE-A4: each finding needs a reproducible request/response pair.
- GATE-A6: prove non-destructively. For DELETE/mutation, prefer proving the
  *authz gap* (e.g. the victim can no longer read an object user_a modified via
  a benign field) over destroying real data. Never wipe another tenant's data
  to score a bug.

## Output

- `authz-matrix.json` fully filled (`result` + `evidence` per row).
- Findings to `api-findings.json` (owasp `API1`/`API3`/`API5`) with CVSS
  vectors — BOLA/BFLA on sensitive objects are typically High/Critical.
