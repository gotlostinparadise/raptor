---
name: api-testing-phase-5-logic
description: Business-logic and resource-abuse testing — rate-limit bypass, sensitive-flow automation, and race conditions (OWASP API4 and API6). Treat as passive-only unless DoS-class testing is authorized.
user-invocable: false
---

# [PHASE 5] Business Logic & Resource Abuse — API4, API6

**LLM-driven, active — and the most authorization-sensitive to run.**
GATE-A1 + GATE-A6. Treat resource-exhaustion tests as **passive-only**
(analyse, do not execute) unless DoS-class testing is explicitly authorized.

## Goal

Abuse the API doing exactly what it was built to do, but faster, cheaper, or
out of intended order. These are logic flaws — no injection, no broken authz,
just intent the server failed to enforce. Scanners cannot find them.

## API6 — Unrestricted access to sensitive business flows

From the Phase 1 list of sensitive flows (checkout, signup, invite, password
reset, fund transfer, coupon redemption, rating/review):
- Can it be **automated at scale**? Missing anti-automation (no CAPTCHA, no
  velocity limit) on a flow that assumes human pace = API6.
- Concrete abuses: bulk account creation, coupon/referral farming, ticket/stock
  scalping, review flooding, resource reservation without commit.
- Test the flow **out of sequence** — skip a step, replay a completed step,
  re-use a one-time token.

## API4 — Unrestricted resource consumption

- **Rate-limit presence & bypass:** absent limits; per-key vs per-IP; bypass
  via header spoofing (`X-Forwarded-For`), rotating keys, or case/trailing-slash
  path variants. GraphQL **batching/aliasing** to multiply work under one request.
- **Cost amplification:** large `limit`/`page_size`, wide field expansion, deep
  GraphQL nesting, file-size/complexity with no ceiling. Reason about the
  amplification factor first; execute only within authorized limits.

## Race conditions (TOCTOU)

- Single-packet / parallel-request attacks (Burp **Turbo Intruder**) on
  balance-affecting flows: double-spend, coupon reuse, limit bypass, duplicate
  resource creation. Prove with two concurrent requests both succeeding where
  one should.
- GATE-A6: prove the race with a benign, reversible effect where possible.

## Output

Findings to `api-findings.json` (owasp `API4`/`API6`). For consumption findings
you did not execute, record the amplification analysis and mark
`status: suspected` with the reasoning — do not claim a DoS you did not (and
should not) run.
