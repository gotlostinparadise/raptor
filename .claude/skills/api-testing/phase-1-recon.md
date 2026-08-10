---
name: api-testing-phase-1-recon
description: Reconnaissance and modelling — capture live traffic, provision multiple accounts per role, and capture real object ids for user_a and user_b so authorization testing is possible.
user-invocable: false
---

# [PHASE 1] Recon & Data/Role Modelling

**LLM-driven, active.** Requires GATE-A1 authorization. See `SKILL.md`.

## Goal

Turn the static inventory into a testable model: real accounts, real tokens,
real object ids. This is the phase that *makes Phase 3 possible* — most
failed BOLA testing fails here, not in Phase 3.

## Steps

1. **Capture traffic.** Drive the app/client through a proxy (Burp, ZAP,
   mitmproxy) and record real request/response pairs. Confirm the observed
   endpoints against `api-inventory.json`; add any not in the spec (API9).

2. **Provision accounts — ≥2 per privilege level.** At minimum:
   - `user_a` (attacker) and `user_b` (victim) at the same low privilege,
   - one `admin`/elevated account,
   - the `anonymous` (no token) case.
   Record each account's auth token and how it is carried (header, cookie).

3. **Capture object ids per account.** For every object-scoped endpoint in
   the inventory, log real ids owned by user_a *and* by user_b (order ids,
   user ids, document ids, ...). Note the id format — sequential integers,
   UUIDs, or hashids — this predicts BOLA enumerability.

4. **Model the data & roles.** Which objects belong to whom; which endpoints
   are meant to be admin-only; which flows are business-sensitive (checkout,
   invite, password reset, fund transfer) — these seed Phase 5 (API6).

5. **Recover hidden inputs.** Probe for undocumented parameters (Arjun/x8-style
   param mining, mass-assignment candidates) and undocumented methods. Add
   findings to the inventory; hidden params often bypass authz.

## Output

- Updated `api-inventory.json` (observed + shadow endpoints, hidden params).
- An account/role/object model: for each role, the token and the object ids
  it legitimately owns (store alongside the run; redact tokens in any report).
- A ranked list of business-sensitive flows for Phase 5.

## Gate

**GATE-A2:** inventory must be complete before Phase 2+. **GATE-A6:** use
non-destructive interactions to capture ids; do not mutate other tenants' data.
