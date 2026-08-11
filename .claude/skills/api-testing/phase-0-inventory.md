---
name: api-testing-phase-0-inventory
description: Build the mechanical API endpoint inventory and seed authorization matrix from an OpenAPI/Swagger spec, Postman collection, or GraphQL introspection result — the ground truth for every later phase.
user-invocable: false
---

# [PHASE 0] Inventory & Discovery — API9

**Mechanical.** Turn an API description into ground truth. See `SKILL.md`
for gates and schemas.

## Goal

Enumerate the full documented surface and pre-compute where authorization
bugs are most likely, so later phases test a parsed list instead of guessing.
Attacks API9 (Improper Inventory Management) at the same time: the diff
between documented and observed endpoints *is* the shadow-API finding.

## Run the parser

If a description file exists (spec, Postman, or GraphQL introspection):

```bash
libexec/raptor-api-inventory --spec <file> --out-dir "$OUTPUT_DIR" [--base-url <url>] [--roles <roles>]
```

Writes `api-inventory.json` (normalised endpoints) and `authz-matrix.json`
(seed BOLA/BFLA/property test rows). It is offline and deterministic.

**No spec?** Skip the parser. Build the inventory during Phase 1 recon from
observed traffic, then hand-write `api-inventory.json` in the same schema so
later phases and the authz matrix still have ground truth.

**GraphQL with introspection disabled?** Note it (a hardening signal, not a
blocker), then recover the schema in Phase 1 (field suggestions, `clairvoyance`-
style probing, or captured client queries) and build the inventory from that.

## Read the output — orient before testing

From `api-inventory.json`, note the three counts that shape effort:
- `object_scoped_count` → the Phase 3 BOLA workload (API1).
- `privileged_count` → the Phase 3 BFLA workload (API5).
- `no_auth_count` → endpoints reachable unauthenticated — check each is
  *meant* to be public (a no-auth object-scoped endpoint is an instant lead).

Skim `owasp_focus` per endpoint: `API7` tags on a `url`/`webhook`/`callback`
parameter are your Phase 4 SSRF targets; `API3` tags mark mutating endpoints
whose body may accept privileged fields.

## Shadow / undocumented surface (API9)

The spec is a claim, not the truth. Queue for Phase 1:
- version siblings (`/v1`→`/v2`, `/internal`, `/beta`, `/debug`),
- undocumented methods on documented paths (try `OPTIONS`, `PUT`, `DELETE`),
- endpoints referenced only in client JS/mobile bundles,
- deprecated/zombie endpoints still live.

Record documented-vs-observed drift; each undocumented live endpoint is an
API9 finding and gets folded into the inventory (extend `api-inventory.json`).

## Gate

**GATE-A2 [INVENTORY-FIRST]:** No active testing until this inventory exists.
Coverage claims (GATE-A5) are measured against it.

## Output

- `api-inventory.json` — normalised endpoints (+ counts, OWASP focus).
- `authz-matrix.json` — seed authorization test rows for Phase 3.
