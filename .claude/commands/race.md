---
description: Business-logic and race-condition testing — fire N identical requests simultaneously (single-packet-attack approximation) and apply a state oracle. If a limited operation (single-use coupon, one withdrawal, stock decrement) succeeds more times than it should, the limit is not atomic — a confirmed TOCTOU race. Safe by default (dry-run unless --active + declared authorization; concurrency hard-capped).
dispatch: libexec/raptor-race --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /race

The flaws scanners miss most: TOCTOU races (double-spend, coupon reuse,
stock/limit bypass) and workflow abuse. These live in *timing* and *state*, not
in a single response — so `/race` fires many identical requests at once and
verdicts with a **state oracle**:

> If a limited operation succeeds **more times than the operator says it should**,
> the limit is not atomic — a confirmed race.

The verdict is a count, not a judgement (`PROOF_STATE_ORACLE`): you declare the
operation and its `expected_max` (usually 1), and RAPTOR reports how many of N
concurrent attempts actually succeeded.

## AUTHORIZATION GATE

Active testing fires real concurrent requests at the target. Refused unless
`--active` **and** a declared `authorization` **and** a non-passive profile.
Concurrency is hard-capped (`max_concurrency`, default 50) to avoid accidental
load. Without `--active` you get a dry-run plan.

## Usage

```
/race --config race.json                 # dry-run plan
/race --config race.json --active        # fire the concurrent requests
```

## Config shape (`race.json`)

```jsonc
{
  "base_url": "https://shop.example.com",
  "authorization": "engagement ACME-2026; written approval on file",
  "token_env": "TESTER_TOKEN",            // optional bearer token
  "max_concurrency": 50,
  "tests": [
    {
      "id": "RACE-1",
      "method": "POST",
      "path": "/coupon/redeem",
      "body": "code=SAVE10",              // form body (or content_type: "json")
      "concurrency": 30,                  // simultaneous requests
      "expected_max": 1,                  // how many SHOULD succeed
      "success_signature": "redeemed"     // body marker for a SUCCESSFUL operation
    }
  ]
}
```

**`success_signature` (needed to confirm):** a `2xx` alone does **not** prove the
operation succeeded — many apps return `200` with a rejection body (`{"error":"already
redeemed"}`) for the losing racers. Set `success_signature` to a marker that appears
only on a genuinely successful operation. Without it, an apparent race is reported as
**suspected** (never a verified outcome), since the success count can't be trusted.
For a success that redirects (`302`), set `success_status` accordingly.

## Output

Under `$OUTPUT_DIR`: `race-findings.json` (per-test success counts), `graph/web.json`
(confirmed races as `vuln` nodes), and verified outcomes via
`libexec/raptor-verified-outcomes $OUTPUT_DIR`. Egress is allowlisted to the target.
