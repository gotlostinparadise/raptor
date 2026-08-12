---
description: Brute-force / rate-limit weakness testing — fire N FAILED authentication attempts (wrong credentials the operator supplies, so no account is accessed) and confirm the absence of brute-force protection when the target never locks out or throttles (no HTTP 429, no lockout/CAPTCHA signature) across N identically-processed failures. A counting oracle (PROOF_STATE_ORACLE, CWE-307) that records the exact tested threshold N. Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-bruteforce --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /bruteforce

An authentication endpoint with no rate-limit or lockout lets an attacker try
passwords indefinitely. `/bruteforce` fires **N failed** login attempts (the
operator supplies *wrong* credentials, so no account is ever accessed) and applies
a counting oracle:

- **No protection (confirmed)** — all N attempts were processed the same way, with
  no HTTP 429 and no lockout/rate-limit/CAPTCHA body signature. The observation is
  the proof (`PROOF_STATE_ORACLE`, CWE-307); the finding records the exact tested
  count N, so the claim is precisely "no lockout within N".
- **Protection present** — a lockout/throttle appeared at attempt K; K is reported
  and nothing is confirmed.

This mirrors the race detector: the verdict is a count over observed responses,
never a judgement.

## AUTHORIZATION GATE

Active testing sends N requests to the target. Refused unless `--active` **and** a
non-empty `authorization` **and** a non-passive profile. Without `--active` you get
a dry-run plan.

## Usage

```
/bruteforce --url https://x --login-url /rest/user/login \
  --body '{"email":"victim@x.com","password":"definitely-wrong"}' --json-body \
  --attempts 15 --authorization "eng Y" --active
```

## Config shape (`bruteforce.json`)

```jsonc
{
  "base_url": "https://app.example.com",
  "login_url": "/rest/user/login",
  "method": "POST",
  "attempts": 15,                       // failed attempts to fire
  "min_attempts": 10,                   // confirm "no lockout" only at/above this
  "body": "{\"email\":\"v@x.com\",\"password\":\"wrong\"}",
  "content_type": "json",
  "lockout_signatures": ["blocked"],    // extra body markers beyond the defaults
  "authorization": "engagement ACME-2026; written approval on file"
}
```

## Output

Under `$OUTPUT_DIR`: `bruteforce-findings.json`, `graph/web.json`, and verified
outcomes via `libexec/raptor-verified-outcomes $OUTPUT_DIR`.
