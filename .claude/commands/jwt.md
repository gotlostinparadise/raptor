---
description: JWT forgery testing — confirm a token signature bypass (alg:none or a brute-forced weak HMAC secret) via a forged-token-accepted A/B oracle. A forgery is a finding only when a corrupted-signature control is rejected (endpoint validates) AND the forgery is accepted. Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-jwt --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /jwt

JWTs are the bearer of identity for most modern APIs, and two implementation
mistakes hand an attacker any identity they like. `/jwt` confirms them mechanically
against one protected endpoint plus one known-valid token:

- **`alg:none`** — the RFC's "unsecured JWS". A library that honours it accepts a
  token with *no signature*, so every claim is attacker-controlled. `/jwt` emits
  the case-variants (`none`/`None`/`NONE`/`nOnE`) libraries have historically
  mis-matched.
- **Weak HMAC secret** — if the token is `HS*`, `/jwt` brutes a small wordlist
  against the token's own signature; a hit means it can mint arbitrary tokens, so
  it re-signs a **tampered** payload (e.g. `role: admin`) with the recovered secret.

## The oracle (why it never false-positives)

A forgery is confirmed only when three observations line up on the protected
endpoint:

1. **baseline** — the *real* token is accepted (2xx): the endpoint is genuinely
   protected and reachable;
2. **negative control** — a token with a *corrupted signature* is **rejected**:
   the endpoint actually validates signatures;
3. **forgery** — our forged token is **accepted**.

Only `(1) ∧ ¬(2) ∧ (3)` confirms — carrying `PROOF_TOKEN_FORGED` (CWE-347). An
endpoint that accepts the corrupted control is reported as **broken/absent auth**,
not a JWT forgery — a different class, never stamped as a signature bypass.

## AUTHORIZATION GATE

Active testing sends requests to the target. Refused unless `--active` **and** the
config (or `--authorization`) declares a non-empty attestation **and** the profile
is not `passive`. Without `--active` you get a dry-run plan (the token is analysed
and the forgeries are listed, but nothing is sent).

## Usage

```
/jwt --url https://api.example.com --token <JWT>                          # dry-run
/jwt --url https://api.example.com --protected-path /rest/user/whoami \
     --token-env JWT --tamper '{"role":"admin"}' --authorization "eng Y" --active
/jwt --config jwt.json --active
```

## Config shape (`jwt.json`)

```jsonc
{
  "base_url": "https://api.example.com",
  "protected_path": "/rest/user/whoami",   // endpoint requiring a valid token
  "method": "GET",
  "token": "eyJhbGciOi...",                 // a known-valid token (or "token_env")
  "token_env": "TESTER_JWT",
  "header_name": "Authorization",           // how the token rides on the request
  "scheme": "Bearer",
  "tamper": { "role": "admin" },            // claim escalations applied to forgeries
  "secrets": ["myapp"],                     // extra weak-secret candidates
  "authorization": "engagement ACME-2026; written approval on file"
}
```

## Output

Under `$OUTPUT_DIR`: `jwt-findings.json`, `graph/web.json` (confirmations as `vuln`
nodes), and verified outcomes via `libexec/raptor-verified-outcomes $OUTPUT_DIR`.
Egress is allowlisted to the target host.
