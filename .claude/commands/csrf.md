---
description: Anti-CSRF-token-absence testing — replay a state-changing request first WITH its anti-CSRF token (a valid baseline) then with the token FIELD REMOVED; if the server still performs the operation, it does not validate an anti-CSRF token on that request (CWE-352, PROOF_STATE_ORACLE). A token-less request that is rejected means the token is enforced (no finding). Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-csrf --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /csrf

If a state-changing request succeeds without its anti-CSRF token, an attacker's
page can forge that request from the victim's browser. `/csrf` tests it directly:

1. **baseline** — send the request WITH the token → it must succeed (proves the
   request works and the baseline is valid);
2. **token removed** — send the same request with the token *field* stripped from
   the body → if it still succeeds, the token is not validated.

Confirmed on `(1) ∧ (2)` as `csrf` (CWE-352, `PROOF_STATE_ORACLE`). A token-less
request that is rejected means the token is enforced — no finding.

**Caveat (honest scope):** token-absence is the classic signal, but a SameSite
cookie can still block cross-origin exploitation. Pair with a `success_signature`
(so "success" means the state actually changed) and a manual cross-origin check to
judge real exploitability.

## AUTHORIZATION GATE

Active testing performs the state change (twice). Refused unless `--active` **and**
a non-empty `authorization` **and** a non-passive profile. Use a benign, reversible
change on an authorized target.

## Usage

```
/csrf --url http://dvwa --path /vulnerabilities/csrf/ \
  --body 'password_new=x&password_conf=x&Change=Change&user_token=T' \
  --token-field user_token --success-signature "Password Changed" \
  --authorization "eng Y" --active
```

## Config shape (`csrf.json`)

```jsonc
{
  "base_url": "http://dvwa.local",
  "path": "/vulnerabilities/csrf/",
  "method": "GET",
  "body": "password_new=x&password_conf=x&Change=Change&user_token=TOKEN",
  "token_field": "user_token",
  "success_signature": "Password Changed",
  "authorization": "engagement ACME-2026; written approval on file"
}
```

## Output

Under `$OUTPUT_DIR`: `csrf-findings.json`, `graph/web.json`, and verified outcomes
via `libexec/raptor-verified-outcomes $OUTPUT_DIR`.
