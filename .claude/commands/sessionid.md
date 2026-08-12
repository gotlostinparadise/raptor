---
description: Weak / predictable session-identifier analysis — sample several issued session tokens and detect DETERMINISTIC weakness: reuse across sessions (CWE-384) or a predictable arithmetic sequence in decimal/hex/base64 (CWE-330). Hard signals confirm (PROOF_TOKEN_ANALYSIS); low entropy is reported SUSPECTED, never stamped confirmed. Safe by default (offline analysis sends nothing; live collection needs --active + declared authorization).
dispatch: libexec/raptor-sessionid --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /sessionid

If a session identifier is guessable, an attacker predicts a valid session and
hijacks the account — no credentials needed. `/sessionid` samples several issued
tokens and looks for **deterministic** weakness only:

- **Reuse** — the same identifier handed to different sessions (fixation / non-
  unique id). CWE-384.
- **Predictable sequence** — the identifiers form an arithmetic run (constant,
  non-zero delta) when parsed as integers in decimal, hex, or the big-endian
  integer of their base64/hex bytes. A constant delta across ≥3 samples is not
  plausibly coincidental for a random id. CWE-330.

Those confirm with `PROOF_TOKEN_ANALYSIS`. A merely **low-entropy** token is
reported *suspected* (an entropy threshold is a heuristic, and `confirmed` never
rests on one) so an operator can follow up.

## AUTHORIZATION GATE

Offline analysis of pre-observed tokens (`--token …`) sends nothing and always
runs. Live collection (`--collect-url` + `--cookie-name`/`--token-path`) requires
`--active` **and** a non-empty `authorization` **and** a non-passive profile.

## Usage

```
# offline: analyse tokens you already captured
/sessionid --url https://x --token 1001 --token 1002 --token 1003

# live: sample a fresh cookie N times and analyse
/sessionid --url https://x --collect-url /login --method POST --cookie-name session \
           --count 8 --authorization "eng Y" --active
```

## Config shape (`sessionid.json`)

```jsonc
{
  "base_url": "https://app.example.com",
  "collect_url": "/rest/user/login",
  "method": "POST",
  "count": 8,
  "cookie_name": "connect.sid",     // OR "token_path": "authentication.token"
  "authorization": "engagement ACME-2026; written approval on file"
}
```

## Output

Under `$OUTPUT_DIR`: `sessionid-findings.json`, `graph/web.json`, and verified
outcomes via `libexec/raptor-verified-outcomes $OUTPUT_DIR`.
