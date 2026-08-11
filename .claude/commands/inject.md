---
description: Deep injection testing with real oracles — SSTI, command injection, SQLi (error + blind boolean), NoSQLi, path traversal, and SSRF (cloud-metadata + blind via OAST). Every finding is tool-confirmed (computed marker, DB error signature, boolean asymmetry, metadata content, or out-of-band callback), never an LLM guess. Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-inject --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /inject

Goes beyond the OWASP heuristic pass with **oracle-verified** injection testing.
Each vulnerability class carries a payload whose *effect* a matching oracle can
observe, so a finding is only recorded when a tool — not the model — confirms it:

| Class | Oracle (the proof) |
|---|---|
| SSTI | a **computed** marker (`{{191*193}}` → `36863`) appears in the response |
| Command injection | an echoed unique marker appears (execution, not reflection) |
| SQLi (error) | a database error signature in the body |
| SQLi / NoSQLi (blind) | boolean asymmetry: true-payload ≈ baseline, false-payload diverges |
| Path traversal | leaked file content (`root:…`) in the response |
| SSRF → metadata | cloud-metadata content returned |
| SSRF / XXE / blind RCE / OOB-SQLi | an **OAST callback** correlated to the payload |

Blind classes need an OAST collaborator (`--oast-domain`, optionally
`--oast-poll-url`); without one they are skipped. Confirmed findings become
proven `vuln` nodes (`PROOF_REFLECTED_MARKER` / `PROOF_OAST_CALLBACK`) in the
graph and verified outcomes.

## AUTHORIZATION GATE (read first)

Active testing sends real (benign, non-destructive) payloads to the target. It is
refused unless you pass `--active` **and** the config declares a non-empty
`authorization` attestation **and** the profile is not `passive`. Without
`--active` you get a dry-run plan and nothing is sent. If you are unsure you have
written authorization, run the dry-run only.

## Usage

```
# Targets from a config:
/inject --config injection.json                       # dry-run plan
/inject --config injection.json --active              # send payloads

# Targets harvested from a prior /webgraph run:
/inject --from-webgraph out/webgraph_run --base-url https://api.example.com \
        --authorization "engagement ACME-2026" --active

# Enable blind classes with an OAST collaborator:
/inject --config injection.json --active \
        --oast-domain oast.example.com --oast-poll-url https://collector/poll
```

## Config shape (`injection.json`)

```jsonc
{
  "base_url": "https://api.example.com",
  "authorization": "engagement ACME-2026; written approval on file",
  "token_env": "TESTER_TOKEN",            // optional: authenticated injection
  "classes": ["ssti", "sqli", "cmdi", "ssrf"],   // omit for all
  "points": [
    {"method": "GET",  "path": "/search",       "param": "q",    "location": "query"},
    {"method": "POST", "path": "/render",        "param": "tpl",  "location": "body", "content_type": "json"}
  ]
}
```

## Output

Under `$OUTPUT_DIR`: `injection-findings.json`, `graph/web.json` (confirmed
findings as `vuln` nodes), and verified outcomes via
`libexec/raptor-verified-outcomes $OUTPUT_DIR`. Egress is allowlisted to the
target host. Pairs naturally with `/webgraph` (map first, then `--from-webgraph`).
