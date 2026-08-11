---
description: Client-side / configuration testing — CORS misconfiguration, CSP weaknesses, clickjacking, insecure cookie flags, and open redirects. Each finding is read straight off the wire (reflected CORS origin, unsafe-inline CSP, framable page, missing Secure/HttpOnly/SameSite, external redirect target). Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-clientside --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /clientside

The client-side and configuration weakness class — the findings that live in HTTP
headers and redirect behaviour, confirmed by the response evidence, not by an LLM:

| Check | Confirmed when |
|---|---|
| CORS misconfiguration | `Access-Control-Allow-Origin` reflects an attacker origin (worse with credentials), is `null`, or `*` + credentials |
| CSP weakness | missing CSP, or `script-src`/`default-src` allows `'unsafe-inline'` / `'unsafe-eval'` / `*` |
| Clickjacking | neither `X-Frame-Options` nor CSP `frame-ancestors` is set (page is framable) |
| Cookie flags | a `Set-Cookie` missing `Secure` / `HttpOnly` / `SameSite` |
| Open redirect | a redirect parameter sends the browser to an external marker host |

## AUTHORIZATION GATE

The probes are benign (a header, a redirect parameter), but active testing still
requires `--active` **and** a declared `authorization` **and** a non-passive
profile. Without `--active` you get a dry-run plan and nothing is sent.

## Usage

```
/clientside --url https://app.example.com                             # dry-run
/clientside --url https://app.example.com --authorization "eng Y" --active
/clientside --config clientside.json --active
```

## Config shape (`clientside.json`)

```jsonc
{
  "base_url": "https://app.example.com",
  "authorization": "engagement ACME-2026; written approval on file",
  "paths": ["/", "/login"],                       // pages to probe for redirects
  "redirect_params": ["url", "redirect", "next"]  // params to test (defaults provided)
}
```

## Output

Under `$OUTPUT_DIR`: `clientside-findings.json`, `graph/web.json` (findings as
`vuln` nodes), and verified outcomes via `libexec/raptor-verified-outcomes
$OUTPUT_DIR`. Egress is allowlisted to the target host.
