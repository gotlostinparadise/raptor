---
description: App-layer content discovery — mine JavaScript for endpoints and (redacted) leaked secrets, probe sensitive paths (.git/.env/backups/debug endpoints) with content signatures, and recover source maps. Discovered endpoints feed the web graph; leaks become proven findings. Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-discover --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /discover

Finds the surface a crawl alone misses: endpoints buried in JavaScript, secrets
committed into front-end bundles, sensitive files left exposed, and original
source recoverable from source maps.

| Check | What it finds |
|---|---|
| JS endpoint mining | `fetch`/`axios`/URL literals in linked + inline JS → endpoint nodes in the graph |
| JS secret scanning | AWS/Google/Slack/GitHub/Stripe keys, JWTs, private keys, generic `api_key=…` — **stored redacted** (preview + fingerprint, never the raw value) |
| Exposed files | `.git/config`, `.env`, DB dumps, `wp-config.php.bak`, `actuator/env`, `.aws/credentials`, … confirmed by a **content signature** (not just a 200) |
| Source maps | `//# sourceMappingURL` → recover the `sources` list (original file paths leaked) |

Confirmed leaks become proven `vuln` nodes and verified outcomes; discovered
endpoints flow into `/webgraph` for the injection / authz commands to target.

## AUTHORIZATION GATE

Active discovery fetches pages and probes paths on the target. Refused unless
`--active` **and** a declared `authorization` **and** a non-passive profile.
Without `--active` you get a dry-run plan.

## Usage

```
/discover --url https://app.example.com                               # dry-run
/discover --url https://app.example.com --authorization "eng Y" --active
/discover --config discovery.json --active --no-exposed               # skip file probes
```

## Output

Under `$OUTPUT_DIR`: `discovery-findings.json`, `graph/web.json` (discovered
endpoints + leak `vuln` nodes), and verified outcomes via
`libexec/raptor-verified-outcomes $OUTPUT_DIR`. Egress is allowlisted to the
target host. Secrets are never written verbatim.
