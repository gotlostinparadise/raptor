---
description: WAF-aware testing — fingerprint the WAF fronting a target (Cloudflare, Akamai, Imperva, AWS WAF, F5, ModSecurity, Sucuri, DDoS-Guard, FortiWeb) and generate payload-evasion variants (URL/double-URL encoding, case toggling, comment splitting, whitespace/null-byte tricks). Detection needs --active + authorization; mutation is offline.
dispatch: libexec/raptor-waf $ARGUMENTS
---

# /waf

The cross-cutting defensive-lessons layer. Knowing a WAF fronts the target
changes the pacing envelope (rate limits, IP bans) and whether payload evasion is
worth attempting — the same lesson RAPTOR learned defensively (DDoS-Guard
fronting bitpapa), applied to testing.

- **Detection** (`--url … --active`) — one benign GET, fingerprinted against
  server headers, cookies, body phrases, and block-status codes.
- **Evasion mutations** (`--mutate PAYLOAD`) — offline. Emits encoded/mutated
  variants of a payload (URL and double-URL encoding, keyword case-toggling, SQL
  comment splitting, whitespace/null-byte tricks). The injection runner can
  resend each and keep whichever the oracle still confirms — the effect is
  unchanged, only the surface form differs.

Rate/concurrency **pacing** itself lives on the web-graph safety profile
(`rps` / `concurrency` / `waf_evasion` knobs on `passive`/`safe`/`aggressive`).

## Usage

```
/waf --mutate "' UNION SELECT 1"                              # offline, always safe
/waf --url https://app.example.com --active --authorization "engagement Y"
```

Detection sends a request, so it requires `--active` **and** `--authorization`.
Mutation is offline and needs neither.
