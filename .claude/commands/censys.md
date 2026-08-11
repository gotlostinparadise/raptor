---
description: Enrich known IPs with Censys asset data — open ports, service software, ASN/org/geo, and TLS certificate names that reveal new subdomains. Free-tier compatible; no bulk search.
dispatch: libexec/raptor-censys --run-dir $OUTPUT_DIR
---

# /censys

Ask Censys what it has seen on IPs RAPTOR already discovered. This is
**enrichment, not discovery**: it takes a host list and adds observed
surface to it — ports and service software Censys has banner data for
(SSH, admin panels, and other things a web-only sweep misses), the
owning ASN/org/country, and the DNS names on any TLS certificate served
there.

Certificate SANs are the high-value output: a SAN inside your scope
roots is a subdomain, and an IP presenting a real leaf certificate for
the target domain is an origin candidate behind whatever CDN fronts it.

## Free tier

The Censys free tier cannot use the bulk `/search/query` endpoint — it
is paid and requires an organization ID. It *can* use the per-asset
LOOKUP endpoints with only an API key, which is all this command uses.
Lookups are serial and paced (~0.6s apart) to stay inside free-tier
limits.

## Usage

```
/censys                                  Enrich the active run's raw/ips.txt
/censys --domain example.com             Mark cert SANs under example.com in-scope
/censys --ips hosts.txt --out-dir ./raw  Explicit input and output
/censys --ip 203.0.113.10 --stdout       One-off lookup, JSONL to stdout
```

`--domain` is repeatable and controls scope matching for certificate
names; matching is label-aware, so `example.com` will not match
`notexample.com`. Without it you still get ports, software, and ASN
data, but no subdomain extraction.

## Credentials

Set `CENSYS_API_KEY`, or write `API_KEY="censys_…"` to one of
`$RAPTOR_CENSYS_CREDENTIALS`, `$RAPTOR_DIR/.censys`, or
`~/.config/raptor/censys`. No organization ID is needed. The key is
never printed, logged, or written to output, and it is not in the
`get_safe_env()` allowlist, so it is stripped from subprocess
environments.

Without a key the command exits non-zero with a message naming the
locations it searched.

## Output

Written under `--out-dir` (default `<run-dir>/raw`):

- `censys-hosts.jsonl` — one record per host, schema in `docs/recon.md`
- `censys-newnames.txt` — union of in-scope certificate names

The record schema is stable and consumed directly by graph and report
builders. Egress is allowlisted to `api.platform.censys.io` through the
in-process proxy; see `docs/recon.md`.
