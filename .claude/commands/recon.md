---
description: Build the infrastructure-layer recon graph — apex domains, subdomains, IPs, ASNs/orgs, services, TLS certs, and edge/WAF providers — from passive discovery (crt.sh, Censys, subfinder) and, when authorized, active enumeration (dnsx, naabu, httpx), merged into one (type,id) graph with a recursive discovery loop. --web also builds the app-layer graph from discovered origins.
dispatch: libexec/raptor-recon --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /recon

RAPTOR's infrastructure-layer discovery pipeline. Where `/webgraph` models an
application's *request* surface, `/recon` maps the *organisation's* external
footprint — every apex, subdomain, IP, ASN/org, open service, TLS certificate,
and CDN/WAF provider — into one typed `(type, id)` merge graph. A recursive
discovery loop feeds newly-found names/IPs back into the next round until the
asset set stops growing, so a cert SAN found by Censys becomes a name resolved by
dnsx becomes a service probed by httpx, all in one run.

It is the feeder for everything downstream: the discovered live origins hand off
to `/webgraph` (via `--web`), which the web-test capabilities (`/webauthz`,
`/inject`, `/graphql`, `/clientside`) consume.

## Sources

- **Passive** (always safe, run under every profile — zero traffic to the
  target): `crtsh` (Certificate Transparency), `censys` (asset lookups, cert
  SANs → origins), `subfinder` (aggregates ~dozens of passive APIs).
- **Active** (traffic to the target's own infrastructure — gated, see below):
  `dnsx` (resolve A/AAAA/CNAME), `naabu` (connect-scan open ports), `httpx`
  (HTTP probe + fingerprint + TLS grab).

Active tool wrappers are sandboxed: HTTP tools (httpx) run behind the
hostname-allowlisted egress proxy; DNS/port tools (dnsx, naabu) run
network-open but read-restricted (`$HOME`/credentials denied), with a
RAPTOR-built argv and rate/concurrency off the safety profile.

## Usage

```
/recon example.com --profile passive                          Passive only (no target traffic)
/recon example.com --profile home --active --authorization "…"  Rate-capped active enum
/recon --scope-file roots.txt --profile vps --active --authorization "…"  Heavy enum
/recon example.com --profile home --active --authorization "…" --web  + app-layer graph
/recon --rebuild                                              Re-derive exports from records
```

Roots are positional (repeatable) or via `--scope-file` (one per line).
`--seed-ips a,b,c` pre-loads IPs for passive enrichment (e.g. Censys) without an
active DNS stage. `--max-rounds N` bounds the discovery loop (default 3).

## Safety profiles & authorization gate

- `passive` — zero traffic to the target; third-party sources only. Always safe.
- `home` (default) — home-network-safe active enum: dnsx-only rate caps, few
  resolvers, no massdns fan-out.
- `vps` — VPS-grade: heavier resolver fan-out permitted, still throttled.

**Active testing sends real traffic to the target's infrastructure.** The `home`
and `vps` profiles therefore require BOTH `--active` and a non-empty
`--authorization "<written authorization>"`. Without them the command refuses and
exits non-zero. `passive` needs neither.

## Credentials

`censys` reads `CENSYS_API_KEY` (or a `.censys` file — see `/censys`);
`subfinder` reads its own provider config. Credential env vars are resolved
in-process and never exported to the sandboxed tool children.

## Output

Written under the run directory (`$OUTPUT_DIR`):

- `normalized/<kind>.jsonl` — one record per line; schema in `core/recon/model.py`
- `graph/recon.json` / `recon.dot` / `recon.graphml` — the merged graph
- `recon-summary.json` — node/edge counts, sources run, asset counts, records
- `web/…` — with `--web`, the app-layer graph (see `/webgraph`)

The graph is a pure function of `normalized/*.jsonl`; `--rebuild` regenerates the
exports without re-touching the target. Feeds `/diagram`, `/webgraph`, and the
web-test capabilities.
