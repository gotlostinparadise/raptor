# Recon / OSINT enrichment

`core/recon/` holds reusable, run-agnostic enrichment sources. A module
here takes assets RAPTOR already knows about — IPs, hostnames,
certificate hashes — and enriches them from an external source. It does
not own the run directory, the graph, or the report: callers pass assets
in and write the returned records wherever they want.

Every outbound call in this package goes through `core.http` with an
explicit hostname allowlist, so the in-process egress proxy
(`core.sandbox.proxy`) refuses CONNECT to anything else. A compromised
response parser cannot exfiltrate to an attacker host.

---

## The pipeline (`/recon`, `libexec/raptor-recon`)

`core/recon/` is not just enrichment sources — it is a full graph-native,
recursive discovery pipeline. The engine (`core/recon/orchestrator.py`)
schedules every registered `Source`, runs a fixed-point discovery loop, persists
`normalized/<kind>.jsonl`, and serialises `graph/recon.{json,dot,graphml}`. It is
the infrastructure twin of `core/webgraph/orchestrator.py` and shares its
"records are the source of truth" discipline — `--rebuild` re-derives the graph
exports from disk without re-touching the target.

### The discovery loop

`run_recon(roots, out_dir, …)` seeds an `Assets` set with the scope roots, then
runs each available source per round, merging every source's `discovered`
identity (names / IPs / cert fingerprints) back into the set. It re-runs while
the set grows (bounded by `--max-rounds`, default 3) and stops at the fixed
point. Node-merge on `(type, id)` makes a re-run idempotent, so a cert SAN found
by Censys becomes a name resolved by dnsx becomes a service probed by httpx — all
in one run.

### Sources

| Source | Kind | `active` | Sandbox | Produces |
|---|---|---|---|---|
| `crtsh` | CT logs (in-process HTTP) | no | egress allowlist | `subdomains` |
| `censys` | asset lookups (in-process HTTP) | no | egress allowlist | `hosts`, `ports`, `certs` |
| `subfinder` | passive-API aggregator (binary) | no | net-open / read-restricted | `subdomains` |
| `dnsx` | resolve A/AAAA/CNAME (binary) | **yes** | net-open / read-restricted (UDP/53) | `dns` |
| `bruteforce` | wordlist DNS bruteforce via dnsx (binary) | **yes** | net-open / read-restricted | `subdomains`, `dns` |
| `naabu` | connect port scan (binary) | **yes** | net-open / read-restricted | `ports` |
| `httpx` | HTTP probe + fingerprint + TLS (binary) | **yes** | egress proxy (host-allowlist) | `http`, `tls` |
| `exposed_origin` | WAF-bypass origin probe (`curl --resolve`) | **yes** | net-open / read-restricted | `origin` |
| `vhost` | Host-header vhost probe (`curl --resolve`) | **yes** | net-open / read-restricted | `vhost` |

`bruteforce` needs an operator-supplied wordlist (`RAPTOR_DNS_WORDLIST` or
`wordlist=`); it no-ops when absent. `exposed_origin` / `vhost` port the
prototype's `curl --resolve` fingerprint + verdict rules (a candidate is
`reachable_vhost` / `exposed_origin` only when it serves a real 2xx page distinct
from the default vhost and not an edge/WAF challenge); the fingerprint primitive
is `core/recon/probe.py` and both take an injectable `prober=` seam for offline
tests.

`core/recon/registry.py:load_sources()` imports every source module so the
registry is populated before a run (a `@register` fires on import).

### Sandboxing the active tools

Active sources shell out to external binaries via `core/recon/toolrunner.py`,
which holds two modes because the kernel primitives don't compose one way:

- **HTTP-layer tools** (`httpx`) run behind the hostname-allowlisted HTTPS egress
  proxy (`run_untrusted_networked`): the allowlist is exactly the in-scope names
  being probed. UDP is blocked and TCP is pinned to the proxy port.
- **DNS / port tools** (`subfinder`, `dnsx`, `naabu`) use UDP/53 and (for the
  scanner) arbitrary TCP, neither of which can traverse an HTTP CONNECT proxy.
  They run network-open but `restrict_reads=True` (`$HOME`/credentials denied)
  with resource rlimits and a sanitised env. Host-level egress allowlisting is
  not achievable for raw DNS/SYN; the compensating control is that the argv is
  built by RAPTOR from in-scope roots (never attacker input) and the tool's
  stdout is parsed in-process — the trust boundary is the parser.

`toolrunner` is also the offline-test seam: a source takes `runner=` defaulting
to the real sandbox helper, and tests inject a fake that returns canned stdout —
so nothing here touches the sandbox or the network in CI.

### Safety profiles & the authorization gate

Profiles (`core/recon/source.py:PROFILES`): `passive` (zero target traffic),
`home` (rate-capped active, default), `vps` (heavier fan-out). Passive sources
run under every profile; active sources are gated **twice** — by the profile
(`passive` drops them) and by an explicit `--active` + non-empty
`--authorization` attestation at the CLI, mirroring the web capabilities' gate.
Throttle knobs (`dns_rate`, `dns_threads`, `http_rate`, …) live on the profile
and the wrappers read them off `ctx.profile.knobs`.

### The infra → app bridge

`--web` calls `core/recon/webbridge.py:build_web_graph`, which reads the run's
`http` records, derives canonical origins, and hands them to
`core/webgraph/orchestrator.py:run_webgraph` under `<run>/web/` — so the infra
graph and the app graph share one lifecycle run dir. It forwards optional
`session=`/`oast=` handles into `run_webgraph`'s slots (a bare `/recon --web`
passes none; a caller with a `/webauthz` identity config supplies them). Recon
profiles map to webgraph profiles `passive→passive`, `home→safe`, `vps→aggressive`.

`--web --url-history` additionally opts into the passive
`core/webgraph/url_history.py:UrlHistorySource` — the pure-Python `gau`/
`waybackurls` analogue that mines `web.archive.org` for historical endpoints,
parameters, and pages (egress-allowlisted to the archive). It is **not**
auto-registered: it has no availability gate, so it would otherwise run — and
contact a third party — in every web run; the bridge/CLI instantiate it
explicitly only when asked.

### Authenticated crawl

`--web --browser` runs the DOM-aware `BrowserCrawlSource` over the discovered
origins. Add `--authz-config <file>` (a `/webauthz` identity config) and the
bridge builds a logged-in `core/session/engine.py:SessionEngine` (via
`core/webauthz/runner.py:build_engine`) and passes it as `run_webgraph`'s
`session=` — the crawl then reaches the authenticated surface where BOLA/BFLA
live. `core/browser/auth.py` is the seam: `resolve_identity` picks the identity
(named, or the first authenticated one) and `context_args_for_identity` converts
its auth headers + cookie jar into Playwright context args
(`new_session(extra_http_headers=…, cookies=…)`); an `IdentityRecord` is stamped
so the graph records which identity the crawl ran as. Both conversion helpers are
pure (no Playwright) and unit-tested; the crawl wiring is covered via a fake
harness. No config / no engine ⇒ an anonymous crawl, unchanged.

### Persisted scope

`/recon` with no roots falls back to the active project's `recon_scope`
(`core/project/project.py`, schema v4) — `{"roots": [...], "profile": "home"}`,
set via `ProjectManager.set_recon_scope(...)` and modelled on the `binaries`
field. Explicit CLI roots / `--profile` always win.

---

## Censys (`core/recon/censys.py`, `/censys`, `libexec/raptor-censys`)

Censys Platform asset enrichment, **free-tier compatible**.

### Two entry points, one implementation

`CensysSource` is the `core.recon.source` plugin the orchestrator
schedules. The functions it wraps (`resolve_api_key`, `CensysClient`,
`parse_host`, `enrich_hosts`) stay directly usable as a library — that
is what `libexec/raptor-censys` calls, so the CLI works standalone
without an orchestrator or a run context.

The plugin declares its contract and normalises output:

| Declaration | Value |
|---|---|
| `egress_hosts` | `("api.platform.censys.io",)` |
| `credential_env_vars` | `("CENSYS_API_KEY",)` |
| `consumes` | `("ips",)` |
| `produces` | `("hosts", "ports", "certs")` |
| `active` | `False` — traffic goes to Censys, never the target, so it runs in every profile including `passive` |

It emits records only; it builds no graph edges. The builder constructs
`exposes` / `cert_origin` edges from the `ports` and `certs` records.
In-scope certificate names also land in `discovered.names`, feeding the
next round of the discovery loop.

`CensysSource.delay` (default `FREE_TIER_DELAY_SECONDS`) is
instance-settable, so a paid key or a test can drop the pace without
monkeypatching `time.sleep`.

Availability differs from the base class on purpose. The default
`has_credentials` only consults `ctx.credentials`, which would make an
operator's `$RAPTOR_DIR/.censys` invisible to the scheduler — Censys
would be silently skipped as "unavailable" despite a working key on
disk. `CensysSource` overrides it to consult the full documented
credential order.

### Why lookup and not search

The free tier cannot use the bulk `/search/query` endpoint — it is paid
and requires an organization ID. It *can* use the per-asset LOOKUP
endpoints with nothing but an API key:

```
GET /v3/global/asset/host/{ip}
GET /v3/global/asset/certificate/{sha256}
GET /v3/global/asset/web-property/{id}
```

So the design is **enrich known assets**, not search. Feed it the IPs a
DNS sweep already resolved and it tells you what Censys has observed
there.

### Two constraints that are load-bearing

1. **A non-default User-Agent is mandatory.** The API sits behind
   Cloudflare, which returns `403` (error 1010) for the stdlib default
   `Python-urllib` UA. `CENSYS_USER_AGENT` is sent on every request.
   Removing it breaks every call with an error that does not mention
   the UA.
2. **No organization ID.** Lookups authenticate with
   `Authorization: Bearer censys_…` alone. Anything that demands an org
   ID is a paid search endpoint and is out of scope.

Lookups are serial with a ~0.6s pace (`FREE_TIER_DELAY_SECONDS`). The
`core.http` retry/backoff/circuit-breaker handles 429s on top of that.

### Credentials

Resolution order (`resolve_api_key`):

1. `CENSYS_API_KEY` in the environment
2. `RAPTOR_CENSYS_CREDENTIALS` → path to a credentials file
3. `$RAPTOR_DIR/.censys` (only when `RAPTOR_DIR` is set)
4. `~/.config/raptor/censys`

Files hold a single `API_KEY="censys_…"` line. Missing credentials raise
`MissingCredential`, whose message names the locations searched and
never a value.

The key is held only in the `Authorization` header built per call. It is
never logged, never written to a record, and never interpolated into an
error string — `core.http` does not log request headers and sanitises
URLs in its messages. `CENSYS_API_KEY` is deliberately **not** in
`RaptorConfig.SAFE_ENV_ALLOWLIST`, so `get_safe_env()` strips it from
any subprocess environment; this module makes its calls in-process and
never hands the key to a child.

### Output schema

`censys-hosts.jsonl` — one JSON object per line:

| Field | Type | Meaning |
|---|---|---|
| `ip` | string | The host address (Censys-reported, falling back to the requested one) |
| `services` | array | Observed services, see below |
| `names` | array of string | In-scope DNS names on TLS certificates served by this host |
| `asn` | int \| null | Autonomous system number |
| `org` | string \| null | AS name, falling back to the whois organization |
| `country` | string \| null | Geolocated country |
| `city` | string \| null | Geolocated city |
| `presents_domain_cert` | bool | Censys observed a leaf certificate for an in-scope name here — an origin candidate |

Each entry in `services`:

| Field | Type | Meaning |
|---|---|---|
| `port` | int \| null | Port number |
| `proto` | string \| null | Application protocol, falling back to transport protocol |
| `software` | string \| null | First product (or vendor) attributed to the service |

`censys-newnames.txt` — the union of `names` across all hosts, one per
line, sorted.

This schema is stable, and grows additively only — consumers read it
with `.get()`, so a new field never breaks an existing builder. `city`
was added after the initial cut for exactly that reason: the normalised
`HostRecord` already carried the field from the ipinfo path, and filling
it from Censys lets records from the two sources merge.

### Scope matching

`in_scope()` is label-aware: `example.com` matches `example.com` and
`a.b.example.com`, but not `notexample.com` or `example.com.evil.net`.
A bare suffix check would inject out-of-scope hosts into the graph.
Wildcard labels are stripped, so a `*.example.com` SAN is recorded as
`example.com`.

### Library use

```python
from core.recon import censys

result = censys.enrich_hosts(ips, ["example.com"])
censys.write_jsonl(out_dir / "censys-hosts.jsonl", result.hosts)
```

Or via the plugin, with a `RunContext` from the orchestrator:

```python
from core.recon.source import get_source

result = get_source("censys")().run(ctx)
```

`enrich_hosts` accepts a `client=` argument — the injection seam tests
use to run fully offline; the plugin path uses `ctx.http_factory` for
the same purpose. `EnrichmentResult` carries `hosts`, `names`,
`requested`, `failed`, and a `service_count` property.

A single failed lookup (403, 404, 429, 5xx) yields `None` and is
recorded in `failed`; enrichment continues. Censys not having seen a
host is the normal case, not an error.

### Tests

`core/recon/tests/test_censys.py` runs fully offline against a stub
`HttpClient` — both the library functions and the plugin, the latter
through a `RunContext` with an injected `http_factory`. No test starts
the egress proxy or touches the network, so there is nothing to
deselect in CI.
