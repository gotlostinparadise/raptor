---
description: Build the application-layer request/traffic graph — origins, pages, forms, endpoints (as templated method+path nodes), parameters, identities, and findings — merged from API-spec import, crawl, and proxy capture into one (type,id) graph with captured request/response as evidence.
dispatch: libexec/raptor-webgraph --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /webgraph

The application-layer twin of the recon graph. Where `/censys` and the recon
pipeline model an organisation's *infrastructure* surface (domains, IPs, ASNs),
`/webgraph` models its *application* surface and is the connective tissue
between recon, API testing, and the web test capabilities: crawl, API-spec
import, and proxy capture all feed **one** `(type, id)` merge graph, so the same
endpoint discovered two ways lands on one node.

The load-bearing modelling choice: an **endpoint node is a template**
(`GET /api/users/{id}`), so the same route hit with different object ids merges
onto one node — which is exactly what makes BOLA/IDOR analysis a graph query
(one endpoint, one `accessible_as` edge per identity, each carrying the observed
request/response as evidence).

## Sources

- **API-spec import** (`--spec`) — offline, always safe. Bridges an
  OpenAPI/Swagger/Postman/GraphQL-introspection description (via the same parser
  `/api` Phase 0 uses) into `endpoint` + `parameter` + `origin` nodes.
- **DOM-aware browser crawl** (`--browser`) — active. Drives headless Chromium
  (Playwright) over the app's same-origin pages so client-side-rendered SPAs,
  runtime XHR/fetch endpoints, injected forms, and `postMessage` channels are
  discovered — the surface a static crawl is blind to. Egress is constrained to
  the in-scope origins' hosts via the allowlist proxy.
- **Static crawl / proxy capture** — additional active sources register
  automatically as they land. They send traffic to the target application and
  are gated by the safety profile + the authorization gate.

## Usage

```
/webgraph --spec openapi.yaml --base-url https://api.example.com   Import a spec (offline)
/webgraph --origins https://app.example.com --browser --profile safe  DOM-aware crawl (active)
/webgraph --spec openapi.yaml --browser --origins https://app.x     Spec + browser, one graph
/webgraph --rebuild                                                 Re-derive exports from records
/webgraph --spec schema.json --stdout                              Print the run summary as JSON
```

`--browser` requires Playwright + Chromium (`pip install playwright &&
playwright install chromium`); without them the command exits with an install
hint. `--allow-unproxied` permits browser navigation to a remote host with no
egress proxy (loopback fixtures / explicit opt-out) — otherwise a remote
navigation without an allowlist proxy is refused.

## Safety profiles

- `passive` — zero traffic to the target application; spec-import / offline only.
- `safe` (default) — authorised, throttled active testing (rps/concurrency capped).
- `aggressive` — higher rate + payload encoding/mutation to probe a WAF. Opt-in.

**Authorization:** active profiles send real requests to the target. Only run
`safe`/`aggressive` against a target you have written authorization to test.
Spec import (`passive`) is always safe.

## Output

Written under the run directory (`$OUTPUT_DIR`):

- `normalized/<kind>.jsonl` — one record per line; schema in `core/webgraph/model.py`
- `graph/web.json` / `web.dot` / `web.graphml` — the merged graph
- `webgraph-summary.json` — node/edge counts, sources run, record counts

The graph is a pure function of `normalized/*.jsonl`; `--rebuild` regenerates the
exports without re-touching the target. Feeds `/diagram` and the web test
capabilities (IDOR/BOLA, injection, GraphQL).
