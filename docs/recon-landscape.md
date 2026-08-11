# Recon landscape — frameworks, tools, methodology, materials

A reference and roadmap for building RAPTOR's web / bug-bounty recon workflow.
It maps the external ecosystem onto RAPTOR's own model so that every entry has
an obvious home: a `core.recon.source.Source` plugin (infra graph), a
`core.webgraph.source` plugin (app graph), a wordlist under `seeds/`, or a
methodology checklist that drives ordering and coverage.

RAPTOR is not adopting a recon framework — it is building one. So the value of
the ecosystem is threefold:

1. **Prior-art frameworks** — architectures to validate against and steal from.
2. **A tool / data-source menu** — each entry is a candidate `Source` plugin.
3. **Methodology & standards** — the *ordering and coverage* logic, encoded as
   checklists and the recursive discovery loop.

> Freshness: compiled from knowledge current to ~Jan 2026. This space moves
> fast — treat the tool lists as a starting menu and re-verify specific tools /
> APIs before wiring them in. The curated indexes under *Living references*
> are the way to stay current.

---

## 1. How this maps onto RAPTOR

RAPTOR already has the bones of a graph-native, recursive recon framework:

| RAPTOR module | Layer | What it models |
|---|---|---|
| `core/recon/` | infrastructure | roots, subdomains, IPs, ASN/org, services, tech, edge providers (CDN/WAF/cloud) |
| `core/webgraph/` | application | origins, pages, endpoints (as method+path **templates**), parameters, forms, identities, vulns |
| `core/browser/` | app crawl | headless crawl + request/response capture |
| `core/oast/` | out-of-band | interactsh-style OOB interaction backend |
| `core/session/` | identity | multi-identity login, cookie jar, replay, authz diff |

Two architectural choices here are load-bearing and independently validated by
the prior art:

- **The recursive `Assets` fixed-point loop** (`core/recon/source.py`) — diff
  the known asset set before/after a round, recurse until nothing new appears.
  This is exactly BBOT's event-driven recursion and Amass's enumeration loop.
- **Endpoint-as-template keying** (`core/webgraph/model.py`) —
  `GET /api/users/{id}` is one node; the same route hit with different object
  ids merges, so BOLA/BFLA analysis becomes a graph query (one endpoint, an
  `accessible_as` edge per identity).

Every tool / API below is framed as: *what `Source` does it become, and which
node/edge kinds does it feed?*

---

## 2. Framework prior art — steal architecture, not just tools

| Framework | What to learn from it |
|---|---|
| **BBOT** (blacklanternsecurity) | Closest philosophical match. Event-driven, **recursive** engine where modules emit/consume typed events (`DNS_NAME`, `IP_ADDRESS`, `URL`, `FINDING`…) — almost exactly RAPTOR's `consumes`/`produces` + `Assets` fixed-point. Read its module interface as validation that the RAPTOR design is right. |
| **Amass** (OWASP) | The graph-native ancestor. Persists an asset graph; passive + active + permutation + ASN; recursive. Its data model *is* `core/recon/model.py`. `intel` vs `enum` = RAPTOR's passive/active split. |
| **reconFTW** | Not architecture — the **coverage checklist as executable bash**. The canonical "what stages exist, in what order." Read it as a spec for which sources are missing. |
| **reNgine / Osmedeus / Trickest** | Orchestration + scan-engine-as-config. Osmedeus's workflow model and Trickest's node graph show how operators compose stages declaratively. |
| **ProjectDiscovery suite** | Not a framework but a toolchain *designed to pipe*: `subfinder → dnsx → naabu → httpx → katana → nuclei`, each JSON-in/JSON-out. This is the Unix-y model RAPTOR's `Source` plugins already follow. |
| **Sn1per / Vajra / rengine** | Broader "one-button" recon; useful mainly as coverage cross-checks. |

---

## 3. The tool menu, mapped to pipeline stages

Each entry is a `Source` candidate. **active** = touches the target's own
infra (gated by `Source.active`; the `passive` profile runs none of them).
**passive** = traffic goes to a third party, never the target.

### 3.1 Seed / scope / ASN (passive)
`asnmap`, `metabigor`, `amass intel`, bgp.he.net, RIPEstat, BGPView, ipinfo.
→ `NODE_ORG`, `announced_by`, netblocks.

### 3.2 Passive subdomain discovery
- **`subfinder`** — aggregates ~40 passive APIs (SecurityTrails, VirusTotal,
  Chaos, etc.). Wrapping this one tool buys most of the passive DNS ecosystem
  behind RAPTOR's egress allowlist. **Highest leverage single source.**
- `amass`, `assetfinder`, `findomain`, `github-subdomains`, `chaos` (PD dataset).
- CT logs: crt.sh *(✓ implemented)*, certspotter, Censys *(✓ implemented)*.
- Search engines / scan DBs: FOFA, ZoomEye, Netlas, BinaryEdge, Quake,
  FullHunt, Onyphe, LeakIX, GreyNoise, Shodan.

→ `NODE_SUBDOMAIN`, `has_subdomain`; cert names → `discovered.names` (next loop round).

### 3.3 Active DNS resolve / bruteforce (active)
`dnsx` *(✓ proto'd)*, `puredns` + `massdns`, `shuffledns`.
Permutation / altname generation: `gotator`, `dnsgen`, `ripgen`, `altdns` —
the "expand what you found" step the recursive loop wants.

### 3.4 Port / service (active)
`naabu` *(✓ proto'd)*, `masscan`, `rustscan`, `nmap` (`-sV` service/software →
`NODE_SERVICE` / `uses`).

### 3.5 HTTP probe / fingerprint (active)
`httpx` *(✓ proto'd)*, `fingerprintx`, `wappalyzer` / `webanalyze`, `whatweb`.
→ origins + `NODE_TECH`. **This is the bridge from infra graph to app graph.**

### 3.6 Eyeball / triage
`gowitness`, `aquatone`, `eyewitness` — screenshots for human triage
(candidate thumbnail artifact).

### 3.7 URL history / crawl → webgraph *(biggest current gap)*
- Active crawl: `katana`, `gospider`, `hakrawler`.
- Passive URL history: `gau`, `waybackurls`, `waymore`, `urlfinder`
  (Wayback + CommonCrawl + URLScan + OTX + VirusTotal).

→ `NODE_ENDPOINT`, `NODE_PAGE`, `NODE_PARAMETER`. Historical URLs are the single
richest endpoint source and need no new model work.

### 3.8 Content / parameter discovery (active)
Content: `ffuf`, `feroxbuster`, `dirsearch`, `gobuster`.
Parameters: `arjun`, `x8`, `paramspider` → `NODE_PARAMETER` (directly powers
BOLA/BFLA authz queries).

### 3.9 JS mining
`jsluice` (best — extracts URLs *and* secrets structurally), `LinkFinder`,
`getJS`, `subjs`, `mantra`, `secretfinder`. → endpoints + parameters + secret findings.

### 3.10 Templated vuln findings
`nuclei` → `NODE_VULN` / `vulnerable_to` edges directly. The natural "finding
source" that turns the graph into something that ends in findings.

### 3.11 Secrets / code
`trufflehog`, `gitleaks`, GitHub code-search dorks, `git-dumper`.

### 3.12 Cloud / storage / origin
`cloud_enum`, `s3scanner`, `gcpbucketbrute`; `cdncheck` (CDN/WAF detection —
pairs with the `exposed-origin` probe for WAF-bypass origin discovery).

### 3.13 Out-of-band
`interactsh` (RAPTOR's `core/oast` is the in-house equivalent), Burp Collaborator.

### 3.14 Wordlists (a dependency, not a tool)
SecLists, **Assetnote wordlists** (best-in-class, data-derived), commonspeak2,
Jhaddix `all.txt`, fuzzing wordlists. `seeds/` is the right home — pin them as a
versioned manifest with provenance.

---

## 4. Data sources / APIs — the passive enrichment layer

These are what RAPTOR's passive `Source` plugins wrap. Grouped by kind, since
one plugin per category (or `subfinder` as an aggregator) covers most of it.

| Category | Sources |
|---|---|
| Certificate transparency | crt.sh *(✓)*, certspotter, Google CT, Censys *(✓)* |
| Passive DNS | SecurityTrails, VirusTotal, PassiveTotal, Farsight DNSDB, Robtex, HackerTarget |
| Internet-wide scan | Shodan, Censys *(✓)*, FOFA, ZoomEye, Netlas, BinaryEdge, Quake, FullHunt, Onyphe, GreyNoise, Hunter, LeakIX |
| ASN / BGP | bgp.he.net, RIPEstat, ipinfo, BGPView, `asnmap` |
| Subdomain datasets | Chaos (ProjectDiscovery) |
| URL history | Wayback Machine, CommonCrawl, URLScan, AlienVault OTX |
| Code / secrets | GitHub code search, GitLab search |

Every one of these fits the existing `core/recon` contract: declare
`egress_hosts`, declare `credential_env_vars`, set `active = False`, declare
`consumes` / `produces`. The Censys plugin (`core/recon/censys.py`) is the
reference implementation.

---

## 5. Methodology & standards — the ordering / coverage logic

- **OWASP WSTG** (Web Security Testing Guide) — authoritative test-case
  taxonomy. `WSTG-INFO-*` is literally the recon / information-gathering
  checklist. Encode these as coverage items.
- **OWASP ASVS** — verification requirements; turns "did we cover X?" into gates.
- **OWASP API Security Top 10 (2023)** — already the spine of `/api`; the app
  graph's endpoint/identity model exists to serve it.
- **PTES** (Intelligence Gathering) & **NIST SP 800-115** — the standards veneer
  for reporting; PTES's OSINT levels are a maturity model.
- **MITRE ATT&CK Reconnaissance (TA0043)** — tag each source with a technique
  (T1595 active scanning, T1590 gather network info, T1596 search open technical
  DBs). Good for provenance and reporting.
- **The Bug Hunter's Methodology (TBHM)** — Jason Haddix. The reference for
  offensive recon workflow ordering (scope → acquisition → analysis →
  recursion). His recursion model = RAPTOR's `Assets` fixed-point.
- **TomNomNom philosophy** — small composable JSON-piping tools. RAPTOR's
  `Source` contract already embodies this.
- Practitioner methodologies worth reading: NahamSec, Assetnote research
  (wordlists + recon posts), Orange Tsai, Ben Sadeghipour, Codingo.

---

## 6. Books

| Book | Why for *this* |
|---|---|
| **The Web Application Hacker's Handbook**, 2e (Stuttard & Pinto) | Canonical app → attack-surface mapping. "Mapping the application" ≈ the webgraph. |
| **Bug Bounty Bootcamp** (Vickie Li) | Best single modern recon-through-reporting workflow book. |
| **Real-World Bug Hunting** (Peter Yaworski) | Report-driven; shows which recon surfaces become bugs. |
| **The Hacker Playbook 2 & 3** (Peter Kim) | Practical recon + chaining playbooks. |
| **OSINT Techniques** (Michael Bazzell) | The passive-enrichment bible — data sources to wrap. |
| **The Tangled Web** (Michal Zalewski) | Browser security model — grounds `core/browser` + app-graph trust boundaries. |
| **Penetration Testing** (Georgia Weidman) | Methodology fundamentals. |
| **The Browser Hacker's Handbook** | Client-side surface, for the crawl/capture layer. |

---

## 7. Living references — how to stay current

- **PortSwigger Web Security Academy** — free; gold standard for the *vuln
  classes* the webgraph should hunt.
- **HackTricks** + **PayloadsAllTheThings** — living methodology wikis;
  source-of-truth for "what checks exist."
- **awesome-bugbounty-tools**, **awesome-hacker-search-engines**,
  **awesome-oast** — curated indexes to mine for new `Source` candidates.
- **ProjectDiscovery blog**, **Assetnote research**, **PentesterLand /
  InfoSec Writeups**, **HackerOne Hacktivity** (disclosed reports) — for
  keeping the source list current.

---

## 8. Roadmap — highest-leverage additions for RAPTOR

Ordered by ratio of coverage gained to code written, against the current gaps.

1. **`subfinder` as one passive Source** — instantly ~40 passive-DNS/CT APIs
   behind the existing egress-allowlist model. Best ratio in the list.
2. **URL-history sources (`gau` / `waymore` + `katana`) → `core/webgraph`** —
   the app graph is currently fed by spec/crawl/proxy only; historical URLs are
   the richest endpoint source and need no new model work.
3. **`nuclei` as a webgraph finding Source** — clean fit to `NODE_VULN` /
   `vulnerable_to`; turns the graph into something that ends in findings.
4. **`jsluice` Source** — endpoints + parameters + secrets from JS,
   structurally. Feeds both graphs.
5. **Permutation stage (`gotator` / `ripgen`)** in the recursive loop — the
   `Assets` fixed-point is the perfect home; permutation is what finds the long tail.
6. **`arjun` / `x8` parameter discovery** → `NODE_PARAMETER`, which directly
   powers the BOLA/BFLA authz queries in `core/session`.
7. **Wordlist manifest in `seeds/`** — pin SecLists + Assetnote as versioned
   dependencies with provenance.

**Structural note.** The infra graph and app graph are both well-developed; the
under-built seam is the **bridge between them** — origin discovery → HTTP probe
→ crawl → endpoints. The bitpapa prototype's `httpx` / `exposed-origin` stubs
need to become first-class sources so infra assets flow into the app graph
automatically. Sections 3.5 (HTTP probe) and 3.7 (crawl / URL history) are that
bridge.
