---
description: Nuclei template scan plus tech→CVE correlation over the recon graph's fingerprints. tech→CVE is offline and always runs (results are suspected indicators); nuclei runs sandboxed when installed and authorized, its matches recorded as confirmed findings. Degrades gracefully when nuclei is absent. Safe by default (nuclei run needs --active + declared authorization).
dispatch: libexec/raptor-nuclei --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /nuclei

Cheap, high-signal coverage that reuses fingerprints RAPTOR already has:

- **tech → CVE** — cross-references the recon graph's `tech` nodes (server
  software, frameworks, libraries) against a curated table of flagship CVEs.
  Offline, always runs. A version match is an **indicator, not a proof**, so
  these land as **suspected** `vuln` nodes — to be confirmed by `/inject`, a
  nuclei template, or manual work. RAPTOR never marks a version-string guess as
  verified.
- **nuclei** — when the `nuclei` binary is installed and testing is authorized,
  runs it (sandboxed, egress-allowlisted to the target) and ingests its matches
  as **confirmed** findings + verified outcomes. When nuclei is absent the command
  says so and the tech→CVE pass still runs.

## AUTHORIZATION GATE

The nuclei run sends real requests to the target and is refused unless `--active`
**and** a declared `authorization` **and** a non-passive profile. The tech→CVE
correlation reads a local graph and sends nothing, so it runs in dry-run too.

## Usage

```
# tech→CVE only (offline), from a prior recon run's graph:
/nuclei --recon-graph out/recon/graph/recon.json

# nuclei scan of a target (needs the binary + authorization):
/nuclei --target https://app.example.com --authorization "eng Y" --active --tags cve,exposure

# both, from a config:
/nuclei --config nuclei.json --active
```

## Config shape (`nuclei.json`)

```jsonc
{
  "target": "https://app.example.com",
  "authorization": "engagement ACME-2026; written approval on file",
  "recon_graph": "out/recon/graph/recon.json",
  "tags": ["cve", "exposure"],
  "severity": ["medium", "high", "critical"]
}
```

## Output

Under `$OUTPUT_DIR`: `nuclei-findings.json`, `graph/web.json` (suspected tech→CVE
+ confirmed nuclei `vuln` nodes), and verified outcomes (confirmed only) via
`libexec/raptor-verified-outcomes $OUTPUT_DIR`.
