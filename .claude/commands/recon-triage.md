---
description: Rank a finished recon run's discovered hosts into an attack-worthy worklist — deterministic interest scoring (interesting name tokens, live HTTP, exposed-origin, non-standard ports, tech banners), optionally reordered and annotated by an LLM. Read-only advisory pass; never touches the target.
dispatch: libexec/raptor-recon-triage $ARGUMENTS
---

# /recon-triage

The read-only intelligence layer over `/recon`. A recon run produces a flat graph
of hosts, services, and origins; this ranks them into an **attack-worthy
worklist** so you attack the `admin.staging.internal-api` before the
`cdn-asset-42`. It reads the finished graph only — no traffic to the target, no
active profile needed.

## How it ranks

1. **Mechanical score (the floor, deterministic):** interesting name tokens
   (`admin`, `internal`, `vpn`, `jenkins`, `git`, `grafana`, `staging`, `dev`,
   `api`, `legacy`, …), a live HTTP service, an exposed-origin flag, non-standard
   ports, and an interesting server/tech banner.
2. **LLM rerank (optional, `--model`):** the model receives the candidate ids +
   their signals and returns an ordering + a one-line rationale per host + a
   short surface narrative. It can **only reorder a set the engine already
   discovered** — ids it invents are dropped, ids it omits are appended in
   heuristic order, and it can never mark anything vulnerable. No model ⇒ pure
   heuristic ranking. See `docs/recon-intelligence.md`.

## Usage

```
/recon-triage <recon-run-dir>                          Heuristic ranking (offline, deterministic)
/recon-triage <recon-run-dir> --model gemini-2.5-pro   LLM-reordered + annotated + narrative
/recon-triage --out-dir <recon-run-dir> --top 25       Top 25 only
/recon-triage <recon-run-dir> --stdout                 Print the summary as JSON
```

Point it at a directory a previous `/recon` wrote (the one containing
`graph/recon.json`).

## Output

Written into the run dir:

- `triage.json` — ranked targets with score, signals, rationale, and the narrative
- `triage.md` — an operator-readable worklist

The LLM call goes through RAPTOR's shared LLM stack (`core.llm.client`), so cost
tracking, the scorecard, and caching all apply. The pass is advisory: it writes
separate artefacts and never mutates the mechanical graph or `normalized/*.jsonl`.
