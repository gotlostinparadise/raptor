# Recon intelligence — the optional LLM layer

The recon **engine** is fully mechanical and stays that way: the orchestrator,
the source plugins, `dnsx`/`naabu`/`httpx`, and the graph builder are
deterministic, reproducible (`--rebuild`), auditable, and cheap to re-run. An LLM
in that hot path would trade all of those away for nothing — the tools already
enumerate/resolve/probe better than any model could.

The value an LLM adds is not *running* recon; it is the **judgment layer** a good
operator applies on top: what is even in scope, which of 500 hosts matter, what
to guess next, and what the graph *means*. This document specifies how that layer
attaches — at the edges, never in the engine — and the one non-negotiable rule
that keeps it safe.

---

## The principle: mechanical engine, LLM at the edges, verify-gate

> **The LLM proposes; a mechanical oracle verifies.**

This is the same seam RAPTOR already uses for payload selection
(`core/payloads/proposer.py`) and the web-pentest capabilities: the model only
ever produces a *proposal* — an ordering, a set of candidate names, a priority —
and a deterministic step decides what is real. Applied to recon:

| The LLM proposes… | The mechanical oracle that verifies it |
|---|---|
| candidate scope roots / ASNs | RDAP/whois/cert ownership + operator confirmation |
| bruteforce permutation candidates | `dnsx` — a name enters the graph only if it *resolves* |
| a priority ordering of discovered hosts | nothing to verify — it is advisory ranking over a set the engine already found |
| a narrative of the attack surface | every claim is a read of the mechanical graph |

The load-bearing guarantee: **the LLM can never inject an asset.** Where it
proposes *new* candidates (scope, permutations), those pass through a mechanical
verifier (`dnsx` resolution, ownership check) before they exist in the graph — a
hallucinated subdomain simply fails to resolve and is dropped. Where it only
*ranks or narrates*, it operates over the mechanically-discovered set and its
output is advisory. Either way a wrong model call wastes a request, never
corrupts the graph or the scan budget.

Everything here **degrades to mechanical** when no model is configured or a call
fails, so recon is fully functional offline and in CI.

---

## Where the LLM helps (ranked by value)

1. **Scope / acquisition mapping** *(implemented — `/recon-seed`,
   `core/recon/seed.py`)*. The fuzziest step: which apexes, ASNs, brands, and
   acquisitions belong to this org. The LLM proposes candidate roots →
   **operator confirms** (the verify-gate — scope is never auto-added) → the
   mechanical pipeline enumerates the confirmed ones. Horizontal enumeration by
   reasoning, not regex.
2. **Triage & ranking** *(implemented — `core/recon/triage.py`)*. Turn a flat
   list of hosts/services into a ranked worklist with rationale and a surface
   narrative. Read-only over the finished graph; zero target traffic.
3. **Permutation seeding** *(implemented — `core/recon/permute.py` →
   `bruteforce`)*. Feed the mechanical `bruteforce` source *target-specific*
   candidates derived from observed naming conventions, instead of only a generic
   wordlist. Output still goes through `dnsx` (the verify-gate). Enabled with
   `/recon --brute-model <name>`.
4. **Narrative / synthesis** *(folded into triage)*. "3 origin candidates behind
   DDoS-Guard, a staging API with no WAF, an exposed `.git`."
5. **Adaptive orchestration** *(implemented — `core/recon/strategist.py`)*.
   Strategic "what to run next" — wildcard found → skip bruteforce; DDoS-Guard →
   prioritise origin discovery. The *sources* stay mechanical and the strategist
   can only *select among already-registered sources*; the LLM makes the
   *escalation* decision. Enabled with `/recon --strategy-model <name>`.

All four LLM layers share one seam — `core/recon/llm.py:ask_structured`
(propose-only, injectable `ask=` for offline tests, `{}`-on-failure so every layer
degrades to its mechanical path). The related **workflow bridge** `/recon --full`
hands recon's discovered origins to the platform's `/webpentest`
(`core/recon/webpentest_bridge.py`) — infra recon → app pentest in one command.

Where the LLM is deliberately **excluded**: enumeration, resolution, port
scanning, HTTP probing, graph merge. Deterministic, cheap, reproducible.

---

## Layer 2 (implemented): triage & ranking

`core/recon/triage.py` is a **read-only** post-processing pass over a finished
recon run. It never touches the target and needs no active profile.

### Pipeline

1. **Extract** (`extract_candidates`) — walk `graph/recon.json`, emit one
   `Candidate` per host (root/subdomain), joined with the services it serves,
   its tech, whether it is behind an edge/WAF, and whether an IP flagged it an
   exposed origin. Pure function of the graph.
2. **Score** (`heuristic_score`) — a deterministic interest score from
   mechanical features: interesting name tokens (`admin`, `internal`, `vpn`,
   `jenkins`, `git`, `grafana`, `staging`, `dev`, `api`, `legacy`, …), a live
   HTTP service, an exposed-origin flag, a non-standard port, an interesting
   server/tech banner. This ordering is the **mechanical fallback and the
   floor**.
3. **Rerank** (`llm_rerank`, optional) — when `--model` is given, the LLM
   receives the candidate ids + their mechanical feature summaries and returns
   (a) an *ordering* of those ids and (b) a one-line rationale per id + a short
   surface narrative. Exactly as in the payload proposer: **ids it invents are
   dropped, ids it omits are appended in heuristic order** — so the worklist is
   always complete and only the *order/annotation* is model-adapted. The call is
   an injectable seam (`ask=`) so tests run offline; any failure falls back to
   the heuristic ordering.
4. **Emit** — `triage.json` (ranked targets with score, reasons, rationale, and
   the narrative) and `triage.md` (an operator-readable worklist).

### The constraint that makes it safe

Triage ranks a set the engine already discovered; the LLM cannot add a host,
cannot mark anything "vulnerable", and cannot remove coverage. The worst a bad
model does is mis-order the list — caught immediately by the operator, and the
mechanical score is always shown alongside.

### Interface

```
libexec/raptor-recon-triage --out-dir <recon-run> [--model <name>] [--top N] [--stdout]
/recon-triage <recon-run> [--model <name>]        # dispatch: libexec/raptor-recon-triage
```

No model → pure heuristic ranking (still useful, fully deterministic). With a
model → the same list, model-reordered and annotated, via
`core.llm.client.LLMClient.generate_structured` (the shared LLM stack, so cost
tracking / scorecard / caching all apply).

---

## Integration shape

- **Advisory layers that only read the graph** (triage, narrative) are standalone
  read-only commands — no `Source`, no target traffic, no profile gate.
- **Layers that propose new candidates** (scope seeding, permutation seeding)
  attach as `Source` plugins or a pre-pass whose output is fed to a mechanical
  verifier (`dnsx`, ownership). They inherit the existing egress/credential/
  active-gating contract; the LLM call itself goes through `core.llm` (egress to
  the model provider only, never the target).
- All LLM use is **opt-in** (`--model`/`--seed`); the default `/recon` is
  unchanged and mechanical.

## Cost, determinism, safety

- **Cost** is bounded and opt-in: one structured call per triage run (or per
  seed/permute pass), through the metered `LLMClient` (scorecard + caching).
- **Determinism** of the engine is preserved — the graph and `normalized/*.jsonl`
  are still a pure function of the mechanical sources; triage writes *separate*
  advisory artefacts (`triage.json`/`.md`) and never mutates them.
- **Safety**: the verify-gate means a hostile/hallucinating model cannot create
  phantom assets or assert findings. LLM egress is to the provider only. Scope
  proposals always require operator confirmation before any active enumeration.
