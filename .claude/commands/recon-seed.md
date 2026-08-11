---
description: Propose reconnaissance scope candidates for an org — apex domains, brands, and ASNs (including likely acquisitions) that an LLM proposes with a confidence + rationale. Operator-gated: it writes a reviewable scope-proposal.json and NEVER scans; you confirm ownership/authorization before feeding confirmed roots to /recon.
dispatch: libexec/raptor-recon-seed --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /recon-seed

The scope/acquisition-mapping layer above `/recon` (recon-intelligence.md layer
1). The hardest recon question — *what's even in scope?* — is where an LLM's
world knowledge helps: which apex domains, brands, and ASNs plausibly belong to
the org, including acquisitions and regional variants a wordlist never finds.

**Operator-gated by design.** Scope is a legal/authorization matter, so a
proposed root is **never auto-scanned**. `/recon-seed` only writes a reviewable
`scope-proposal.json`; you confirm each candidate, then feed the confirmed roots
to `/recon` (`--scope-file` or `--save-scope`). Every candidate carries a
confidence + rationale so you can judge it. See `docs/recon-intelligence.md`.

## Usage

```
/recon-seed --org "Acme Corp" --model gemini-2.5-pro
/recon-seed --org "Acme" --seed acme.com --seed acme.io --model claude-opus-4-8
/recon-seed --org "Acme" --model <name> --stdout
```

`--org` (required) is the target organisation; `--seed` (repeatable) supplies
domains/brands already known in-scope to anchor the proposal; `--model`
(required) — scope proposal is inherently the LLM's job.

## Output

Written under the run directory (`$OUTPUT_DIR`):

- `scope-proposal.json` — candidates, each with `domain` / `kind`
  (apex|brand|asn) / `confidence` / `rationale`, plus a `note` that this is a
  proposal, not scope.

## Workflow

```
/recon-seed --org "Acme" --seed acme.com --model <name>   # propose
#  → review scope-proposal.json, confirm ownership/authorization
/recon --scope-file confirmed-roots.txt --profile home --active --authorization "…"
```

The LLM only *proposes*; the operator is the verify-gate. Nothing is enumerated
until you confirm and run `/recon` on the confirmed roots.
