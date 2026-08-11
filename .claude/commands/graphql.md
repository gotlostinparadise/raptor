---
description: GraphQL security testing — confirm introspection left open in production (information disclosure) and alias/batching DoS amplification. Argument injection is delegated to /inject and field-level authorization to /webauthz. Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-graphql --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /graphql

GraphQL is a distinct, fast-growing surface that generic web scanners miss.
`/graphql` confirms the two GraphQL-specific weaknesses:

- **Introspection enabled** in production — one query returns the whole schema
  (types, queries, mutations, arguments). Confirmed when the endpoint answers the
  introspection query with a schema; the schema itself is the evidence.
- **Alias / batching amplification** — a single request aliasing an expensive
  field N times multiplies server work. Confirmed when the server resolves all
  aliases instead of rejecting the document on a complexity/alias limit. This is
  resource-class, so it only runs with `--resource-tests`.

Two things are **delegated, not duplicated**:
- **Argument injection** → `/inject`. GraphQL fields land as endpoints in the
  graph, so `/inject --from-webgraph <dir>` targets their arguments with the full
  SQLi/SSTI/OAST oracle suite.
- **Field-level authorization** → `/webauthz`. A GraphQL query is a `POST /graphql`
  body; declare it as a test and the authz oracle replays it across identities.

## AUTHORIZATION GATE

Active testing sends requests to the target. Refused unless `--active` **and** the
config (or `--authorization`) declares a non-empty attestation **and** the profile
is not `passive`. Without `--active` you get a dry-run plan. The batching DoS
check additionally requires `--resource-tests` (resource-abuse is off by default).

## Usage

```
/graphql --url https://api.example.com/graphql                          # dry-run
/graphql --url https://api.example.com/graphql --authorization "eng Y" --active
/graphql --config graphql.json --active --resource-tests                # + DoS check
```

## Config shape (`graphql.json`)

```jsonc
{
  "base_url": "https://api.example.com",
  "path": "/graphql",
  "authorization": "engagement ACME-2026; written approval on file",
  "token_env": "TESTER_TOKEN",     // optional authenticated introspection
  "resource_tests": false,          // enable alias/batching DoS
  "dos_field": "products",          // field to alias (default: first query field)
  "dos_aliases": 100
}
```

## Output

Under `$OUTPUT_DIR`: `graphql-findings.json`, `graph/web.json` (findings as `vuln`
nodes), and verified outcomes via `libexec/raptor-verified-outcomes $OUTPUT_DIR`.
Egress is allowlisted to the target host.
