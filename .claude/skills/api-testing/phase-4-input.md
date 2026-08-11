---
name: api-testing-phase-4-input
description: Input validation, injection, and SSRF testing — schema-aware fuzzing from the spec plus targeted probes for SQL/NoSQL/command/SSTI injection, path traversal, XXE, and SSRF (OWASP API7).
user-invocable: false
---

# [PHASE 4] Input Validation, Injection & SSRF — API7 (+ injection classes)

**LLM-driven, active.** GATE-A1 authorization required. See `SKILL.md`.

## Goal

Find where untrusted input reaches a dangerous sink: injection, SSRF, traversal,
and deserialization. Drive this from the parsed inventory — every parameter and
body field is an input to test.

## Schema-aware fuzzing (spec-driven)

When an OpenAPI/GraphQL schema exists, fuzz from it — the schema tells the fuzzer
the exact shape, so it explores structure a blind fuzzer misses:
- **Schemathesis** — property-based fuzzing directly from OpenAPI/GraphQL.
- **RESTler** — stateful REST sequence fuzzing (infers request order).
- Feed each with valid auth so it reaches authenticated code paths.

## Injection classes (per parameter / body field)

- **SQL / NoSQL** — error-based and blind; for NoSQL, operator injection
  (`{"$ne": null}`, `{"$gt": ""}`) in JSON bodies.
- **Command injection** — shell metacharacters in fields reaching exec sinks.
- **SSTI** — template markers (`{{7*7}}`, `${7*7}`) in fields rendered server-side.
- **Path traversal / LFI** — `../` in file/path/name parameters.
- **XXE** — when the API accepts XML, external entity + parameter entities.
- **Deserialization** — language-native gadget payloads where objects are
  deserialized (Java/PHP/Python pickle/.NET).

## SSRF — API7 (priority)

Every parameter that takes a URL, hostname, or file reference is an SSRF
candidate — the inventory tags these (`owasp_focus` contains `API7`;
`url`/`uri`/`webhook`/`callback`/`redirect`/`image_url` names). Test:
- cloud metadata (`169.254.169.254`, GCP/Azure equivalents),
- internal hosts / `localhost` / link-local, and non-HTTP schemes
  (`file://`, `gopher://`, `dict://`),
- DNS-rebinding and redirect-based bypasses of allowlists,
- blind SSRF via an out-of-band collector (Burp Collaborator / interactsh).

## GraphQL-specific input

- Deeply nested / recursive queries (resource exhaustion → also API4).
- Injection through arguments; batching/aliasing to multiply work.
- Introspection exposure and field-suggestion information leaks.

## Output

Findings to `api-findings.json` (owasp `API7` for SSRF; use the closest CWE/OWASP
mapping for other injection). Each with the injected input and the observable
proof (error, out-of-band hit, reflected result). GATE-A4 applies.
