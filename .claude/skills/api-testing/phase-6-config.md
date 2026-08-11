---
name: api-testing-phase-6-config
description: Configuration and unsafe-consumption testing — CORS, security headers, error verbosity, TLS, HTTP methods (API8), and trust in upstream/third-party APIs (API10).
user-invocable: false
---

# [PHASE 6] Configuration & Unsafe Consumption — API8, API10

**LLM-driven.** Mostly passive; GATE-A4 for any active probe. See `SKILL.md`.

## API8 — Security misconfiguration

- **CORS:** reflected `Origin`, `Access-Control-Allow-Origin: *` with
  credentials, `null` origin acceptance, weak subdomain regex.
- **Security headers:** missing `Strict-Transport-Security`,
  `X-Content-Type-Options`, `Content-Security-Policy`; permissive caching of
  sensitive responses.
- **Verbose errors:** stack traces, framework/version banners, SQL errors, file
  paths leaked in error bodies. Trigger malformed input and read the error.
- **HTTP methods & surface:** `TRACE`/`OPTIONS` enabled; debug/actuator/swagger
  endpoints exposed (`/actuator`, `/swagger-ui`, `/graphql` playground,
  `/.env`, `/debug`); default credentials on admin surfaces.
- **TLS:** protocol/cipher downgrade, missing HSTS, mixed content.

## API10 — Unsafe consumption of APIs

The target consuming *other* APIs is a trust boundary too:
- Does it blindly trust redirects/data from upstream/third-party services?
- Injection or SSRF via data fetched from an integrated API and reflected into
  a sink (webhooks, OAuth userinfo, payment callbacks, imported feeds).
- Insufficient validation of upstream TLS, schemas, or response size.

## Method

Most checks are passive (headers, error bodies, exposed paths) and safe to run
even in spec-only mode where a live host is reachable read-only. Use the
inventory to target: exposed non-app paths and any endpoint whose behaviour
depends on a third-party response (API10).

## Output

Findings to `api-findings.json` (owasp `API8`/`API10`) with the response
evidence (header dump, error body excerpt, exposed-path response). GATE-A4.
