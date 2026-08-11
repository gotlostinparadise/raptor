---
name: api-testing-phase-2-authn
description: Authentication testing — JWT algorithm/signature attacks, OAuth/OIDC flow flaws, and API-key/session weaknesses (OWASP API2).
user-invocable: false
---

# [PHASE 2] Authentication — API2

**LLM-driven, active.** GATE-A1 authorization required. See `SKILL.md`.

## Goal

Break or bypass identity establishment: forge tokens, downgrade signatures,
abuse OAuth flows, or brute weak credentials/keys.

## JWT (when tokens are JWTs)

- **`alg:none`** — strip the signature, set `"alg":"none"`, see if accepted.
- **Algorithm confusion** — RS256→HS256, signing with the public key as the
  HMAC secret (server verifies HMAC with a key it treats as public).
- **Weak secret** — crack HS256 secrets offline (`jwt_tool`, `hashcat`
  mode 16500). A cracked secret = arbitrary token forgery.
- **`kid` injection** — path traversal / SQLi in the `kid` header to control
  the verification key.
- **Claim tampering** — change `sub`, `role`, `scope`, `aud`; re-sign if a
  key was recovered. Test expiry (`exp`) enforcement and token replay.

## OAuth 2.0 / OIDC (when present)

- `redirect_uri` validation (open redirect, path/subdomain confusion).
- Missing/weak `state` (CSRF on the callback) and PKCE downgrade.
- Token leakage via `Referer`/logs; implicit-flow token exposure.
- Scope escalation; refresh-token rotation and revocation.
- Reference: IETF OAuth 2.0 Security BCP (RFC 9700) / OAuth 2.1.

## API keys / sessions

- Brute-force / credential-stuffing protection (rate limits, lockout).
- Key entropy, rotation, revocation; keys accepted in URL/query (logged).
- Session fixation, cookie flags (`HttpOnly`, `Secure`, `SameSite`).

## Method

For each authenticated endpoint in the inventory: attempt access with (a) no
token, (b) an expired token, (c) a tampered token, (d) another user's token.
Any non-401/403 that returns protected data is a finding.

## Output

Findings to `api-findings.json` (owasp `API2`), each with a request/response
pair proving the bypass (GATE-A4). Redact live secrets; show token *structure*,
not usable credentials.
