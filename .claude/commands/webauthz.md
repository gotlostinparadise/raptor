---
description: Access-control testing (IDOR/BOLA/BFLA, OWASP API1/API5) via multi-identity replay — replays each request as user A vs B vs anonymous and lets the response diff, not an LLM, confirm broken access control. Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-webauthz --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /webauthz

Broken access control is the **#1 web and API risk**, and the one scanners
cannot find — because deciding whether access *should* have been allowed needs
ground truth only the operator has: which identity legitimately owns which
object. `/webauthz` takes that ground truth and turns it into a mechanical test.

You declare identities (each authenticated by an **env-var reference**, never a
literal secret) and concrete test cases — a request, and the identity that
legitimately owns the object it touches. The command replays that exact request
as every other identity (and anonymous) through RAPTOR's session engine and runs
the **authorization diff**: if an identity that should be denied instead gets the
*same resource back* (identical response-body hash as the owner), that is a
confirmed horizontal break. **The verdict is the tool's, not the LLM's** — and it
is proven (`PROOF_AUTHZ_DIFF`), landing as a verified outcome.

## AUTHORIZATION GATE (read first, every active run)

Active testing sends **real requests** to the target. It is refused unless:

1. you pass `--active`, **and**
2. the config declares a non-empty `authorization` attestation (recorded on every
   proof), **and**
3. the profile is not `passive`.

Without `--active` you get a **dry-run**: the test plan + the surface graph, and
**nothing is sent**. If you are unsure whether you have written authorization to
test the target, STOP — run the dry-run only.

## Usage

```
# 1. Seed a config from the mechanical API inventory (/api Phase 0), offline:
/webauthz --init --inventory api-inventory.json

# 2. Fill in real object ids, credential env-var names, and `authorization`.
#    Then dry-run (no traffic) to review the plan:
/webauthz --config authz-config.json

# 3. Run it for real (sends traffic; requires authorization in the config):
/webauthz --config authz-config.json --active --profile safe
```

## Config shape (`authz-config.json`)

```jsonc
{
  "base_url": "https://api.example.com",
  "authorization": "engagement ACME-2026; written approval on file",  // REQUIRED for --active
  "identities": [
    {"name": "user_a", "role": "user",  "login": {"type": "bearer", "token_env": "USER_A_TOKEN"}},
    {"name": "user_b", "role": "user",  "login": {"type": "bearer", "token_env": "USER_B_TOKEN"}},
    {"name": "admin",  "role": "admin", "login": {"type": "bearer", "token_env": "ADMIN_TOKEN"}}
  ],
  "tests": [
    {"id": "AZ-1", "method": "GET", "path": "/api/orders/1001", "owner": "user_a",
     "class": "bola", "owasp": "API1", "others": ["user_b", "anonymous"],
     "control_path": "/api/orders/9999"},
    {"id": "AZ-2", "method": "DELETE", "path": "/admin/purge", "owner": "admin",
     "class": "bfla", "owasp": "API5", "privileged": true, "others": ["user_a", "anonymous"]}
  ]
}
```

**`control_path` (recommended for BOLA):** a path to a *different* object the owner
does **not** own. It proves the endpoint is object-specific: if the owner's real
object and the control return the same body, the endpoint is constant/public and a
body-match across identities is **not** a BOLA (suppressed). Without a
`control_path`, a body-match is reported as **suspected**, not a confirmed/verified
finding — this prevents false positives on endpoints that return a constant `200`
(e.g. `{"ok":true}`) for everyone.

Login types: `bearer` (`token_env`), `api_key` (`header` + `value_env`), `basic`
(`username_env`/`password_env`), `form` (`login_url` + `fields`, values may be
`"env:VAR"`), `none`. Credentials are resolved from the environment and kept out
of `get_safe_env()`, so they never reach a subprocess.

## Output

Under the run directory (`$OUTPUT_DIR`):

- `webauthz-findings.json` — per-test verdicts + observations
- `graph/web.json` — endpoints, identities, and `accessible_as` edges carrying
  the per-identity evidence; confirmed breaks as `vuln` nodes
- verified outcomes — surfaced by `libexec/raptor-verified-outcomes $OUTPUT_DIR`

Egress is allowlisted to the target host via the in-process proxy. Findings feed
`/webgraph` and `/diagram`.
