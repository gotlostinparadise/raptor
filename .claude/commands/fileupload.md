---
description: Unrestricted file-upload testing — upload a dangerous-extension marker file whose body echoes a token-wrapped arithmetic product, locate where it was stored (parsed from the response, an operator template, or common upload prefixes), retrieve it, and confirm EXECUTED (computed product returned — code execution) or RETRIEVABLE (source served verbatim). Either is a confirmed unrestricted upload (CWE-434, PROOF_REFLECTED_MARKER). Safe by default (dry-run unless --active + declared authorization).
dispatch: libexec/raptor-fileupload --out-dir $OUTPUT_DIR $ARGUMENTS
---

# /fileupload

An upload endpoint that accepts a dangerous file type and serves it back is a
direct path to code execution. `/fileupload` uploads a benign marker file
(`<?php echo TOKEN.(a*b).TOKEN ?>` — it only echoes a number), finds where it
landed, and reads it back:

- **Executed** — the retrieved body carries the *computed product* wrapped in the
  token. Only server-side execution produces the number; serving the source
  cannot. The strongest proof.
- **Retrievable** — the source is served back verbatim (token + literal `a*b`).
  Stored and reachable — an unrestricted upload even if not executed.

Both confirm as `unrestricted_file_upload` (CWE-434, `PROOF_REFLECTED_MARKER`).
The stored path is discovered from the upload response, a `--retrieve-template`
(`{filename}`), or a list of common upload directories (DVWA's first).

## AUTHORIZATION GATE

Active testing uploads a file to the target. Refused unless `--active` **and** a
non-empty `authorization` **and** a non-passive profile. Without `--active` you get
a dry-run plan.

## Usage

```
/fileupload --url http://dvwa --upload-url /vulnerabilities/upload/ \
  --retrieve-template '/hackable/uploads/{filename}' --authorization "eng Y" --active
```

## Config shape (`fileupload.json`)

```jsonc
{
  "base_url": "http://dvwa.local",
  "upload_url": "/vulnerabilities/upload/",
  "field_name": "uploaded",
  "ext": ".php",
  "extra_fields": { "Upload": "Upload" },
  "retrieve_template": "/hackable/uploads/{filename}",
  "authorization": "engagement ACME-2026; written approval on file"
}
```

## Output

Under `$OUTPUT_DIR`: `fileupload-findings.json`, `graph/web.json`, and verified
outcomes via `libexec/raptor-verified-outcomes $OUTPUT_DIR`.
