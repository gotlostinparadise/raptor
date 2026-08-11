---
description: Burp-repeater analog — send and tamper an HTTP request from a spec (change method/headers/query/body, resend, diff) and turn any request into a runnable PoC (curl one-liner, self-contained stdlib Python script, or raw HTTP). PoC generation is offline; sending requires --active + authorization.
dispatch: libexec/raptor-repeater $ARGUMENTS
---

# /repeater

The manual-testing companion, plus RAPTOR's exploit-generation ethos at the web
layer: a finding is more useful as a **runnable artifact** than as prose.

- **Send / tamper** (`--send --active`) — send a request spec, optionally
  tampering it first (`--set-param NAME=VALUE`, `--set-header NAME=VALUE`), and
  see the response fingerprint (status, length, body hash). Statuses come back as
  data (no exception on 4xx/5xx).
- **PoC generation** (`--poc {curl,python,http}`) — offline. Emit a copy-paste
  curl, a self-contained Python 3 stdlib script (no third-party deps, runs
  anywhere), or a raw HTTP/1.1 request. `--out FILE` writes it to disk.

## Request spec (`req.json`)

```jsonc
{
  "method": "POST",
  "url": "https://api.example.com/orders?id=1",
  "headers": {"Authorization": "Bearer …", "Content-Type": "application/json"},
  "body": "{\"qty\":1}"
}
```

## Usage

```
/repeater --spec req.json --poc curl                      # copy-paste curl (offline)
/repeater --spec req.json --poc python --out poc.py       # runnable Python PoC
/repeater --spec req.json --set-param id=2 --poc http     # tamper, then raw HTTP
/repeater --spec req.json --set-param id=2 --send --active --authorization "eng Y"
```

Sending a request requires `--active` **and** `--authorization`. PoC generation
needs neither — it never touches the network.
