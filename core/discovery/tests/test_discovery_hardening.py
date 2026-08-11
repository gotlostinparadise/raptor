"""Hardening tests for core.discovery oracle boundaries.

Focused, deterministic pins for genuinely-uncovered branches that the base
``test_discovery.py`` suite does not exercise:

  * secret REDACTION correctness — both at the extractor and, critically, at the
    RUNNER/record level: the raw secret must never persist, only its redacted
    proof (preview + length + fingerprint);
  * false-positive avoidance — sub-threshold / benign strings that look
    secret-ish are NOT flagged;
  * exposed-file signature NEGATIVES — redirects, 5xx, the ``< 300`` boundary,
    lowercase env echoes, the empty-signature branch, and a SPA catch-all that
    returns index.html for every sensitive path;
  * JS endpoint extraction edge cases — cross-pattern dedup, relative/MIME/pure
    -interpolation drops, query-string preservation, source-map ``@`` variant,
    and malformed source-map recovery.

No network, no sleeps. HTTP is stubbed with the same FakeClient/resp fakes the
base suite uses.
"""

import hashlib
import json
from pathlib import Path

import pytest

from core.discovery import extractors, probes
from core.discovery.config import from_dict
from core.discovery.runner import run_discovery
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized fixture"


def _cfg(**kw):
    base = {"base_url": "https://app.test", "authorization": _AUTH}
    base.update(kw)
    return from_dict(base)


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _all_files_text(root) -> str:
    """Concatenate every persisted file under ``root`` (for absence/presence checks)."""
    blobs = []
    for p in Path(root).rglob("*"):
        if p.is_file():
            try:
                blobs.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    return "\n".join(blobs)


# ───────────────────── secret REDACTION correctness ─────────────────────

def test_secret_raw_value_absent_from_entire_record():
    # Strengthens the base 'preview != raw' check: the raw secret must not be a
    # substring of ANY field, and the redacted proof must be exact.
    raw = "AKIAIOSFODNN7EXAMPLE"
    secrets = extractors.extract_secrets(f'const k = "{raw}";')
    assert len(secrets) == 1
    rec = secrets[0]
    assert rec["type"] == "aws_access_key"
    assert rec["fingerprint"] == _fp(raw)          # direction 1: proof present + correct
    assert rec["length"] == "20"
    assert rec["preview"] == "AKIA…"
    assert all(raw not in str(v) for v in rec.values())   # direction 2: raw unreconstructable


def test_typed_secret_patterns_detected_and_redacted():
    # Exercises the google/github/stripe pattern branches (base suite only hits
    # aws + generic + jwt) and asserts redaction on each.
    google = "AIza" + "B" * 35
    github = "ghp_" + "C" * 36
    stripe = "sk_live_" + "D" * 24
    secrets = extractors.extract_secrets(f'g="{google}"; h="{github}"; s="{stripe}"')
    by_type = {s["type"]: s for s in secrets}
    assert {"google_api_key", "github_token", "stripe_secret"} <= set(by_type)
    for raw, kind in [(google, "google_api_key"), (github, "github_token"),
                      (stripe, "stripe_secret")]:
        rec = by_type[kind]
        assert all(raw not in str(v) for v in rec.values())   # raw never stored
        assert rec["fingerprint"] == _fp(raw)
        assert rec["length"] == str(len(raw))
        assert rec["preview"].endswith("…") and raw[:4] in rec["preview"]


def test_runner_redacts_secret_in_all_persisted_records(tmp_path):
    # Record-level contract through the full runner: a secret mined from JS must
    # not survive in ANY on-disk artifact — only the redacted fingerprint does.
    secret = "sk_live_" + "A" * 24
    appjs = (f'const STRIPE = "{secret}";').encode()
    index = b'<html><script src="/static/app.js"></script></html>'

    def h(method, url, headers, body):
        if url.endswith("/static/app.js"):
            return resp(200, body=appjs)
        if url.rstrip("/").endswith("app.test") or url.endswith("/"):
            return resp(200, body=index)
        return resp(404, body=b"nope")

    run = run_discovery(_cfg(probe_exposed=False), out_dir=tmp_path, active=True,
                        client_factory=lambda hosts: FakeClient(h), producing_model="t")
    assert run.secrets_found >= 1
    assert "exposed_secret" in {f.get("class") for f in run.findings}
    blob = _all_files_text(tmp_path)
    assert secret not in blob                       # raw secret never persisted anywhere
    assert _fp(secret) in blob                       # the redacted proof did persist
    vulns = tmp_path / "normalized" / "vulns.jsonl"
    assert vulns.exists() and secret not in vulns.read_text()


# ───────────────────── false-positive avoidance ─────────────────────

def test_subthreshold_and_benign_not_flagged_as_secrets():
    # Keyword-present-but-too-short, wrong-length AWS lookalike, and prefix-less
    # constants must all produce NO secret finding.
    text = (
        'password = "abc";'                            # keyword, value < 16 chars
        'const region = "AKIA123";'                    # AWS-ish prefix, too short for AKIA[16]
        'const build = "SHORTHASH12";'                 # random-ish, no key prefix
        'const note = "a normal harmless configuration value";'  # spaces + no keyword
    )
    assert extractors.extract_secrets(text) == []


# ───────────────────── exposed-file signature NEGATIVES ─────────────────────

def test_check_exposed_rejects_redirect_and_server_error():
    # Matching body but non-2xx status → not confirmed (base suite only tests 404).
    body = b"[core]\n\trepositoryformatversion = 0"
    assert probes.check_exposed(".git/config", r"\[core\]", resp(301, body=body)) is None
    assert probes.check_exposed(".git/config", r"\[core\]", resp(302, body=body)) is None
    assert probes.check_exposed(".git/config", r"\[core\]", resp(500, body=body)) is None
    assert probes.check_exposed(".git/config", r"\[core\]", resp(200, body=body))  # positive control


def test_check_exposed_status_upper_boundary():
    # Pins the '200 <= status < 300' upper edge: 299 confirms, 300 does not.
    body = b"[core]"
    assert probes.check_exposed(".git/config", r"\[core\]", resp(299, body=body))
    assert probes.check_exposed(".git/config", r"\[core\]", resp(300, body=body)) is None


def test_check_exposed_env_signature_rejects_lowercase():
    # A SPA echoing lowercase config keys must NOT confirm a real .env leak.
    sig = r"(?m)^[A-Z][A-Z0-9_]{2,}="
    assert probes.check_exposed(".env", sig, resp(200, body=b"foo=bar\nbaz=qux")) is None
    assert probes.check_exposed(".env", sig, resp(200, body=b"SECRET_KEY=x\nDB_HOST=y"))  # control


def test_check_exposed_empty_signature_confirms_on_200():
    # Falsy-signature branch: a path with no content signature is confirmed on any 2xx.
    f = probes.check_exposed("some/path", "", resp(200, body=b"whatever"))
    assert f is not None and f["type"] == "exposed_file" and f["path"] == "some/path"
    assert probes.check_exposed("some/path", "", resp(404, body=b"whatever")) is None


def test_runner_spa_catchall_yields_no_exposed_file(tmp_path):
    # Every path (incl. /.git/config, /.env) returns 200 index.html — the content
    # signatures must reject all of them, so ZERO exposed-file findings.
    index = b"<!doctype html><html><body>app</body></html>"

    def h(method, url, headers, body):
        return resp(200, body=index)

    run = run_discovery(_cfg(), out_dir=tmp_path, active=True,
                        client_factory=lambda hosts: FakeClient(h))
    assert run.requests_sent >= len(probes.EXPOSED_PATHS)
    assert run.exposed_files == 0
    assert "exposed_file" not in {f.get("class") for f in run.findings}


# ───────────────────── JS endpoint extraction edge cases ─────────────────────

def test_extract_endpoints_dedups_across_patterns():
    # The same path surfaced via fetch(), a bare literal, and axios.get() must be
    # de-duplicated to a single endpoint (the 'seen' set).
    eps = extractors.extract_endpoints(
        'fetch("/api/x"); const u = "/api/x"; axios.get("/api/x")')
    assert eps == ["/api/x"]


def test_extract_endpoints_drops_relative_mime_and_interp_only():
    # Non-endpoints: relative (no leading slash), MIME strings, pure-interpolation,
    # and bare-root noise are all filtered out.
    js = ('fetch("api/relative");'   # no leading slash
          'fetch("text/html");'      # MIME type, not a path
          'fetch("${base}");'        # pure interpolation → empties out
          'fetch("/")')              # bare root
    assert extractors.extract_endpoints(js) == []


def test_extract_endpoints_preserves_query_string():
    # The extractor keeps the query (the runner is what strips it into params).
    eps = extractors.extract_endpoints('const u = "/api/search?q=1&sort=name";')
    assert "/api/search?q=1&sort=name" in eps


def test_source_map_url_at_variant_and_absent():
    # Base suite only covers the '//#' form; pin the '//@' variant and no-match.
    assert extractors.source_map_url("code;\n//@ sourceMappingURL=out.js.map") == "out.js.map"
    assert extractors.source_map_url("var x = 1; // nothing here") == ""


def test_recover_sources_malformed_and_coercion():
    assert probes.recover_sources(b"not-json{{{") == []                        # invalid JSON
    assert probes.recover_sources(json.dumps(["a", "b"]).encode()) == []       # top-level not a dict
    assert probes.recover_sources(json.dumps({"version": 3}).encode()) == []   # no sources key
    assert probes.recover_sources(json.dumps({"sources": "x"}).encode()) == [] # sources not a list
    assert probes.recover_sources(json.dumps({"sources": [1, 2]}).encode()) == ["1", "2"]  # str-coerced
