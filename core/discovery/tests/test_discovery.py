"""Tests for core.discovery — extractors, probes, and the runner."""

import json

import pytest

from core.discovery import extractors, probes
from core.discovery.config import from_dict
from core.discovery.runner import run_discovery
from core.labeled_attempts.view import Oracle, collect_outcomes
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized fixture"


# ─────────────────────────── extractors ───────────────────────────

def test_extract_endpoints_from_js():
    js = 'fetch("/api/users/1"); const u="/api/orders"; axios.get("https://app.test/api/x")'
    eps = extractors.extract_endpoints(js, same_origin="https://app.test")
    assert "/api/users/1" in eps and "/api/orders" in eps
    assert "https://app.test/api/x" in eps


def test_extract_endpoints_drops_offsite_urls():
    js = 'fetch("https://evil.test/steal")'
    assert extractors.extract_endpoints(js, same_origin="https://app.test") == []


def test_extract_endpoints_strips_spa_template_literals():
    # regression (found testing Juice Shop): Angular template literals must be
    # cleaned so the real path survives and is injectable — not left as
    # "${this.hostServer}/rest/..." which crashes URL construction downstream.
    js = ("this.http.get(`${this.hostServer}/rest/products/search?q=${term}`);"
          "fetch(`${this.config.prefix}${e}${this.config.suffix}`);"
          "this.http.get(`//ipinfo.io`)")
    eps = extractors.extract_endpoints(js)
    assert any(e.startswith("/rest/products/search") for e in eps)  # real path recovered
    assert all("${" not in e for e in eps)                          # no interpolation junk
    assert all(not e.startswith("//") for e in eps)                 # no protocol-relative externals
    assert "/" not in [e for e in eps if len(e) <= 1]               # no bare-slash noise


def test_extract_secrets_redacts():
    text = 'const k="AKIAIOSFODNN7EXAMPLE"; api_key: "abcd1234efgh5678ijkl"'
    secrets = extractors.extract_secrets(text)
    types = {s["type"] for s in secrets}
    assert "aws_access_key" in types
    # never store the raw value
    for s in secrets:
        assert "AKIAIOSFODNN7EXAMPLE" != s.get("preview")
        assert "fingerprint" in s and len(s["fingerprint"]) == 12


def test_script_srcs_and_source_map_url():
    html = '<script src="/static/app.js"></script>'
    assert extractors.script_srcs(html) == ["/static/app.js"]
    assert extractors.source_map_url("code;\n//# sourceMappingURL=app.js.map") == "app.js.map"


def test_check_exposed_requires_signature():
    assert probes.check_exposed(".git/config", r"\[core\]",
                                resp(200, body=b"[core]\n\trepositoryformatversion = 0"))
    # 200 with wrong content (SPA catch-all) is NOT a hit
    assert probes.check_exposed(".git/config", r"\[core\]",
                                resp(200, body=b"<!doctype html>")) is None
    # 404 is not a hit
    assert probes.check_exposed(".env", r"^[A-Z]", resp(404, body=b"")) is None


def test_recover_sources():
    mp = json.dumps({"sources": ["src/app.ts", "src/secret.ts"]}).encode()
    assert probes.recover_sources(mp) == ["src/app.ts", "src/secret.ts"]


# ─────────────────────────── runner ───────────────────────────

def _cfg(**kw):
    base = {"base_url": "https://app.test", "authorization": _AUTH}
    base.update(kw)
    return from_dict(base)


def test_dry_run_sends_nothing(tmp_path):
    run = run_discovery(_cfg(), out_dir=tmp_path, active=False)
    assert run.requests_sent == 0 and run.findings[0].get("planned")


def test_active_gate(tmp_path):
    cfg = _cfg(); cfg.authorization = ""
    with pytest.raises(ValueError):
        run_discovery(cfg, out_dir=tmp_path, active=True,
                      client_factory=lambda h: FakeClient(lambda *a: resp(200)))


def _rich_server():
    index = (b'<html><script src="/static/app.js"></script></html>')
    appjs = (b'fetch("/api/profile");const K="AKIAIOSFODNN7EXAMPLE";'
             b'\n//# sourceMappingURL=app.js.map')
    smap = json.dumps({"sources": ["src/a.ts", "src/b.ts"]}).encode()

    def h(method, url, headers, body):
        if url.endswith("/static/app.js"):
            return resp(200, body=appjs)
        if url.endswith("app.js.map"):
            return resp(200, body=smap)
        if url.endswith("/.git/config"):
            return resp(200, body=b"[core]\n\tbare = false")
        if url.endswith("/.env"):
            return resp(200, body=b"SECRET_KEY=supersecret\nDB_HOST=db")
        if url.rstrip("/").endswith("app.test") or url.endswith("/"):
            return resp(200, body=index)
        return resp(404, body=b"nope")
    return lambda hosts: FakeClient(h)


def test_secret_in_endpoint_url_is_not_stored_verbatim(tmp_path):
    # regression: a JWT in a fetched URL's query must not land in the graph as
    # an endpoint path; only the param NAME is recorded (value stripped)
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.SIGSIGSIGSIG"
    appjs = f'fetch("/api/data?token={jwt}&sort=name")'.encode()

    def h(method, url, headers, body):
        if url.endswith("/static/app.js"):
            return resp(200, body=appjs)
        if url.rstrip("/").endswith("app.test") or url.endswith("/"):
            return resp(200, body=b'<script src="/static/app.js"></script>')
        return resp(404, body=b"nope")

    run = run_discovery(_cfg(probe_exposed=False), out_dir=tmp_path, active=True,
                        client_factory=lambda hosts: FakeClient(h))
    graph_text = (tmp_path / "graph" / "web.json").read_text()
    norm = (tmp_path / "normalized" / "endpoints.jsonl")
    blob = graph_text + (norm.read_text() if norm.exists() else "")
    assert jwt not in blob                              # the secret never persists
    assert "/api/data" in blob                          # the path (sans query) does
    # the param name survives as a parameter node
    pnorm = tmp_path / "normalized" / "parameters.jsonl"
    assert pnorm.exists() and "token" in pnorm.read_text()


def test_full_discovery_finds_endpoints_secrets_files_maps(tmp_path):
    run = run_discovery(_cfg(), out_dir=tmp_path, active=True,
                        client_factory=_rich_server(), producing_model="t")
    classes = {f["class"] for f in run.findings}
    assert run.endpoints_found >= 1
    assert "exposed_secret" in classes
    assert "exposed_file" in classes
    assert "source_map_exposed" in classes
    # proofs surfaced
    outs = collect_outcomes(tmp_path, project_root=tmp_path)
    assert any(o.oracle == Oracle.WEB for o in outs)
    # discovered endpoint made it into the graph
    web = json.loads((tmp_path / "graph" / "web.json").read_text())
    assert any(n["type"] == "endpoint" for n in web["nodes"])
