"""Tests for T3 chaining — artifact extraction, point derivation, and the
two-step end-to-end (finding A leaks endpoint B, chaining tests B, B confirms in
one run). Extraction/derivation only produce candidate surface; the mechanical
oracle still confirms every chained finding.
"""

import re
from urllib.parse import unquote

from core.injection.chain import (
    ChainArtifacts, derive_identities, derive_points, extract_artifacts)
from core.injection.config import from_dict
from core.injection.runner import run_injection
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized test fixture"


def _blob(url, body):
    return unquote(url) + (unquote(body.decode()) if body else "")


# ── extraction ───────────────────────────────────────────────────────

def test_extract_artifacts_finds_endpoints_tokens_ids():
    findings = [{"excerpt":
                 'auth eyJhbGciOi.eyJzdWIi.SIGabcd ; '
                 'next: /rest/admin/panel ; '
                 '{"userid": 42, "uuid": "12345678-1234-1234-1234-123456789abc"}'}]
    arts = extract_artifacts(findings, base_url="http://t")
    assert any("/rest/admin/panel" in e for e in arts.endpoints)
    assert any(tok.startswith("eyJ") for tok in arts.tokens)
    assert "42" in arts.object_ids
    assert any(len(i) == 36 for i in arts.object_ids)      # the uuid


def test_extract_ignores_findings_without_excerpt():
    assert extract_artifacts([{"id": "INJ-1", "class": "sqli"}]).is_empty()


# ── derivation ───────────────────────────────────────────────────────

def test_derive_points_makes_points_and_preserves_query_param():
    arts = ChainArtifacts(
        endpoints=["/rest/admin/panel", "/rest/admin/panel",
                   "/api/v1/users?role=admin"])
    pts = derive_points(arts, seen_labels=set())
    labels = [p.label for p in pts]
    assert any("/rest/admin/panel" in lbl for lbl in labels)
    # a leaked query param is carried onto the derived point
    assert any("/api/v1/users" in lbl and "role" in lbl for lbl in labels)
    # /rest/admin/panel is derived once (dedupe by label)
    assert sum("/rest/admin/panel" in lbl for lbl in labels) == 1


def test_derive_points_skips_already_tested():
    arts = ChainArtifacts(endpoints=["/rest/admin/panel"])
    seen = {"GET /rest/admin/panel [query:id]"}
    assert derive_points(arts, seen) == []


def test_derive_points_llm_selection_is_coverage_preserving(monkeypatch):
    arts = ChainArtifacts(endpoints=["/a", "/b", "/c"])

    class _Resp:
        def __init__(self, d):
            self.result = d

    class _FakeClient:
        def __init__(self):
            self.config = type("C", (), {"config_for_model": lambda self, m: {}})()

        def generate_structured(self, prompt, schema, system_prompt=None,
                                model_config=None):
            return _Resp({"ordered_paths": ["/b [id]", "INVENTED [id]"]})

    monkeypatch.setattr("core.llm.client.LLMClient", _FakeClient)
    pts = derive_points(arts, set(), llm_model="fake", target="t")
    paths = [p.path for p in pts]
    assert paths[0] == "/b"                 # model's real pick first
    assert set(paths) == {"/a", "/b", "/c"}  # coverage preserved; invented dropped


# ── two-step end-to-end ──────────────────────────────────────────────

def _two_step_app():
    """Finding A (SSTI on /start) leaks endpoint /rest/admin/secret in its body;
    /rest/admin/secret is error-based-SQLi vulnerable → finding B."""
    def h(method, url, headers, body):
        blob = _blob(url, body)
        if "/start" in url:
            # evaluate the SSTI arithmetic marker → the oracle confirms A …
            evaluated = re.sub(r"\{\{(\d+)\*(\d+)\}\}",
                               lambda m: str(int(m.group(1)) * int(m.group(2))), blob)
            # … and the response leaks a fresh endpoint for the chainer to find
            return resp(200, body=(evaluated + "  next: /rest/admin/secret").encode())
        if "/rest/admin/secret" in url:
            if "'" in blob:                 # a quote breaks the query → 500 DB error
                return resp(500, body=b"SQLITE_ERROR: near syntax error")
            return resp(200, body=b"admin area")
        return resp(200, body=b"nope")
    return lambda hosts: FakeClient(h)


def _cfg(**extra):
    data = {"base_url": "https://app.test", "authorization": _AUTH,
            "points": [{"method": "GET", "path": "/start", "param": "q",
                        "location": "query"}],
            "classes": ["ssti", "sqli"]}
    data.update(extra)
    return from_dict(data)


def test_two_step_chain_resolves_in_one_run(tmp_path):
    run = run_injection(_cfg(chain=True), out_dir=tmp_path, active=True,
                        client_factory=_two_step_app())
    classes = {f["class"] for f in run.findings if f.get("proof")}
    # finding A (ssti on /start) AND the chained finding B (sqli on the leaked
    # endpoint) both confirm in the same run.
    assert "ssti" in classes and "sqli" in classes
    assert any(f["class"] == "sqli" and "/rest/admin/secret" in f["point"]
               for f in run.findings)
    assert run.chain is not None and run.chain["rounds"]


def test_chain_off_by_default_does_not_reach_step_two(tmp_path):
    run = run_injection(_cfg(), out_dir=tmp_path, active=True,
                        client_factory=_two_step_app())
    # without chaining, only the directly-mapped /start point is tested → no
    # finding on the leaked endpoint.
    assert run.chain is None
    assert not any("/rest/admin/secret" in f.get("point", "") for f in run.findings)


def test_config_chain_round_trips():
    cfg = from_dict({"base_url": "https://x", "chain": True, "chain_rounds": 3})
    assert cfg.chain is True and cfg.chain_rounds == 3


# ── N2: token → identity escalation ──────────────────────────────────

_TOKEN = "eyJhbGci.eyJhZG1p.SIGvalue123"


def _token_escalation_app():
    """Finding A (SSTI on /start) leaks a JWT + an admin endpoint; /rest/admin/vault
    is injectable ONLY when replayed as the leaked bearer identity (else 401)."""
    def h(method, url, headers, body):
        blob = _blob(url, body)
        auth = headers.get("Authorization", "")
        if "/start" in url:
            ev = re.sub(r"\{\{(\d+)\*(\d+)\}\}",
                        lambda m: str(int(m.group(1)) * int(m.group(2))), blob)
            return resp(200, body=(ev + f"  token={_TOKEN}  next: /rest/admin/vault").encode())
        if "/rest/admin/vault" in url:
            if f"Bearer {_TOKEN}" not in auth:
                return resp(401, body=b"unauthorized")
            if "'" in blob:
                return resp(500, body=b"SQLITE_ERROR: near syntax error")
            return resp(200, body=b"vault")
        return resp(200, body=b"nope")
    return lambda hosts: FakeClient(h)


def _start_cfg():
    return from_dict({"base_url": "https://app.test", "authorization": _AUTH,
                      "points": [{"method": "GET", "path": "/start", "param": "q",
                                  "location": "query"}],
                      "classes": ["ssti", "sqli"], "chain": True})


def test_leaked_token_becomes_identity_and_unlocks_step_two(tmp_path):
    run = run_injection(_start_cfg(), out_dir=tmp_path, active=True,
                        client_factory=_token_escalation_app())
    # B (sqli on the admin endpoint) confirms ONLY because the leaked token was
    # registered as an identity and replayed — the anonymous tester gets 401.
    assert any(f["class"] == "sqli" and "/rest/admin/vault" in f["point"]
               for f in run.findings)
    assert run.chain is not None
    assert any(rnd.get("new_identities") for rnd in run.chain["rounds"])


def test_derive_identities_from_tokens():
    arts = ChainArtifacts(tokens=[_TOKEN, _TOKEN, "eyJx.eyJy.SIGzz99"])
    idents = derive_identities(arts)
    assert len(idents) == 2                      # de-duplicated
    assert all(tok.startswith("eyJ") for _name, tok in idents)


# ── N6: chained surface persistence ──────────────────────────────────

def test_chained_surface_is_persisted_to_normalized(tmp_path):
    run = run_injection(_cfg(chain=True), out_dir=tmp_path, active=True,
                        client_factory=_two_step_app())
    # the leaked endpoint is persisted as endpoint+param records so the
    # orchestrator fixpoint can re-test it across the OTHER phases too.
    eps = (tmp_path / "normalized" / "endpoints.jsonl").read_text(encoding="utf-8")
    params = (tmp_path / "normalized" / "parameters.jsonl").read_text(encoding="utf-8")
    assert "/rest/admin/secret" in eps and "/rest/admin/secret" in params
    assert run.chain and run.chain.get("persisted_endpoints", 0) >= 1


def test_persist_chained_surface_merges_and_dedupes(tmp_path):
    from core.injection.chain import persist_chained_surface
    from core.injection.config import InjectionPoint
    nd = tmp_path / "normalized"
    nd.mkdir()
    pts = [InjectionPoint("GET", "/a", "id", "query"),
           InjectionPoint("GET", "/a", "id", "query")]   # duplicate
    assert persist_chained_surface(nd, pts, "http://t") == 1   # deduped to one
    assert persist_chained_surface(nd, pts, "http://t") == 0   # already present
