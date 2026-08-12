"""Tests for the T2 read/adapt layer — response reading, WAF-evasion retries,
response-guided ordering, and the 5xx-body path that unblocks error-based SQLi.
Adaptation only reorders/expands payloads; the oracle still fires every verdict.
"""

from urllib.parse import unquote

from core.injection import oracles
from core.injection.adapt import (
    ResponseRead, adaptive_try, llm_reorder_factory, read_response,
)
from core.injection.config import from_dict
from core.injection.runner import run_injection
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized test fixture"


# ── read_response ────────────────────────────────────────────────────

def test_read_response_extracts_db_error_and_status():
    read = read_response(resp(500, body=b"...near syntax: SQLITE_ERROR"))
    assert read.status == 500 and read.sql_db == "sqlite" and read.blocked is False


def test_read_response_flags_waf_block():
    assert read_response(resp(403, body=b"Access Denied")).blocked is True
    assert read_response(
        resp(200, body=b"Request blocked by our Web Application Firewall")).blocked is True
    assert read_response(resp(200, body=b"normal page")).blocked is False


# ── adaptive_try mechanics ───────────────────────────────────────────

def test_adaptive_try_defaults_to_fixed_catalog_loop():
    calls = []

    def send(p):
        calls.append(p)
        return resp(200, body=(b"HIT" if p == "p2" else b"no"))

    hit = adaptive_try([("p1", None), ("p2", None), ("p3", None)], send,
                       lambda r, _e: b"HIT" in (r.body or b""))
    assert hit and hit["payload"] == "p2" and hit["evaded"] is False
    assert calls == ["p1", "p2"]          # stops at first match, no reorder/evade


def test_adapt_steps_caps_sends():
    calls = []

    def send(p):
        calls.append(p)
        return resp(200, body=b"no")

    hit = adaptive_try([("a", None), ("b", None), ("c", None)], send,
                       lambda r, _e: False, steps=2)
    assert hit is None and calls == ["a", "b"]


def test_waf_evasion_confirms_when_raw_is_blocked():
    MARK = "PWND"

    def send(payload):
        # a WAF that blocks the literal payload but lets an encoded form through
        if "%" in payload or "/**/" in payload:
            return resp(200, body=f"reflected {MARK}".encode())
        return resp(403, body=b"Request blocked by WAF")

    matcher = lambda r, _e: oracles.reflected(r, MARK)
    raw = "1' OR '1'='1"
    # without evasion the raw is blocked → nothing confirms
    assert adaptive_try([(raw, None)], send, matcher, evade=False) is None
    # with evasion an encoded variant slips through and the oracle confirms
    hit = adaptive_try([(raw, None)], send, matcher, evade=True)
    assert hit and hit["evaded"] is True


def test_reorder_prioritizes_and_preserves_coverage():
    seen = []

    def send(p):
        seen.append(p)
        return resp(200, body=(b"HIT" if p == "z" else b"x"))

    def reorder(read, remaining):
        z = [c for c in remaining if c[0] == "z"]
        rest = [c for c in remaining if c[0] != "z"]
        return z + rest                    # float "z" to the front of the rest

    hit = adaptive_try([("a", None), ("b", None), ("z", None), ("c", None)], send,
                       lambda r, _e: b"HIT" in r.body, reorder=reorder)
    assert hit["payload"] == "z"
    assert seen[0] == "a" and seen[1] == "z"   # probe first, then reordered pick


# ── LLM reorder (coverage-preserving, invented ignored) ──────────────

def test_llm_reorder_ignores_invented_and_appends_omitted(monkeypatch):
    class _Resp:
        def __init__(self, d):
            self.result = d

    class _FakeClient:
        def __init__(self):
            self.config = type("C", (), {
                "config_for_model": lambda self, m: {}})()

        def generate_structured(self, prompt, schema, system_prompt=None,
                                model_config=None):
            # promote "b", invent one, omit "a"/"c"
            return _Resp({"ordered_payloads": ["b", "INVENTED"], "reason": "x"})

    monkeypatch.setattr("core.llm.client.LLMClient", _FakeClient)
    reorder = llm_reorder_factory("sqli", "fake-model", target="t")
    out = reorder(ResponseRead(500, 10, "sqlite", False, "err"),
                  [("a", None), ("b", None), ("c", None)])
    assert [p for p, _ in out] == ["b", "a", "c"]   # chosen first; invented dropped; rest appended


# ── end-to-end through run_injection ─────────────────────────────────

def _sqli_5xx_app():
    def h(method, url, headers, body):
        blob = unquote(url) + (unquote(body.decode()) if body else "")
        if "'" in blob:                    # a quote breaks the query → 500 with DB error
            return resp(500, body=b"SQLITE_ERROR: near syntax error")
        return resp(200, body=b"ok")
    return lambda hosts: FakeClient(h)


def _cfg(classes, **extra):
    data = {"base_url": "https://app.test", "authorization": _AUTH,
            "points": [{"method": "GET", "path": "/p", "param": "q",
                        "location": "query"}],
            "classes": classes}
    data.update(extra)
    return from_dict(data)


def test_error_based_sqli_confirms_on_5xx_body(tmp_path):
    # regression for the 5xx-body fix: a 500 carrying a DB error must confirm SQLi.
    run = run_injection(_cfg(["sqli"]), out_dir=tmp_path, active=True,
                        client_factory=_sqli_5xx_app())
    assert any(f["class"] == "sqli" and f.get("proof") for f in run.findings)


def test_adapt_mode_still_confirms_and_is_opt_in(tmp_path):
    run = run_injection(_cfg(["sqli"], adapt=True), out_dir=tmp_path, active=True,
                        client_factory=_sqli_5xx_app())
    assert any(f["class"] == "sqli" for f in run.findings)


def test_config_adapt_round_trips():
    cfg = from_dict({"base_url": "https://x", "adapt": True, "adapt_steps": 4})
    assert cfg.adapt is True and cfg.adapt_steps == 4
