"""N7 multi-model verification tests. The mechanical oracle stays authoritative;
verification is an advisory confidence signal that never downgrades a finding.
Model calls are stubbed — no network.
"""

from urllib.parse import unquote_plus

from core.injection.config import from_dict
from core.injection.runner import run_injection
from core.injection.verify import verify_findings
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized test fixture"


def test_verify_only_confirmed_findings_with_consensus_and_dissent(monkeypatch):
    findings = [
        {"id": "INJ-0001", "class": "sqli", "proof": "reflected_marker", "excerpt": "e"},
        {"id": "INJ-0002", "class": "xss", "proof": None},   # unconfirmed → skipped
    ]

    def fake_judge(finding, model):
        return {"model": model, "supported": model == "A",
                "confidence": 0.9 if model == "A" else 0.2, "reason": "x"}

    monkeypatch.setattr("core.injection.verify.judge_finding", fake_judge)
    out = verify_findings(findings, ["A", "B"])
    assert len(out) == 1 and out[0]["finding_id"] == "INJ-0001"
    assert out[0]["agree"] == 1 and out[0]["total"] == 2 and out[0]["dissent"] is True


def test_verify_model_error_counts_as_abstention_not_dissent(monkeypatch):
    def judge(finding, model):
        if model == "bad":
            raise RuntimeError("model down")
        return {"model": model, "supported": True, "confidence": 0.8}

    monkeypatch.setattr("core.injection.verify.judge_finding", judge)
    out = verify_findings([{"id": "INJ-1", "class": "sqli", "proof": "x"}],
                          ["good", "bad"])
    assert out[0]["total"] == 1 and out[0]["agree"] == 1 and out[0]["dissent"] is False


def test_verify_is_noop_without_models():
    assert verify_findings([{"id": "x", "proof": "p"}], []) == []


def _sqli_app():
    def h(method, url, headers, body):
        blob = unquote_plus(url) + (unquote_plus(body.decode()) if body else "")
        if "'" in blob:
            return resp(500, body=b"SQLITE_ERROR: near syntax error")
        return resp(200, body=b"ok")
    return lambda hosts: FakeClient(h)


def test_run_injection_attaches_verification(tmp_path, monkeypatch):
    monkeypatch.setattr("core.injection.verify.judge_finding",
                        lambda f, m: {"model": m, "supported": True, "confidence": 0.9})
    cfg = from_dict({"base_url": "https://app.test", "authorization": _AUTH,
                     "points": [{"method": "GET", "path": "/item", "param": "q",
                                 "location": "query"}],
                     "classes": ["sqli"], "verify_models": ["A"]})
    run = run_injection(cfg, out_dir=tmp_path, active=True,
                        client_factory=_sqli_app())
    assert any(f["class"] == "sqli" for f in run.findings)     # confirmed first
    assert run.verification and run.verification[0]["mean_confidence"] == 0.9


def test_no_verification_without_models(tmp_path):
    cfg = from_dict({"base_url": "https://app.test", "authorization": _AUTH,
                     "points": [{"method": "GET", "path": "/item", "param": "q",
                                 "location": "query"}], "classes": ["sqli"]})
    run = run_injection(cfg, out_dir=tmp_path, active=True, client_factory=_sqli_app())
    assert run.verification is None                            # off by default


def test_config_verify_models_round_trips():
    assert from_dict({"base_url": "https://x",
                      "verify_models": ["a", "b"]}).verify_models == ["a", "b"]
