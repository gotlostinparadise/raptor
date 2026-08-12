"""Tests for core.sessionid — deterministic weak/predictable session-id analysis."""

import base64
import json
from pathlib import Path

from core.sessionid.analysis import analyze, shannon_entropy
from core.sessionid.config import from_dict
from core.sessionid.runner import run_sessionid


# ─────────────────────────── analysis (sound core) ───────────────────────────

def test_sequential_decimal_confirmed():
    a = analyze(["1000", "1001", "1002", "1003"])
    assert a.confirmed and a.confirmed_class == "predictable_session_id"
    assert a.detail["delta"] == 1


def test_sequential_base64_counter_confirmed():
    toks = [base64.urlsafe_b64encode((100 + i).to_bytes(4, "big")).rstrip(b"=").decode()
            for i in range(4)]
    a = analyze(toks)
    assert a.confirmed_class == "predictable_session_id"


def test_reuse_confirmed():
    a = analyze(["abc", "def", "abc"])
    assert a.confirmed_class == "session_id_reuse"
    assert "abc" in a.detail["reused"]


def test_random_high_entropy_tokens_not_flagged():
    # 32-char urlsafe-random-looking tokens: not sequential, not reused, high entropy
    toks = ["Xq7Za1PmЬ".ljust(32, chr(65 + i)) for i in range(4)]
    toks = ["k3Jf9Qw2Lp8Zx1Vc7Bn4Ms6Rt0Yd5Hg", "9Qw2Lp8Zx1Vc7Bn4Ms6Rt0Yd5Hgk3Jf",
            "Lp8Zx1Vc7Bn4Ms6Rt0Yd5Hgk3Jf9Qw2", "7Bn4Ms6Rt0Yd5Hgk3Jf9Qw2Lp8Zx1Vc"]
    a = analyze(toks)
    assert not a.confirmed and not a.suspected_class


def test_low_entropy_short_token_suspected_not_confirmed():
    # low entropy + short, but NOT an arithmetic sequence in any base and not
    # reused → suspected, never confirmed. (Deltas 1 then 15 are non-constant.)
    a = analyze(["aaaa", "aaab", "aaba"])
    assert not a.confirmed
    assert a.suspected_class == "weak_session_id"


def test_too_few_tokens():
    assert not analyze(["only-one"]).confirmed


def test_shannon_entropy_bounds():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0


# ─────────────────────────── runner ───────────────────────────

def _cfg(**kw):
    base = {"base_url": "https://app.test", "authorization": "lab"}
    base.update(kw)
    return from_dict(base)


def test_runner_offline_confirms_from_provided_tokens(tmp_path):
    run = run_sessionid(_cfg(tokens=["500", "501", "502", "503"]),
                        out_dir=tmp_path, active=False)
    assert run.requests_sent == 0
    assert any(f.get("proof") == "token_analysis" for f in run.findings)
    vulns = Path(tmp_path) / "normalized" / "vulns.jsonl"
    rows = [json.loads(l) for l in vulns.read_text().splitlines() if l.strip()]
    assert any(r["proof_kind"] == "token_analysis"
               and r["vuln_class"] == "predictable_session_id" for r in rows)


def test_runner_collects_cookie_tokens_and_confirms(tmp_path):
    # a server that hands out a sequential session cookie each hit
    from core.session.tests.fakes import FakeClient, resp
    counter = [41]

    def h(method, url, headers, body):
        counter[0] += 1
        return resp(200, **{"Set-Cookie": f"SESSIONID={counter[0]}; Path=/"})

    run = run_sessionid(
        _cfg(collect_url="/login", method="GET", count=5, cookie_name="SESSIONID"),
        out_dir=tmp_path, active=True, client_factory=lambda hosts: FakeClient(h))
    assert run.tokens_collected == 5
    assert any(f.get("proof") == "token_analysis" for f in run.findings)
