"""N5 integration/depth tests: boolean-class WAF evasion, and triaging the
chained (T3) surface so a budget is spent on plausible pairs.
"""

import re
from urllib.parse import unquote_plus

from core.injection.config import from_dict
from core.injection.runner import run_injection
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized test fixture"


def _blob(url, body):
    return unquote_plus(url) + (unquote_plus(body.decode()) if body else "")


# ── boolean-class WAF evasion ────────────────────────────────────────

def _waf_boolean_app():
    """Boolean-SQLi vulnerable, but a WAF 403s any bare space-delimited ``AND``.
    A mixed-case / comment-split evasion variant slips through and the boolean
    differential (TRUE≈baseline, FALSE differs) then confirms."""
    def h(method, url, headers, body):
        blob = _blob(url, body)
        # WAF: block a bare AND/OR keyword unless an evasion transform hid it
        # (mixed-case, comment-split, tab). Blocks BOTH sides of every raw pair.
        if re.search(r"\b(?:AND|OR)\b", blob) and "/**/" not in blob and "\t" not in blob:
            return resp(403, body=b"Request blocked by WAF")
        if "1'='2" in blob or "1=2" in blob:          # FALSE branch diverges
            return resp(200, body=b"no results")
        return resp(200, body=b"RESULT " * 40)        # baseline / TRUE branch
    return lambda hosts: FakeClient(h)


def _cfg(classes, **extra):
    data = {"base_url": "https://app.test", "authorization": _AUTH,
            "points": [{"method": "GET", "path": "/item", "param": "q",
                        "location": "query"}],
            "classes": classes}
    data.update(extra)
    return from_dict(data)


def test_boolean_sqli_confirms_via_evasion_when_waf_blocks_raw(tmp_path):
    # without adapt the raw boolean payloads are all blocked → no confirmation
    run_plain = run_injection(_cfg(["sqli"]), out_dir=tmp_path / "a", active=True,
                              client_factory=_waf_boolean_app())
    assert not any(f["class"] == "sqli" for f in run_plain.findings)
    # with adapt, an evasion-encoded boolean pair slips past the WAF and confirms
    run_adapt = run_injection(_cfg(["sqli"], adapt=True), out_dir=tmp_path / "b",
                              active=True, client_factory=_waf_boolean_app())
    assert any(f["class"] == "sqli" and f.get("proof") for f in run_adapt.findings)


# ── triaged chained surface ──────────────────────────────────────────

def _chain_leak_app():
    """SSTI on /start leaks BOTH an asset endpoint (/rest/app.js) and a real one
    (/rest/data); both are SQLi-vulnerable if tested — triage must drop the asset."""
    def h(method, url, headers, body):
        blob = _blob(url, body)
        if "/start" in url:
            ev = re.sub(r"\{\{(\d+)\*(\d+)\}\}",
                        lambda m: str(int(m.group(1)) * int(m.group(2))), blob)
            return resp(200, body=(ev + "  see /rest/app.js and /rest/data").encode())
        if "/rest/app.js" in url or "/rest/data" in url:
            if "'" in blob:
                return resp(500, body=b"SQLITE_ERROR: near syntax error")
            return resp(200, body=b"ok")
        return resp(200, body=b"nope")
    return lambda hosts: FakeClient(h)


def _start_cfg(**extra):
    data = {"base_url": "https://app.test", "authorization": _AUTH,
            "points": [{"method": "GET", "path": "/start", "param": "q",
                        "location": "query"}],
            "classes": ["ssti", "sqli"], "chain": True}
    data.update(extra)
    return from_dict(data)


def test_chained_points_are_triaged(tmp_path):
    # request_budget turns triage on; the chained asset endpoint scores 0 and is
    # dropped, while the real endpoint is tested and confirms.
    run = run_injection(_start_cfg(request_budget=500), out_dir=tmp_path, active=True,
                        client_factory=_chain_leak_app())
    assert any(f["class"] == "sqli" and "/rest/data" in f.get("point", "")
               for f in run.findings)
    assert not any("/rest/app.js" in f.get("point", "") for f in run.findings)


def test_chain_without_triage_tests_all_chained_points(tmp_path):
    # no budget/model/triage → chained points are tested untriaged (asset included)
    run = run_injection(_start_cfg(), out_dir=tmp_path, active=True,
                        client_factory=_chain_leak_app())
    pts = {f.get("point", "") for f in run.findings if f["class"] == "sqli"}
    assert any("/rest/data" in p for p in pts)
    assert any("/rest/app.js" in p for p in pts)
