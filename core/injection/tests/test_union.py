"""Tests for N1 UNION extraction — reflection-proof confirmation + read-only data
pull, and the runner escalation from a confirmed SQLi. A pure reflector must NOT
confirm (the computed product only appears if the injected SELECT actually ran).
"""

import re
from urllib.parse import unquote_plus

from core.injection.config import from_dict
from core.injection.markers import MarkerFactory
from core.injection.runner import run_injection
from core.injection.union import extract_via_union
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized test fixture"


def _blob(url, body):
    # _send encodes spaces as '+' (urlencode); decode them like a real server so
    # multi-word SQL ("UNION SELECT", "ORDER BY") is matched.
    return unquote_plus(url) + (unquote_plus(body.decode()) if body else "")


def _sqlite_eval(select_clause: str):
    """Evaluate the FIRST ``'tok'||(inner)||'tok'`` concat like SQLite would."""
    m = re.search(r"'([A-Za-z0-9]+)'\|\|\((.+)\)\|\|'\1'", select_clause)
    if not m:
        return None
    tok, inner = m.group(1), m.group(2).strip()
    am = re.fullmatch(r"(\d+)\*(\d+)", inner)
    if am:
        val = str(int(am.group(1)) * int(am.group(2)))
    elif "sqlite_version" in inner:
        val = "3.9.9"
    elif "group_concat" in inner:
        val = "Users,Cards"
    else:
        val = "?"
    return f"{tok}{val}{tok}"


def _union_app(columns=3):
    """A UNION-injectable fake: `')` breakout, `columns` columns, generic ||."""
    def h(method, url, headers, body):
        blob = _blob(url, body)
        m = re.search(r"ORDER BY (\d+)", blob)
        if m:
            return (resp(500, body=b"SQLITE_ERROR: no such column")
                    if int(m.group(1)) > columns else resp(200, body=b"ok"))
        if "UNION SELECT" in blob:
            sel = re.split(r"--|#", blob.split("UNION SELECT", 1)[1])[0]
            if sel.count(",") + 1 != columns:
                return resp(500, body=b"SQLITE_ERROR: SELECTs to the left and right "
                                       b"of UNION do not have the same number of result columns")
            return resp(200, body=(_sqlite_eval(sel) or "norender").encode())
        if "'" in blob:                      # error-based confirm (a quote breaks the query)
            return resp(500, body=b"SQLITE_ERROR: near syntax error")
        return resp(200, body=b"baseline")
    return lambda hosts: FakeClient(h)


def _reflector_app():
    """Echoes the raw payload verbatim — reflection, never execution."""
    def h(method, url, headers, body):
        return resp(200, body=_blob(url, body).encode())
    return lambda hosts: FakeClient(h)


def _point():
    from core.injection.config import InjectionPoint
    return InjectionPoint(method="GET", path="/item", param="q", location="query")


def _engine(app):
    from core.session.engine import SessionEngine
    return SessionEngine(app(["h"]))


# ── the oracle ───────────────────────────────────────────────────────

def test_union_confirms_and_extracts():
    eng = _engine(_union_app(columns=3))
    from core.injection.runner import _send
    calls = {"n": 0}

    def send(pl):
        calls["n"] += 1
        return _send(eng, "anonymous", "http://t", _point(), pl)

    res = extract_via_union(_point(), send, MarkerFactory().next())
    assert res is not None
    assert res.columns == 3
    assert res.extracted.get("db_version") == "3.9.9"
    assert "Users" in (res.extracted.get("tables") or "")


def test_union_reflection_proof_no_confirm_on_pure_reflector():
    eng = _engine(_reflector_app())
    from core.injection.runner import _send

    def send(pl):
        return _send(eng, "anonymous", "http://t", _point(), pl)

    # a reflector echoes '(191*193)' literally — the product never appears, so the
    # computed marker can't match and nothing is (falsely) confirmed.
    assert extract_via_union(_point(), send, MarkerFactory().next()) is None


# ── runner escalation ────────────────────────────────────────────────

def _cfg(**extra):
    data = {"base_url": "https://app.test", "authorization": _AUTH,
            "points": [{"method": "GET", "path": "/item", "param": "q",
                        "location": "query"}],
            "classes": ["sqli"]}
    data.update(extra)
    return from_dict(data)


def test_confirmed_sqli_escalates_to_union_extraction(tmp_path):
    run = run_injection(_cfg(union=True), out_dir=tmp_path, active=True,
                        client_factory=_union_app(columns=3))
    union_finds = [f for f in run.findings if f.get("proof")]
    assert any(f["class"] == "sqli" for f in union_finds)
    # the union finding carries the extracted data as its excerpt (for chaining)
    assert any("db_version" in (f.get("excerpt") or "") for f in run.findings)


def test_union_off_by_default(tmp_path):
    run = run_injection(_cfg(), out_dir=tmp_path, active=True,
                        client_factory=_union_app(columns=3))
    # sqli still confirms (error-based), but no UNION extraction excerpt is attached
    assert any(f["class"] == "sqli" for f in run.findings)
    assert not any("db_version" in (f.get("excerpt") or "") for f in run.findings)


def test_config_union_round_trips():
    assert from_dict({"base_url": "https://x", "union": True}).union is True


def test_union_extract_runs_operator_declared_expression():
    eng = _engine(_union_app(columns=3))
    from core.injection.runner import _send

    def send(pl):
        return _send(eng, "anonymous", "http://t", _point(), pl)

    res = extract_via_union(_point(), send, MarkerFactory().next(),
                            extract_sql=["SELECT group_concat(email) FROM Users"])
    assert res is not None and "custom_0" in res.extracted


def test_union_extract_implies_union_and_round_trips():
    cfg = from_dict({"base_url": "https://x",
                     "union_extract": ["SELECT group_concat(email) FROM Users"]})
    assert cfg.union is True                       # union_extract implies union
    assert cfg.union_extract == ["SELECT group_concat(email) FROM Users"]
