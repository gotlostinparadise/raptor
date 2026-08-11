"""Tests for the payload catalog — entry/context/store/proposer/feedback."""

import json

from core.payloads.context import detect_context
from core.payloads.entry import (
    CTX_ATTR_DOUBLE, CTX_HTML_BODY, CTX_JS_STRING, ORACLE_COMPUTED, ORACLE_UNESCAPED,
    PayloadEntry,
)
from core.payloads.feedback import record_confirmed
from core.payloads.proposer import propose
from core.payloads.store import PayloadStore, default_store


# ─────────────────────────── entry ───────────────────────────

def test_render_and_expected_unescaped():
    e = PayloadEntry("x", "xss", "<img onerror=\"a='{tok}'\">", oracle=ORACLE_UNESCAPED)
    assert e.render(tok="T") == "<img onerror=\"a='T'\">"
    assert e.expected(tok="T") == e.render(tok="T")   # raw presence == injection


def test_expected_computed_is_product_wrapped():
    e = PayloadEntry("s", "ssti", "{tok}{{ {a}*{b} }}{tok}", oracle=ORACLE_COMPUTED)
    assert e.expected(tok="T", a=191, b=193) == "T36863T"
    assert "36863" not in e.render(tok="T", a=191, b=193)   # product not in raw payload


# ─────────────────────────── context detection ───────────────────────────

def test_detect_context_html_body_and_attr_and_js():
    assert CTX_HTML_BODY in detect_context("<div>MARK</div>", "MARK")
    assert CTX_ATTR_DOUBLE in detect_context('<input value="MARK">', "MARK")
    assert CTX_JS_STRING in detect_context("<script>var x='MARK'</script>", "MARK")
    assert detect_context("no reflection here", "MARK") == []


# ─────────────────────────── store ───────────────────────────

def test_store_select_context_first():
    s = default_store()
    ents = s.select("xss", contexts=[CTX_JS_STRING])
    assert ents and ents[0].context == CTX_JS_STRING     # context match ordered first
    assert all(e.vuln_class == "xss" for e in ents)


def test_store_drops_destructive():
    s = PayloadStore([PayloadEntry("d", "cmdi", "rm -rf /", destructive=True),
                      PayloadEntry("ok", "cmdi", "; echo {tok}")])
    assert [e.id for e in s.select("cmdi")] == ["ok"]
    assert len(s.select("cmdi", include_destructive=True)) == 2


def test_store_add_enriches_by_id():
    s = PayloadStore([PayloadEntry("a", "xss", "x")])
    added = s.add([PayloadEntry("b", "xss", "y"), PayloadEntry("a", "xss", "x2")])
    assert added == 1 and len(s.all()) == 2


# ─────────────────────────── proposer (mechanical fallback) ───────────────────────────

def test_propose_mechanical_when_no_model(tmp_path):
    s = default_store()
    # isolate the flywheel log so the test pins pure mechanical ordering
    fb = str(tmp_path / "empty.jsonl")
    ents = propose(s, "xss", context_hints=[CTX_HTML_BODY], model=None, feedback=fb)
    # deterministic mechanical order = store.select order
    assert [e.id for e in ents] == [e.id for e in s.select("xss", contexts=[CTX_HTML_BODY])]


# ─────────────────────────── proposer (flywheel) ───────────────────────────

def test_flywheel_promotes_confirmed_payload(tmp_path):
    fb = str(tmp_path / "fb.jsonl")
    s = default_store()
    base = [e.id for e in s.select("xss")]
    promote = base[-1]                       # a vector NOT already first
    record_confirmed(promote, "xss", path=fb)
    ents = propose(s, "xss", model=None, feedback=fb)
    assert ents[0].id == promote             # confirmed vector floated to front
    assert {e.id for e in ents} == set(base)  # coverage preserved


def test_flywheel_is_target_scoped(tmp_path):
    fb = str(tmp_path / "fb.jsonl")
    s = default_store()
    base = [e.id for e in s.select("xss")]
    promote = base[-1]
    record_confirmed(promote, "xss", target="https://a.test", path=fb)
    # a different target sees no boost; the matching target does
    other = propose(s, "xss", model=None, target="https://b.test", feedback=fb)
    match = propose(s, "xss", model=None, target="https://a.test", feedback=fb)
    assert other[0].id == base[0] and match[0].id == promote


def test_propose_preserves_coverage_on_llm_failure(monkeypatch):
    # a broken "model" path falls back to the full candidate set, order intact
    s = default_store()
    import core.payloads.proposer as P
    monkeypatch.setattr(P, "_llm_rank", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    ents = propose(s, "xss", model="cc/whatever")
    assert {e.id for e in ents} == {e.id for e in s.select("xss")}


# ─────────────────────────── feedback ───────────────────────────

def test_record_confirmed_appends(tmp_path):
    p = tmp_path / "fb.jsonl"
    record_confirmed("xss-body-iframe-js", "xss", technique="iframe/js", path=str(p))
    row = json.loads(p.read_text().strip())
    assert row["entry_id"] == "xss-body-iframe-js" and row["vuln_class"] == "xss"
