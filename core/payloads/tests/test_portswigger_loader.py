"""Tests for the PortSwigger XSS loader — cheat-sheet parse + soundness gate."""

import json

from core.payloads.loaders.portswigger import load_xss
from core.payloads.store import PayloadStore


# A miniature cheat-sheet-shaped document: nested tags/events with `code`
# vectors, plus one destructive and one sink-less (unverifiable) entry.
_CHEAT = json.dumps({
    "tags": [
        {"tag": "img", "events": [{"code": "<img src=x onerror=alert(1)>"}]},
        {"tag": "svg", "code": "<svg onload=prompt(document.domain)>"},
        {"tag": "a", "code": "<a href=javascript:alert(document.cookie)>x</a>"},
        {"tag": "b", "code": "<b>inert markup, no sink</b>"},        # dropped
        {"tag": "x", "code": "<img src=x onerror=alert(1)>; DROP TABLE t"},  # dropped
    ],
})


def test_portswigger_parses_nested_and_adapts_sinks():
    ents = load_xss(fetch=lambda: _CHEAT)
    assert ents, "expected adapted entries from the cheat sheet"
    templates = [e.template for e in ents]
    assert all("window.__raptor_xss" in t for t in templates)     # sentinel injected
    assert all("alert(" not in t and "prompt(" not in t for t in templates)
    assert all(e.source == "PortSwigger" and "dom" in e.tags for e in ents)


def test_portswigger_soundness_gate_drops_unverifiable_and_destructive():
    blob = " ".join(e.template for e in load_xss(fetch=lambda: _CHEAT))
    assert "inert markup" not in blob      # no sink → cannot confirm → dropped
    assert "DROP TABLE" not in blob        # destructive → dropped


def test_portswigger_falls_back_to_line_list():
    ents = load_xss(fetch=lambda: "<img src=x onerror=alert(1)>\n# comment\n")
    assert len(ents) == 1 and "window.__raptor_xss" in ents[0].template


def test_portswigger_enriches_store_and_degrades_on_failure():
    s = PayloadStore()
    before = len(s.select("xss"))
    s.load(load_xss, fetch=lambda: _CHEAT)
    assert len(s.select("xss")) > before

    def boom():
        raise RuntimeError("network down")
    assert load_xss(fetch=boom) == []      # graceful, never raises
