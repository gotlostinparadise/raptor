"""Tests for the PayloadsAllTheThings loader — adapt + soundness gate."""

from core.payloads.loaders.payloadsallthethings import load_xss
from core.payloads.store import PayloadStore


_FIXTURE = "\n".join([
    "<script>alert(1)</script>",              # adaptable → sentinel
    "<img src=x onerror=alert('xss')>",       # adaptable
    "<svg/onload=prompt(document.domain)>",   # adaptable (prompt sink)
    "<b>plain markup, no sink</b>",           # unverifiable → dropped
    "'; DROP TABLE users;-- <script>alert(1)</script>",  # destructive → dropped
    "# a comment line",                        # skipped
    "",                                         # blank → skipped
])


def test_loader_adapts_sinks_to_sentinel():
    ents = load_xss(fetch=lambda: _FIXTURE)
    templates = [e.template for e in ents]
    assert templates, "expected some adapted entries"
    assert all("window.__raptor_xss" in t for t in templates)   # sentinel injected
    assert all("alert(" not in t and "prompt(" not in t for t in templates)  # sinks rewritten
    assert all(e.oracle == "unescaped" and "dom" in e.tags for e in ents)


def test_loader_soundness_gate_drops_unverifiable_and_destructive():
    ents = load_xss(fetch=lambda: _FIXTURE)
    blob = " ".join(e.template for e in ents)
    assert "plain markup" not in blob       # no sink → cannot confirm → dropped
    assert "DROP TABLE" not in blob         # destructive → dropped


def test_loader_enriches_store_by_id():
    s = PayloadStore()
    before = len(s.select("xss"))
    s.load(load_xss, fetch=lambda: _FIXTURE)
    assert len(s.select("xss")) > before    # imported vectors added to the catalog


def test_loader_degrades_on_fetch_failure():
    def boom():
        raise RuntimeError("network down")
    assert load_xss(fetch=boom) == []        # graceful, never raises
