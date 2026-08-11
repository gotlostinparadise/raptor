"""Tests for the payload-feedback flywheel — record + count + SAGE gating."""

from core.payloads.feedback import confirmed_counts, record_confirmed


def test_confirmed_counts_tallies_by_class(tmp_path):
    fb = str(tmp_path / "fb.jsonl")
    record_confirmed("xss-a", "xss", path=fb)
    record_confirmed("xss-a", "xss", path=fb)
    record_confirmed("sqli-x", "sqli", path=fb)
    assert confirmed_counts("xss", path=fb) == {"xss-a": 2}
    assert confirmed_counts("sqli", path=fb) == {"sqli-x": 1}
    assert confirmed_counts("ssti", path=fb) == {}          # none recorded


def test_confirmed_counts_target_filter(tmp_path):
    fb = str(tmp_path / "fb.jsonl")
    record_confirmed("xss-a", "xss", target="https://a.test", path=fb)
    record_confirmed("xss-b", "xss", target="https://b.test", path=fb)
    assert confirmed_counts("xss", target="https://a.test", path=fb) == {"xss-a": 1}
    assert confirmed_counts("xss", path=fb) == {"xss-a": 1, "xss-b": 1}   # all targets


def test_confirmed_counts_missing_log_is_empty(tmp_path):
    assert confirmed_counts("xss", path=str(tmp_path / "nope.jsonl")) == {}


def test_record_confirmed_never_raises_and_skips_sage_by_default(tmp_path, monkeypatch):
    # SAGE opt-in is off (conftest) → the sidecar is never touched; JSONL written.
    monkeypatch.delenv("RAPTOR_PAYLOAD_SAGE", raising=False)
    fb = str(tmp_path / "fb.jsonl")
    record_confirmed("xss-a", "xss", technique="t", target="x", path=fb)
    assert confirmed_counts("xss", path=fb) == {"xss-a": 1}
