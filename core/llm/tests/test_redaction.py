"""Tests for ``core.llm.redaction`` — LLM-guarded prompt scrub before
external egress (Feature 2).

The guard LLM is mocked via the ``_guard_spans`` seam so no real call is
made. Covers: the toggle + guarded-destination gate, the regex floor,
span application / stable tokens, fail-closed behaviour, guard-trust
enforcement, and the provider hook.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

import pytest

from core.llm import redaction as R
from core.llm import sensitivity as S
from core.llm.redaction import RedactionUnavailable


@dataclass
class FakeCfg:
    provider: str
    model_name: str = "m"
    api_base: Optional[str] = None


OMNI = FakeCfg(provider="omni", api_base="https://omniroute.grigoreo.dev/v1")
ANTHROPIC = FakeCfg(provider="anthropic")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_SENSITIVITY_REGISTRY", str(tmp_path / "reg.json"))
    monkeypatch.delenv("RAPTOR_REDACT_EXTERNAL", raising=False)
    R.set_enabled(False)
    S.reset_current()
    yield
    R.set_enabled(False)
    S.reset_current()


def _mock_guard(spans: List[Tuple[str, str]]):
    def _fn(text, out_dir=None):
        return list(spans)
    return _fn


# --------------------------------------------------------------------------
# Toggle + destination gate
# --------------------------------------------------------------------------

def test_disabled_by_default_passthrough(monkeypatch):
    monkeypatch.setattr(R, "_guard_spans", _mock_guard([("sk-should-not-run", "secret")]))
    assert R.should_redact(OMNI) is False
    p, s = R.redact_prompt(OMNI, "key sk-abc123", None)
    assert p == "key sk-abc123"  # untouched — redaction off


def test_enabled_but_trusted_destination_passthrough(monkeypatch):
    R.set_enabled(True)
    monkeypatch.setattr(R, "_guard_spans", _mock_guard([("x", "secret")]))
    # Anthropic is first-party -> not guarded -> no redaction (also what
    # prevents the guard call recursing on itself).
    assert R.should_redact(ANTHROPIC) is False
    p, _ = R.redact_prompt(ANTHROPIC, "hello", None)
    assert p == "hello"


def test_enabled_guarded_destination_redacts(monkeypatch):
    R.set_enabled(True)
    monkeypatch.setattr(R, "_guard_spans",
                        _mock_guard([("Project Cerberus", "internal_identifier")]))
    assert R.should_redact(OMNI) is True
    p, _ = R.redact_prompt(OMNI, "audit of Project Cerberus module", None)
    assert "Project Cerberus" not in p
    assert "[INTERNAL_IDENTIFIER_1]" in p


# --------------------------------------------------------------------------
# Regex floor (deterministic, independent of the guard)
# --------------------------------------------------------------------------

def test_regex_floor_catches_known_secret_even_if_guard_misses(monkeypatch):
    R.set_enabled(True)
    monkeypatch.setattr(R, "_guard_spans", _mock_guard([]))  # guard finds nothing
    text = "token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'"
    p, mapping = R.redact_text(text)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in p
    assert any("ghp_" in v for v in mapping.values())


def test_regex_aws_and_jwt(monkeypatch):
    R.set_enabled(True)
    monkeypatch.setattr(R, "_guard_spans", _mock_guard([]))
    spans = R._regex_spans("id AKIAIOSFODNN7EXAMPLE and eyJhbGc.eyJzdWIx.SflKxwRJ")
    joined = " ".join(s for s, _ in spans)
    assert "AKIAIOSFODNN7EXAMPLE" in joined


# --------------------------------------------------------------------------
# Span application: stable tokens, longest-first, exact-substring only
# --------------------------------------------------------------------------

def test_apply_stable_tokens_and_counts():
    text = "a=SECRETONE b=SECRETONE c=SECRETTWO"
    out, mapping, counts = R._apply_spans(
        text, [("SECRETONE", "secret"), ("SECRETTWO", "secret")])
    assert out.count("[SECRET_1]") == 2  # both occurrences of first
    assert "[SECRET_2]" in out
    assert counts["secret"] == 2
    assert mapping["[SECRET_1]"] == "SECRETONE"


def test_hallucinated_span_not_present_is_ignored():
    text = "clean source code"
    out, mapping, _ = R._apply_spans(text, [("NONEXISTENT", "secret")])
    assert out == text and mapping == {}


def test_code_body_preserved(monkeypatch):
    # Guard flags only the secret; the internal IP in code stays (it may
    # be the finding). We assert the code logic is intact.
    R.set_enabled(True)
    monkeypatch.setattr(R, "_guard_spans", _mock_guard([("hunter2pass", "credential")]))
    code = "connect('10.0.0.5', password='hunter2pass')"
    p, _ = R.redact_text(code)
    assert "10.0.0.5" in p            # code/finding preserved
    assert "hunter2pass" not in p     # credential scrubbed


# --------------------------------------------------------------------------
# Fail-closed
# --------------------------------------------------------------------------

def test_fail_closed_when_guard_raises(monkeypatch):
    R.set_enabled(True)

    def _boom(text, out_dir=None):
        raise RedactionUnavailable("guard down")

    monkeypatch.setattr(R, "_guard_spans", _boom)
    with pytest.raises(RedactionUnavailable):
        R.redact_prompt(OMNI, "some prompt with data", None)


def test_guard_config_unavailable_without_trusted(monkeypatch):
    # No Anthropic key and no Claude Code -> no trusted guard -> refuse.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import core.llm.detection as det
    monkeypatch.setattr(det, "detect_llm_availability",
                        lambda: type("A", (), {"claude_code": False})())
    with pytest.raises(RedactionUnavailable):
        R.build_guard_config()


def test_guard_config_prefers_anthropic_haiku(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = R.build_guard_config()
    assert cfg.provider == "anthropic"
    assert cfg.model_name == R.GUARD_MODEL
    assert S.model_is_trusted(cfg) is True  # never a guarded guard


# --------------------------------------------------------------------------
# Provider hook wiring
# --------------------------------------------------------------------------

def test_provider_generate_structured_calls_redaction(monkeypatch):
    R.set_enabled(True)
    captured = {}

    def _mock_redact_prompt(config, prompt, system_prompt=None, out_dir=None):
        captured["called"] = True
        return "[REDACTED]", system_prompt

    monkeypatch.setattr(R, "redact_prompt", _mock_redact_prompt)

    # Build an OpenAICompatibleProvider pointed at omni; stub the network
    # so we only exercise the redaction hook, not a real API call.
    from core.llm.providers import OpenAICompatibleProvider
    from core.llm.config import ModelConfig
    prov = object.__new__(OpenAICompatibleProvider)
    prov.config = ModelConfig(provider="omni", model_name="cc/x",
                              api_base="https://omniroute.grigoreo.dev/v1", api_key="k")
    prov.instructor_client = None

    class _Boom(Exception):
        pass

    def _explode(*a, **k):
        raise _Boom()

    # After redaction runs, the method proceeds to build a pydantic model;
    # make that explode so we stop right after the hook.
    monkeypatch.setattr("core.llm.providers._dict_schema_to_pydantic", _explode)
    with pytest.raises(_Boom):
        prov.generate_structured("secret prompt", {"type": "object"})
    assert captured.get("called") is True
