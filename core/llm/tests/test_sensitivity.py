"""Tests for ``core.llm.sensitivity`` — the per-target external-LLM
egress gate (Feature 1).

Covers: the trust model, tri-state resolution (env / context / dormant),
UNKNOWN -> SENSITIVE fail-closed behaviour, the registry round-trip and
marker file, and the create_provider enforcement point.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import pytest

from core.llm import sensitivity as S
from core.llm.sensitivity import OmniEgressBlocked


@dataclass
class FakeCfg:
    provider: str
    model_name: str = "m"
    api_base: Optional[str] = None


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Every test gets a private registry, no env override, and a clean
    module context."""
    monkeypatch.setenv("RAPTOR_SENSITIVITY_REGISTRY", str(tmp_path / "reg.json"))
    monkeypatch.delenv("RAPTOR_SENSITIVE", raising=False)
    S.reset_current()
    yield
    S.reset_current()


# --------------------------------------------------------------------------
# Trust model
# --------------------------------------------------------------------------

@pytest.mark.parametrize("provider", [
    "anthropic", "bedrock", "ollama",
    "claudecode", "claude_code", "claude-code",
    "claudecode-resumable",
])
def test_first_party_providers_trusted(provider):
    assert S.model_is_trusted(FakeCfg(provider=provider)) is True


def test_omni_provider_is_guarded():
    cfg = FakeCfg(provider="omni",
                  api_base="https://omniroute.grigoreo.dev/v1")
    assert S.model_is_trusted(cfg) is False


def test_openai_and_gemini_guarded():
    assert S.model_is_trusted(FakeCfg(provider="openai")) is False
    assert S.model_is_trusted(FakeCfg(provider="gemini")) is False


def test_anthropic_host_via_generic_provider_trusted():
    # Someone points a generic OpenAI-compatible provider straight at
    # Anthropic — the host, not just the provider name, earns trust.
    cfg = FakeCfg(provider="custom", api_base="https://api.anthropic.com/v1")
    assert S.model_is_trusted(cfg) is True


def test_loopback_host_trusted():
    cfg = FakeCfg(provider="vllm", api_base="http://127.0.0.1:8000/v1")
    assert S.model_is_trusted(cfg) is True


def test_unknown_host_non_trusted_provider_is_guarded():
    cfg = FakeCfg(provider="mystery", api_base=None)
    assert S.model_is_trusted(cfg) is False


# --------------------------------------------------------------------------
# Tri-state resolution
# --------------------------------------------------------------------------

def test_dormant_by_default_allows_everything():
    # No context set, no env -> UNSET -> gate dormant -> guard is a no-op.
    assert S.current_state() == S.UNSET
    S.guard_model(FakeCfg(provider="omni",
                          api_base="https://omniroute.grigoreo.dev/v1"))


def test_env_override_forces_sensitive(monkeypatch):
    monkeypatch.setenv("RAPTOR_SENSITIVE", "1")
    assert S.current_state() == S.SENSITIVE
    with pytest.raises(OmniEgressBlocked):
        S.guard_model(FakeCfg(provider="omni",
                              api_base="https://omniroute.grigoreo.dev/v1"))


def test_env_override_external_ok_allows(monkeypatch):
    monkeypatch.setenv("RAPTOR_SENSITIVE", "external_ok")
    assert S.current_state() == S.EXTERNAL_OK
    S.guard_model(FakeCfg(provider="omni",
                          api_base="https://omniroute.grigoreo.dev/v1"))


def test_env_wins_over_context(monkeypatch):
    S.set_current_target("project:known-external")
    S.set_classification("project:known-external", sensitive=False)
    S.set_current_target("project:known-external")
    assert S.current_state() == S.EXTERNAL_OK
    monkeypatch.setenv("RAPTOR_SENSITIVE", "sensitive")
    assert S.current_state() == S.SENSITIVE


# --------------------------------------------------------------------------
# UNKNOWN -> SENSITIVE fail-closed
# --------------------------------------------------------------------------

def test_unknown_target_defaults_sensitive(tmp_path):
    state = S.set_current_target(tmp_path)
    assert state == S.SENSITIVE
    assert S.current_target_is_known() is False
    with pytest.raises(OmniEgressBlocked):
        S.guard_model(FakeCfg(provider="omni",
                              api_base="https://omniroute.grigoreo.dev/v1"))


def test_unknown_target_still_allows_first_party(tmp_path):
    S.set_current_target(tmp_path)
    # Sensitive, but Anthropic/Claude Code are allowed.
    S.guard_model(FakeCfg(provider="anthropic"))
    S.guard_model(FakeCfg(provider="claude_code"))


def test_none_target_is_sensitive():
    assert S.set_current_target(None) == S.SENSITIVE
    assert S.current_target_is_known() is False


# --------------------------------------------------------------------------
# Registry + marker
# --------------------------------------------------------------------------

def test_registry_roundtrip(tmp_path):
    t = tmp_path / "proj"
    t.mkdir()
    assert S.get_classification(t) is None
    S.set_classification(t, sensitive=False, note="public OSS")
    assert S.get_classification(t) is False
    S.set_classification(t, sensitive=True)
    assert S.get_classification(t) is True


def test_external_ok_target_allows_omni(tmp_path):
    t = tmp_path / "public"
    t.mkdir()
    S.set_classification(t, sensitive=False)
    assert S.set_current_target(t) == S.EXTERNAL_OK
    assert S.current_target_is_known() is True
    S.guard_model(FakeCfg(provider="omni",
                          api_base="https://omniroute.grigoreo.dev/v1"))


def test_marker_file_forces_sensitive_over_registry(tmp_path):
    t = tmp_path / "eng"
    t.mkdir()
    S.set_classification(t, sensitive=False)  # registry says external ok...
    (t / S.MARKER_FILENAME).write_text("")    # ...but marker wins.
    assert S.get_classification(t) is True


def test_malformed_registry_treated_empty(tmp_path, monkeypatch):
    reg = tmp_path / "bad.json"
    reg.write_text("{ not json")
    monkeypatch.setenv("RAPTOR_SENSITIVITY_REGISTRY", str(reg))
    assert S.get_classification(tmp_path) is None  # fail-closed downstream


def test_registry_written_0600(tmp_path):
    t = tmp_path / "p"
    t.mkdir()
    S.set_classification(t, sensitive=True)
    reg = tmp_path / "reg.json"
    assert oct(reg.stat().st_mode & 0o777) == "0o600"


# --------------------------------------------------------------------------
# create_provider enforcement point
# --------------------------------------------------------------------------

def test_create_provider_blocks_guarded_when_sensitive(monkeypatch):
    from core.llm.providers import create_provider
    from core.llm.config import ModelConfig
    monkeypatch.setenv("RAPTOR_SENSITIVE", "sensitive")
    cfg = ModelConfig(provider="omni", model_name="cc/claude-opus-5",
                      api_base="https://omniroute.grigoreo.dev/v1",
                      api_key="x")
    with pytest.raises(OmniEgressBlocked):
        create_provider(cfg)


def test_engage_for_run_unknown_blocks_and_propagates(tmp_path, monkeypatch):
    monkeypatch.delenv("RAPTOR_SENSITIVE", raising=False)
    state = S.engage_for_run(tmp_path, tmp_path)
    assert state == S.SENSITIVE
    # propagated to env for any worker children
    assert os.environ.get("RAPTOR_SENSITIVE") == S.SENSITIVE


def test_engage_for_run_respects_operator_env(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_SENSITIVE", "external_ok")
    S.engage_for_run(tmp_path, tmp_path)
    # operator override is never clobbered
    assert os.environ["RAPTOR_SENSITIVE"] == "external_ok"


def test_engage_for_run_never_raises(monkeypatch):
    # A broken registry path must not break run startup.
    monkeypatch.setenv("RAPTOR_SENSITIVITY_REGISTRY", "/proc/nonexistent/x/y")
    monkeypatch.delenv("RAPTOR_SENSITIVE", raising=False)
    # Should not raise regardless.
    S.engage_for_run("/some/target", None)


def test_create_provider_audit_written(tmp_path, monkeypatch):
    from core.llm.config import ModelConfig
    monkeypatch.setenv("RAPTOR_SENSITIVE", "sensitive")
    S.set_current_target("project:x", out_dir=tmp_path)
    cfg = ModelConfig(provider="omni", model_name="cc/x",
                      api_base="https://omniroute.grigoreo.dev/v1", api_key="x")
    with pytest.raises(OmniEgressBlocked):
        from core.llm.providers import create_provider
        create_provider(cfg)
    audit = tmp_path / "omni-egress.jsonl"
    assert audit.is_file()
    assert "deny" in audit.read_text()
