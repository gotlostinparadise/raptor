"""Keep payload-catalog tests off the operator's real flywheel + SAGE."""

import pytest


@pytest.fixture(autouse=True)
def _isolate_payload_feedback(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_PAYLOAD_FEEDBACK", str(tmp_path / "feedback.jsonl"))
    monkeypatch.delenv("RAPTOR_PAYLOAD_SAGE", raising=False)
    yield
