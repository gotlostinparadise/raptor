"""Test isolation for the injection suite.

The runner now feeds the payload flywheel on every confirmed finding
(:func:`core.payloads.feedback.record_confirmed`). Without isolation those
writes would land in the operator's real ``~/.raptor/payload-feedback.jsonl``
and — if the SAGE flag were set — in live SAGE memory. Redirect the log to a
per-test temp file and keep the SAGE opt-in off.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_payload_feedback(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_PAYLOAD_FEEDBACK", str(tmp_path / "feedback.jsonl"))
    monkeypatch.delenv("RAPTOR_PAYLOAD_SAGE", raising=False)
    yield
