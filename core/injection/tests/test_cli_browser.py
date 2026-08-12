"""Q4 — standalone `/inject` parity with the orchestrator: browser + form-context.

Two guarantees:

  * ``--browser`` / ``--llm-model`` are accepted and the DOM-XSS harness is only
    built when the browser is actually requested (and available) — no harness
    otherwise, so a plain run stays HTTP-only.
  * ``--from-webgraph`` round-trips the sibling **form-context** (``others``) and
    ``content_type`` through the config, the same fields the orchestrator fix
    preserved. Dropping them here silently re-breaks the submit-gated classes
    (sqli/cmdi) for standalone runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.injection.cli import _build_parser, _harness_from, _load
from core.webgraph.scope import endpoint_id


def _args(argv):
    return _build_parser().parse_args(argv)


def test_new_flags_parse():
    a = _args(["--out-dir", "o", "--config", "c.json", "--browser",
               "--llm-model", "gpt", "--oast-auto"])
    assert a.browser is True and a.llm_model == "gpt" and a.oast_auto is True


def test_harness_none_without_browser():
    a = _args(["--out-dir", "o", "--base-url", "http://127.0.0.1:3000",
               "--from-webgraph", "d", "--active"])
    assert _harness_from(a) is None


def test_harness_none_on_dry_run():
    # --browser but no --active: a dry-run confirms nothing, so no browser.
    a = _args(["--out-dir", "o", "--base-url", "http://127.0.0.1:3000",
               "--from-webgraph", "d", "--browser"])
    assert _harness_from(a) is None


def test_harness_none_when_browser_unavailable(monkeypatch):
    # active + --browser requested but Playwright/Chromium absent → graceful None.
    import core.browser.harness as bh
    monkeypatch.setattr(bh, "available", lambda: False)
    a = _args(["--out-dir", "o", "--base-url", "http://127.0.0.1:3000",
               "--from-webgraph", "d", "--browser", "--active"])
    assert _harness_from(a) is None


def _seed_webgraph(root: Path) -> None:
    """A minimal /webgraph normalized dir: a POST /login with a submit sibling."""
    nd = root / "normalized"
    nd.mkdir(parents=True)
    eid = endpoint_id("POST", "/login")
    (nd / "endpoints.jsonl").write_text(
        json.dumps({"method": "POST", "path": "/login"}) + "\n")
    (nd / "parameters.jsonl").write_text("\n".join(
        json.dumps({"endpoint_id": eid, "name": name, "location": "body"})
        for name in ("username", "password", "Login")) + "\n")


def test_from_webgraph_preserves_form_context(tmp_path):
    _seed_webgraph(tmp_path)
    a = _args(["--out-dir", "o", "--from-webgraph", str(tmp_path),
               "--base-url", "http://app.test", "--authorization", "ok"])
    cfg = _load(a)
    by_param = {p.param: p for p in cfg.points}
    assert set(by_param) == {"username", "password", "Login"}
    # each point carries its same-endpoint siblings as form-context
    assert by_param["username"].others == {"password": "password", "Login": "Login"}
    assert by_param["username"].location == "body"
    assert by_param["username"].content_type == "form"
