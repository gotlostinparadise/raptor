"""Tests for core.webauthz.template + cli."""

import json

from core.webauthz.cli import main
from core.webauthz.template import template_from_inventory

_INVENTORY = {
    "base_url": "https://api.x.com",
    "endpoints": [
        {"method": "GET", "path": "/users/{userId}", "object_scoped": True,
         "privileged": False},
        {"method": "DELETE", "path": "/admin/purge", "object_scoped": False,
         "privileged": True},
        {"method": "GET", "path": "/health", "object_scoped": False,
         "privileged": False},
    ],
}


def test_template_makes_bola_and_bfla_tests():
    t = template_from_inventory(_INVENTORY)
    classes = {row["class"] for row in t["tests"]}
    assert classes == {"bola", "bfla"}
    assert t["authorization"] == ""            # operator must fill it
    assert any(i["name"] == "admin" for i in t["identities"])
    # the non-sensitive /health endpoint is not tested
    assert all("/health" not in row["path"] for row in t["tests"])


def test_template_from_matrix_shape():
    matrix = {"base_url": "https://api.x.com", "tests": [
        {"method": "GET", "path": "/o/{id}", "test_type": "BOLA"},
        {"method": "POST", "path": "/admin/x", "test_type": "BFLA"},
    ]}
    t = template_from_inventory(matrix)
    assert {r["class"] for r in t["tests"]} == {"bola", "bfla"}


def test_cli_init_writes_template(tmp_path):
    inv = tmp_path / "inv.json"
    inv.write_text(json.dumps(_INVENTORY), encoding="utf-8")
    rc = main(["--out-dir", str(tmp_path / "run"), "--init",
               "--inventory", str(inv)])
    assert rc == 0
    cfg = json.loads((tmp_path / "run" / "authz-config.json").read_text())
    assert cfg["base_url"] == "https://api.x.com"
    assert len(cfg["tests"]) == 2


def test_cli_dry_run(tmp_path, capsys):
    cfg = {
        "base_url": "https://api.x.com",
        "identities": [{"name": "user_a", "login": {"type": "bearer", "token_env": "UA"}}],
        "tests": [{"id": "AZ-1", "method": "GET", "path": "/o/1", "owner": "user_a"}],
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    rc = main(["--out-dir", str(tmp_path / "run"), "--config", str(cfg_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run" in out and "run with --active" in out


def test_cli_active_without_authorization_errors(tmp_path, capsys):
    cfg = {
        "base_url": "https://api.x.com",
        "identities": [{"name": "user_a", "login": {"type": "none"}}],
        "tests": [{"id": "AZ-1", "method": "GET", "path": "/o/1", "owner": "user_a"}],
    }
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    rc = main(["--out-dir", str(tmp_path / "run"), "--config", str(cfg_path), "--active"])
    assert rc == 2
    assert "authorization" in capsys.readouterr().err
