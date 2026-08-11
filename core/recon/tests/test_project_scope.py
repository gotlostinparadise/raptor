"""Tests for recon_scope project persistence + the CLI fallback to it."""

from __future__ import annotations

import json

import pytest

from core.project.project import Project, ProjectManager
from core.project.schema import _validate_project
from core.recon import cli


def test_save_scope_invokes_set_recon_scope(tmp_path, monkeypatch):
    """--save-scope is the writer the recon_scope fallback needs: the CLI path
    must call ProjectManager.set_recon_scope with the resolved roots + profile."""
    import core.project.project as pp

    captured = {}

    class FakePM:
        def __init__(self, *a, **k):
            pass

        def get_active(self):
            return type("P", (), {"name": "acme"})()

        def set_recon_scope(self, name, roots, profile=None):
            captured["name"] = name
            captured["roots"] = list(roots)
            captured["profile"] = profile

    monkeypatch.setattr(pp, "ProjectManager", FakePM)
    monkeypatch.setattr(cli, "load_sources", lambda: None)

    def fake_run_recon(roots, out_dir, **kw):
        from core.recon.orchestrator import RunSummary
        return RunSummary(out_dir=str(out_dir), roots=list(roots),
                          profile=kw.get("profile"), rounds=0)

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)

    rc = cli.main(["acme.com", "acme.io", "--out-dir", str(tmp_path / "run"),
                   "--profile", "passive", "--save-scope"])
    assert rc == 0
    assert captured == {"name": "acme", "roots": ["acme.com", "acme.io"],
                        "profile": "passive"}


def test_save_scope_no_active_project_is_graceful(tmp_path, monkeypatch):
    import core.project.project as pp

    class NoActivePM:
        def __init__(self, *a, **k):
            pass

        def get_active(self):
            return None

    monkeypatch.setattr(pp, "ProjectManager", NoActivePM)
    monkeypatch.setattr(cli, "load_sources", lambda: None)
    monkeypatch.setattr(cli, "run_recon", lambda roots, out_dir, **kw: __import__(
        "core.recon.orchestrator", fromlist=["RunSummary"]).RunSummary(
        out_dir=str(out_dir), roots=list(roots), profile=kw.get("profile"), rounds=0))
    # no active project -> warns, still exits 0
    rc = cli.main(["acme.com", "--out-dir", str(tmp_path / "run"),
                   "--profile", "passive", "--save-scope"])
    assert rc == 0


def test_recon_scope_round_trips():
    p = Project(name="acme", target="acme.com", output_dir="/tmp/acme",
                recon_scope={"roots": ["acme.com", "acme.io"], "profile": "vps"})


def test_recon_scope_round_trips():
    p = Project(name="acme", target="acme.com", output_dir="/tmp/acme",
                recon_scope={"roots": ["acme.com", "acme.io"], "profile": "vps"})
    d = p.to_dict()
    assert d["version"] == 4
    assert d["recon_scope"] == {"roots": ["acme.com", "acme.io"], "profile": "vps"}
    back = Project.from_dict(d)
    assert back.recon_scope == p.recon_scope


def test_recon_scope_defaults_and_bad_shape():
    assert Project.from_dict({"name": "x"}).recon_scope == {}
    # a non-dict recon_scope is coerced to {}
    assert Project.from_dict({"name": "x", "recon_scope": ["bad"]}).recon_scope == {}


def test_schema_validates_recon_scope():
    ok, errs = _validate_project({
        "version": 4, "name": "x", "target": "t", "output_dir": "o",
        "recon_scope": {"roots": ["a.com"], "profile": "home"},
    })
    assert ok, errs
    bad, errs = _validate_project({
        "version": 4, "name": "x", "target": "t", "output_dir": "o",
        "recon_scope": {"roots": ["a.com", ""]},
    })
    assert not bad
    assert any("recon_scope.roots[1]" in e for e in errs)


def test_set_recon_scope_persists(tmp_path):
    pm = ProjectManager(projects_dir=tmp_path / "projects")
    pm.create("proj1", "acme.com", output_dir=str(tmp_path / "out"))
    updated = pm.set_recon_scope("proj1", ["acme.com", " acme.com ", "acme.io"], profile="vps")
    assert updated.recon_scope["roots"] == ["acme.com", "acme.io"]   # de-duped + stripped
    assert updated.recon_scope["profile"] == "vps"
    # reload from disk
    reloaded = pm.load("proj1")
    assert reloaded.recon_scope["roots"] == ["acme.com", "acme.io"]
    # and the persisted file passes schema validation
    raw = json.loads((tmp_path / "projects" / "proj1.json").read_text())
    ok, errs = _validate_project(raw)
    assert ok, errs


def test_cli_falls_back_to_project_scope(tmp_path, monkeypatch):
    # no roots + no scope-file -> use the project scope the monkeypatched
    # _project_scope returns; passive profile so no network/gate.
    monkeypatch.setattr(cli, "_project_scope", lambda: (["proj.example.com"], "passive"))

    captured = {}

    def fake_run_recon(roots, out_dir, **kwargs):
        captured["roots"] = list(roots)
        captured["profile"] = kwargs.get("profile")
        from core.recon.orchestrator import RunSummary
        return RunSummary(out_dir=str(out_dir), roots=list(roots),
                          profile=kwargs.get("profile"), rounds=0)

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)
    rc = cli.main(["--out-dir", str(tmp_path)])
    assert rc == 0
    assert captured["roots"] == ["proj.example.com"]
    assert captured["profile"] == "passive"


def test_cli_explicit_profile_overrides_project(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_project_scope", lambda: (["p.example.com"], "vps"))
    captured = {}

    def fake_run_recon(roots, out_dir, **kwargs):
        captured["profile"] = kwargs.get("profile")
        from core.recon.orchestrator import RunSummary
        return RunSummary(out_dir=str(out_dir), roots=list(roots),
                          profile=kwargs.get("profile"), rounds=0)

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)
    # explicit passive on the CLI must win over the project's vps
    rc = cli.main(["--out-dir", str(tmp_path), "--profile", "passive"])
    assert rc == 0
    assert captured["profile"] == "passive"
