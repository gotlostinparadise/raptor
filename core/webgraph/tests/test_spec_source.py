"""Tests for core.webgraph.spec_source — offline API-spec → graph import."""

import json

from core.webgraph import model as M
from core.webgraph.orchestrator import run_webgraph
from core.webgraph.spec_source import ApiSpecImportSource
from core.webgraph.source import RunContext, Surface, PROFILES

_OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/users/{userId}": {
            "get": {
                "parameters": [
                    {"name": "userId", "in": "path", "required": True},
                    {"name": "expand", "in": "query"},
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/admin/users": {
            "post": {
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"email": {"type": "string"},
                                   "role": {"type": "string"}},
                }}}},
                "responses": {"201": {"description": "created"}},
            }
        },
    },
}


def _write_spec(tmp_path):
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps(_OPENAPI), encoding="utf-8")
    return p


def _ctx(tmp_path, profile="passive"):
    return RunContext(
        origins=(), surface=Surface(), profile=PROFILES[profile],
        raw_dir=tmp_path, normalized_dir=tmp_path,
    )


def test_available_requires_existing_spec(tmp_path):
    assert ApiSpecImportSource(spec_path=None).available(_ctx(tmp_path)) is False
    spec = _write_spec(tmp_path)
    assert ApiSpecImportSource(spec_path=str(spec)).available(_ctx(tmp_path)) is True


def test_import_emits_endpoints_params_and_origin(tmp_path):
    spec = _write_spec(tmp_path)
    src = ApiSpecImportSource(spec_path=str(spec))
    res = src.run(_ctx(tmp_path))
    assert res.error is None
    kinds = res.records
    assert "endpoints" in kinds and "parameters" in kinds and "origins" in kinds
    # object-scoped endpoint recognised
    ep = [e for e in kinds["endpoints"] if e["path"] == "/users/{userId}"][0]
    assert ep["object_scoped"] is True
    # param locations mapped
    locs = {p["name"]: p["location"] for p in kinds["parameters"]}
    assert locs["userId"] == M.LOC_PATH and locs["expand"] == M.LOC_QUERY


def test_spec_import_runs_under_passive_profile_end_to_end(tmp_path):
    spec = _write_spec(tmp_path)
    out = tmp_path / "run"
    summary = run_webgraph(
        [], out, sources=[ApiSpecImportSource(spec_path=str(spec))],
        profile="passive",
    )
    # active=False → spec import runs even passively (spec-only is safe)
    assert "api_spec_import" in summary.sources_run
    web = json.loads((out / "graph" / "web.json").read_text())
    ids = {n["id"] for n in web["nodes"]}
    assert "endpoint:GET /users/{userId}" in ids
    assert any(i.startswith("parameter:GET /users/{userId}|path:userId") for i in ids)
    assert any(n["type"] == "origin" for n in web["nodes"])
