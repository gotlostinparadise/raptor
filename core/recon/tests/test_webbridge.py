"""Offline test for the infra->app bridge (recon http records -> webgraph)."""

from __future__ import annotations

import json

from core.recon.webbridge import _origins_from_records, build_web_graph


def test_origins_derived_from_http_records():
    records = {"http": [
        {"host": "api.example.com", "url": "https://api.example.com/v1", "status": 200},
        {"host": "api.example.com", "url": "https://api.example.com/v2", "status": 200},
        {"host": "www.example.com", "url": "", "status": 200},
        {"host": "", "url": ""},   # nothing usable -> skipped
    ]}
    origins = _origins_from_records(records)
    # both api.example.com URLs collapse to one origin; www derives from host
    assert "https://api.example.com" in origins
    assert "https://www.example.com" in origins
    assert len(origins) == 2


def test_build_web_graph_writes_origin_nodes(tmp_path):
    (tmp_path / "normalized").mkdir(parents=True)
    (tmp_path / "normalized" / "http.jsonl").write_text(
        json.dumps({"host": "api.example.com", "url": "https://api.example.com"}) + "\n",
        encoding="utf-8",
    )
    summary = build_web_graph(tmp_path, ["example.com"], profile="home")
    assert summary.profile == "safe"   # home -> safe mapping
    graph = json.loads((tmp_path / "web" / "graph" / "web.json").read_text())
    ids = {n["id"] for n in graph["nodes"]}
    assert "origin:https://api.example.com" in ids


def test_profile_mapping():
    from core.recon.webbridge import _PROFILE_MAP
    assert _PROFILE_MAP == {"passive": "passive", "home": "safe", "vps": "aggressive"}
