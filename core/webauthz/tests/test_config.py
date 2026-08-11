"""Tests for core.webauthz.config — schema, validation, load."""

import json

import pytest

from core.webauthz import config as C


_BASE = {
    "base_url": "https://api.x.com",
    "identities": [
        {"name": "user_a", "login": {"type": "bearer", "token_env": "UA"}},
        {"name": "user_b", "login": {"type": "bearer", "token_env": "UB"}},
    ],
    "tests": [
        {"id": "AZ-1", "method": "GET", "path": "/api/orders/1001",
         "owner": "user_a", "class": "bola", "others": ["user_b", "anonymous"]},
    ],
}


def test_from_dict_builds_config_and_endpoint_id():
    cfg = C.from_dict(_BASE)
    assert cfg.base_url == "https://api.x.com"
    assert cfg.tests[0].endpoint_id == "GET /api/orders/{id}"
    assert cfg.credential_env_vars() == ["UA", "UB"]


def test_missing_owner_rejected():
    bad = json.loads(json.dumps(_BASE))
    del bad["tests"][0]["owner"]
    with pytest.raises(ValueError):
        C.from_dict(bad)


def test_unknown_identity_rejected():
    bad = json.loads(json.dumps(_BASE))
    bad["tests"][0]["others"] = ["ghost"]
    with pytest.raises(ValueError):
        C.from_dict(bad)


def test_base_url_required():
    with pytest.raises(ValueError):
        C.from_dict({"identities": [], "tests": []})


def test_load_config_json(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(_BASE), encoding="utf-8")
    cfg = C.load_config(p)
    assert len(cfg.tests) == 1
