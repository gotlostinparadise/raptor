"""Offline tests for the source registry loader and tool-runner parse helpers."""

from __future__ import annotations

from core.recon.registry import load_sources
from core.recon.source import all_sources
from core.recon.toolrunner import parse_jsonl, tool_available


def test_load_sources_populates_registry():
    load_sources(force=True)
    names = set(all_sources())
    assert {"crtsh", "censys", "subfinder", "dnsx", "naabu", "httpx"} <= names


def test_load_sources_is_idempotent():
    r1 = load_sources(force=True)
    r2 = load_sources()   # cached: no work
    assert r1["loaded"]
    assert r2 == {"loaded": [], "skipped": []}


def test_parse_jsonl_skips_noise():
    stdout = (
        "banner line, not json\n"
        '{"host": "a.example.com"}\n'
        "\n"
        "not json either\n"
        '{"host": "b.example.com"}\n'
        '["a list is not a dict"]\n'
    )
    rows = parse_jsonl(stdout)
    assert [r["host"] for r in rows] == ["a.example.com", "b.example.com"]


def test_tool_available_for_missing_binary():
    assert tool_available("definitely-not-a-real-binary-xyz") is False
