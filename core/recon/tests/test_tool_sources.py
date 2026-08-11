"""Offline tests for the active tool-wrapper sources.

Each source is driven with an injected ``runner`` that returns canned tool
stdout, so no binary, sandbox, or network is touched. We assert the declared
contract, the emitted records, discovered-asset growth, and the availability
gating (profile + binary-on-PATH).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.recon import dnsx as dnsx_mod
from core.recon import httpx as httpx_mod
from core.recon import naabu as naabu_mod
from core.recon import subfinder as subfinder_mod
from core.recon.source import Assets, PROFILES, RunContext
from core.recon.toolrunner import ToolResult


def _ctx(tmp_path, *, names=(), ips=(), roots=("example.com",), profile="home"):
    raw = tmp_path / "raw"
    norm = tmp_path / "normalized"
    raw.mkdir(parents=True, exist_ok=True)
    norm.mkdir(parents=True, exist_ok=True)
    return RunContext(
        roots=tuple(roots),
        assets=Assets(names=set(names), ips=set(ips)),
        profile=PROFILES[profile],
        raw_dir=raw, normalized_dir=norm,
        env={"PATH": "/usr/bin"}, credentials={},
    )


def _fake(stdout):
    def runner(cmd, **kwargs):
        runner.cmd = cmd
        runner.kwargs = kwargs
        return ToolResult(stdout=stdout)
    return runner


# ─────────────────────────── subfinder ───────────────────────────

def test_subfinder_contract_and_records(tmp_path):
    src = subfinder_mod.SubfinderSource(runner=_fake(
        json.dumps({"host": "api.example.com", "source": "crtsh"}) + "\n"
        + json.dumps({"host": "www.example.com"}) + "\n"
        + json.dumps({"host": "evil.notexample.com"}) + "\n"   # out of scope
        + json.dumps({"host": "example.com"}) + "\n"           # apex, not a sub
    ))
    assert src.active is False
    assert src.produces == ("subdomains",)
    ctx = _ctx(tmp_path, profile="passive")   # passive runs it (active=False)
    r = src.run(ctx)
    names = {row["name"] for row in r.records.get("subdomains", [])}
    assert names == {"api.example.com", "www.example.com"}
    assert "api.example.com" in r.discovered.names
    assert (tmp_path / "raw" / "subfinder.jsonl").exists()


# ─────────────────────────── dnsx ───────────────────────────

def test_dnsx_emits_active_dns_and_discovers_ips(tmp_path):
    src = dnsx_mod.DnsxSource(runner=_fake(
        json.dumps({"host": "api.example.com", "a": ["203.0.113.5"],
                    "cname": ["cdn.example.com"], "status_code": "NOERROR"}) + "\n"
    ))
    assert src.active is True
    ctx = _ctx(tmp_path, names={"api.example.com"})
    r = src.run(ctx)
    rec = r.records["dns"][0]
    assert rec["a"] == ["203.0.113.5"]
    assert rec["discovery"] == "active"
    assert "203.0.113.5" in r.discovered.ips
    assert "cdn.example.com" in r.discovered.names   # in-scope CNAME chased


def test_dnsx_reads_rate_knobs_from_profile(tmp_path):
    runner = _fake("")
    src = dnsx_mod.DnsxSource(runner=runner)
    src.run(_ctx(tmp_path, names={"api.example.com"}, profile="vps"))
    # vps knobs: dns_rate=300, dns_threads=100
    assert "300" in runner.cmd
    assert "100" in runner.cmd


# ─────────────────────────── naabu ───────────────────────────

def test_naabu_emits_ports(tmp_path):
    src = naabu_mod.NaabuSource(runner=_fake(
        json.dumps({"ip": "203.0.113.5", "port": 443, "protocol": "tcp"}) + "\n"
        + json.dumps({"ip": "203.0.113.5", "port": 22, "protocol": "tcp"}) + "\n"
    ))
    ctx = _ctx(tmp_path, ips={"203.0.113.5"})
    r = src.run(ctx)
    ports = sorted(row["port"] for row in r.records["ports"])
    assert ports == [22, 443]
    assert all(row["source"] == "naabu" for row in r.records["ports"])


# ─────────────────────────── httpx ───────────────────────────

def test_httpx_emits_http_and_tls(tmp_path):
    src = httpx_mod.HttpxSource(runner=_fake(
        json.dumps({
            "input": "api.example.com", "url": "https://api.example.com",
            "status_code": 200, "title": "Home", "webserver": "nginx",
            "tech": ["Nginx"], "content_length": 42, "a": ["203.0.113.5"],
            "tls": {"subject_cn": "api.example.com",
                    "subject_an": ["api.example.com", "new.example.com"],
                    "issuer_org": "Lets Encrypt"},
        }) + "\n"
    ))
    assert src.produces == ("http", "tls")
    ctx = _ctx(tmp_path, names={"api.example.com"})
    r = src.run(ctx)
    http = r.records["http"][0]
    assert http["host"] == "api.example.com"
    assert http["status"] == 200
    assert http["server"] == "nginx"
    assert http["ip"] == "203.0.113.5"
    tls = r.records["tls"][0]
    assert "new.example.com" in tls["san"]
    # in-scope SAN becomes a discovered name
    assert "new.example.com" in r.discovered.names


def test_httpx_proxy_hosts_are_the_probed_names(tmp_path):
    runner = _fake("")
    src = httpx_mod.HttpxSource(runner=runner)
    src.run(_ctx(tmp_path, names={"api.example.com", "www.example.com"}))
    assert set(runner.kwargs["proxy_hosts"]) == {"api.example.com", "www.example.com"}


# ─────────────────────────── availability gating ───────────────────────────

def test_active_source_unavailable_in_passive_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(naabu_mod, "tool_available", lambda b: True)
    src = naabu_mod.NaabuSource()
    assert src.available(_ctx(tmp_path, profile="passive")) is False
    assert src.available(_ctx(tmp_path, profile="home")) is True


def test_source_unavailable_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(subfinder_mod, "tool_available", lambda b: False)
    src = subfinder_mod.SubfinderSource()
    assert src.available(_ctx(tmp_path, profile="passive")) is False
