"""Offline tests for the recon orchestrator: discovery loop, persistence, gating."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.recon.model import DISCOVERY_ACTIVE, DnsRecord, PortRecord, SubdomainRecord
from core.recon.orchestrator import (
    load_records, persist_records, rebuild_from_disk, run_recon,
)
from core.recon.source import (
    Source, SourceResult, _REGISTRY, register, unregister,
)


@pytest.fixture
def clean_registry():
    snapshot = dict(_REGISTRY)
    try:
        yield
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(snapshot)


class _Discoverer(Source):
    """Passive fake: seeds one subdomain per root, resolves known subs to an IP."""

    name = "t_discoverer"
    consumes = ("roots", "names")
    produces = ("subdomains", "dns")
    active = False

    def run(self, ctx):
        r = SourceResult(source=self.name)
        for root in ctx.roots:
            sub = f"api.{root}"
            if sub not in ctx.assets.names:
                r.add(SubdomainRecord(name=sub, root=root, sources=["t"]))
                r.discovered.names.add(sub)
        for n in sorted(ctx.assets.names):
            if n not in ctx.roots:
                r.add(DnsRecord(name=n, a=["203.0.113.7"], discovery=DISCOVERY_ACTIVE))
                r.discovered.ips.add("203.0.113.7")
        return r


class _ActivePortScan(Source):
    name = "t_ports"
    consumes = ("ips",)
    produces = ("ports",)
    active = True

    def run(self, ctx):
        r = SourceResult(source=self.name)
        for ip in sorted(ctx.assets.ips):
            r.add(PortRecord(ip=ip, port=443, proto="tcp", source="t"))
        return r


def test_discovery_loop_recurses_to_fixed_point(tmp_path):
    summary = run_recon(["example.com"], tmp_path, sources=[_Discoverer], profile="passive")
    # round 1 finds api.example.com; round 2 resolves it (grows ips); round 3 stable
    assert summary.rounds >= 2
    assert summary.asset_counts == {"names": 2, "ips": 1, "certs": 0}
    graph = json.loads((tmp_path / "graph" / "recon.json").read_text())
    ids = {n["id"] for n in graph["nodes"]}
    assert "subdomain:api.example.com" in ids
    assert "ip:203.0.113.7" in ids


def test_records_persisted_and_rebuildable(tmp_path):
    run_recon(["example.com"], tmp_path, sources=[_Discoverer], profile="passive")
    assert (tmp_path / "normalized" / "subdomains.jsonl").exists()
    reloaded = load_records(tmp_path / "normalized")
    assert reloaded["subdomains"][0]["name"] == "api.example.com"
    # rebuild reproduces the same graph from disk with no sources
    g = rebuild_from_disk(tmp_path, ["example.com"])
    assert g.stats()["node_count"] == 3


def test_passive_profile_skips_active_sources(tmp_path):
    summary = run_recon(
        ["example.com"], tmp_path,
        sources=[_Discoverer, _ActivePortScan], profile="passive",
    )
    assert "t_ports" not in summary.sources_run
    assert "ports" not in summary.record_counts


def test_active_source_runs_under_home_profile(tmp_path):
    summary = run_recon(
        ["example.com"], tmp_path,
        sources=[_Discoverer, _ActivePortScan], profile="home",
    )
    assert "t_ports" in summary.sources_run
    assert summary.record_counts.get("ports") == 1


def test_seed_ips_feeds_ip_consumers(tmp_path):
    summary = run_recon(
        ["example.com"], tmp_path, sources=[_ActivePortScan], profile="home",
        seed_ips=["198.51.100.9"],
    )
    assert summary.record_counts.get("ports") == 1
    reloaded = load_records(tmp_path / "normalized")
    assert reloaded["ports"][0]["ip"] == "198.51.100.9"


def test_row_dedup_across_rounds(tmp_path):
    """A source re-emitting identical rows each round persists them once."""

    class _Repeater(Source):
        name = "t_repeater"
        consumes = ("roots",)
        produces = ("subdomains",)
        active = False

        def run(self, ctx):
            r = SourceResult(source=self.name)
            # always re-discover the same name -> keeps the loop going one extra
            # round, but the row must not duplicate in the normalized file
            r.add(SubdomainRecord(name="dup.example.com", root="example.com", sources=["t"]))
            r.discovered.names.add("dup.example.com")
            return r

    run_recon(["example.com"], tmp_path, sources=[_Repeater], profile="passive")
    lines = (tmp_path / "normalized" / "subdomains.jsonl").read_text().splitlines()
    assert len([ln for ln in lines if ln.strip()]) == 1


def test_broken_source_does_not_abort_run(tmp_path):
    class _Broken(Source):
        name = "t_broken"
        produces = ()
        active = False

        def run(self, ctx):
            raise RuntimeError("boom")

    summary = run_recon(
        ["example.com"], tmp_path, sources=[_Broken, _Discoverer], profile="passive",
    )
    assert "t_broken" in summary.errors
    assert "t_discoverer" in summary.sources_run
