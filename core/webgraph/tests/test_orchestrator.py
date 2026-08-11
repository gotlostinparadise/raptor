"""Tests for core.webgraph.orchestrator — run-loop, persistence, serialisation."""

import json

from core.webgraph import model as M
from core.webgraph.orchestrator import (
    load_records, rebuild_from_disk, run_webgraph,
)
from core.webgraph.source import Source, SourceResult, Surface


class _CrawlStub(Source):
    """A fake active source: emits one endpoint + request, discovers one URL."""

    name = "_crawl_stub"
    active = True
    produces = ("endpoints", "requests")

    def run(self, ctx):
        r = SourceResult(source=self.name)
        r.add(M.EndpointRecord(method="GET", path="/api/users/1",
                               origin="https://x.com", source=self.name))
        r.add(M.RequestRecord(endpoint_id="GET /api/users/{id}",
                              identity="anonymous", status=200, source=self.name))
        r.discovered = Surface(urls={"https://x.com/api/users/1"})
        return r


def test_run_persists_records_and_serialises_graph(tmp_path):
    summary = run_webgraph(
        ["https://x.com"], tmp_path, sources=[_CrawlStub()], profile="safe",
    )
    assert summary.sources_run == ["_crawl_stub"]
    assert summary.record_counts.get("endpoints") == 1
    assert summary.node_count >= 2 and summary.edge_count >= 1

    # normalized/*.jsonl written
    assert (tmp_path / "normalized" / "endpoints.jsonl").exists()
    # graph exports written
    web_json = json.loads((tmp_path / "graph" / "web.json").read_text())
    ids = {n["id"] for n in web_json["nodes"]}
    assert "endpoint:GET /api/users/{id}" in ids
    # summary sidecar written
    assert (tmp_path / "webgraph-summary.json").exists()


def test_passive_profile_drops_active_source(tmp_path):
    summary = run_webgraph(
        ["https://x.com"], tmp_path, sources=[_CrawlStub()], profile="passive",
    )
    assert summary.sources_run == []
    assert summary.record_counts == {}
    assert summary.node_count == 1  # only the seeded origin node


def test_broken_source_recorded_not_fatal(tmp_path):
    class _Boom(Source):
        name = "_boom"
        active = True
        produces = ("pages",)

        def run(self, ctx):
            raise RuntimeError("kaboom")

    summary = run_webgraph(
        ["https://x.com"], tmp_path, sources=[_Boom(), _CrawlStub()],
        profile="safe",
    )
    assert "_boom" in summary.errors
    assert "_crawl_stub" in summary.sources_run  # the good source still ran


def test_rebuild_from_disk_is_pure(tmp_path):
    run_webgraph(["https://x.com"], tmp_path, sources=[_CrawlStub()], profile="safe")
    records = load_records(tmp_path / "normalized")
    assert "endpoints" in records
    g = rebuild_from_disk(tmp_path, ["https://x.com"])
    assert ("endpoint", "GET /api/users/{id}") in g.nodes


def test_discovery_loop_stops_at_fixed_point(tmp_path):
    # _CrawlStub discovers the same URL every round → surface stops growing → 1 round
    summary = run_webgraph(
        ["https://x.com"], tmp_path, sources=[_CrawlStub()], profile="safe",
        max_rounds=5,
    )
    assert summary.rounds <= 2
