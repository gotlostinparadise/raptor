"""Offline tests for bruteforce + the exposed-origin / vhost probes.

bruteforce is driven with a fake dnsx ``runner``; the two probes with a fake
``prober`` returning canned :class:`ProbeResult`s — so the verdict logic is
exercised with no curl, sandbox, or network.
"""

from __future__ import annotations

import json

import pytest

from core.recon import bruteforce as bf_mod
from core.recon import exposed_origin as eo_mod
from core.recon import vhost as vh_mod
from core.recon.probe import ProbeResult
from core.recon.source import Assets, PROFILES, RunContext
from core.recon.toolrunner import ToolResult


def _ctx(tmp_path, *, names=(), ips=(), roots=("example.com",), profile="home"):
    raw = tmp_path / "raw"
    norm = tmp_path / "normalized"
    raw.mkdir(parents=True, exist_ok=True)
    norm.mkdir(parents=True, exist_ok=True)
    return RunContext(
        roots=tuple(roots), assets=Assets(names=set(names), ips=set(ips)),
        profile=PROFILES[profile], raw_dir=raw, normalized_dir=norm,
        env={"PATH": "/usr/bin"}, credentials={},
    )


# ─────────────────────────── bruteforce ───────────────────────────

def test_bruteforce_resolves_candidates(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("api\ndev\n# comment\n\n", encoding="utf-8")

    def runner(cmd, **kwargs):
        runner.cmd = cmd
        # dnsx "resolves" one of the generated candidates
        return ToolResult(stdout=json.dumps(
            {"host": "api.example.com", "a": ["203.0.113.9"], "status_code": "NOERROR"}
        ) + "\n")

    src = bf_mod.BruteforceSource(wordlist=str(wl), runner=runner)
    assert src.active is True
    ctx = _ctx(tmp_path)
    r = src.run(ctx)
    # candidate file was api.example.com / dev.example.com
    cand = (tmp_path / "raw" / "bruteforce-candidates.txt").read_text()
    assert "api.example.com" in cand and "dev.example.com" in cand
    assert r.records["dns"][0]["discovery"] == "active"
    assert any(s["name"] == "api.example.com" for s in r.records["subdomains"])
    assert "203.0.113.9" in r.discovered.ips


def test_bruteforce_unavailable_without_wordlist(tmp_path):
    src = bf_mod.BruteforceSource(wordlist=None)
    assert src.available(_ctx(tmp_path)) is False


def test_bruteforce_passes_wordlist_as_readable_path(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("api\n", encoding="utf-8")
    captured = {}

    def runner(cmd, **kwargs):
        captured.update(kwargs)
        return ToolResult(stdout="")

    bf_mod.BruteforceSource(wordlist=str(wl), runner=runner).run(_ctx(tmp_path))
    assert str(wl.resolve()) in captured["readable_paths"]


# ─────────────────────────── vhost ───────────────────────────

def test_vhost_reachable_when_distinct_and_2xx(tmp_path):
    def prober(scheme, ip, host, **kwargs):
        if host.startswith("zzq9-nope"):        # baseline: default vhost
            return ProbeResult(status=200, body_sha256="BASE", content_length=10)
        return ProbeResult(status=200, body_sha256="REAL", content_length=99,
                           title="Admin", server="nginx")

    src = vh_mod.VhostSource(prober=prober)
    ctx = _ctx(tmp_path, names={"secret.example.com"}, ips={"203.0.113.9"})
    r = src.run(ctx)
    recs = r.records.get("vhost", [])
    assert len(recs) == 2   # https + http both distinct
    assert all(rec["verdict"] == "reachable_vhost" for rec in recs)
    assert "secret.example.com" in r.discovered.names


def test_vhost_challenge_is_not_reachable(tmp_path):
    def prober(scheme, ip, host, **kwargs):
        if host.startswith("zzq9-nope"):
            return ProbeResult(status=200, body_sha256="BASE")
        return ProbeResult(status=200, body_sha256="X", server="ddos-guard")

    src = vh_mod.VhostSource(prober=prober)
    r = src.run(_ctx(tmp_path, names={"a.example.com"}, ips={"1.2.3.4"}))
    assert "vhost" not in r.records
    # but the challenge probes are still recorded raw
    raw = (tmp_path / "raw" / "vhost.jsonl").read_text()
    assert '"verdict": "challenge"' in raw


def test_vhost_same_as_baseline_is_default(tmp_path):
    def prober(scheme, ip, host, **kwargs):
        return ProbeResult(status=200, body_sha256="SAME", content_length=5)

    src = vh_mod.VhostSource(prober=prober)
    r = src.run(_ctx(tmp_path, names={"a.example.com"}, ips={"1.2.3.4"}))
    assert "vhost" not in r.records   # candidate == default vhost


# ─────────────────────────── exposed_origin ───────────────────────────

def test_exposed_origin_flags_real_backend(tmp_path):
    def prober(scheme, ip, host, **kwargs):
        return ProbeResult(status=200, body_sha256="ORIGIN", content_length=1234,
                           title="Home", server="nginx")

    src = eo_mod.ExposedOriginSource(prober=prober)
    r = src.run(_ctx(tmp_path, ips={"203.0.113.9"}))
    recs = r.records.get("origin", [])
    assert len(recs) == 2   # https + http
    assert all(rec["verdict"] == "exposed_origin" for rec in recs)
    assert all(rec["host_header"] == "example.com" for rec in recs)


def test_exposed_origin_challenge_not_flagged(tmp_path):
    def prober(scheme, ip, host, **kwargs):
        return ProbeResult(status=403, body_sha256="X", server="cloudflare",
                           title="Just a moment...")

    src = eo_mod.ExposedOriginSource(prober=prober)
    r = src.run(_ctx(tmp_path, ips={"1.2.3.4"}))
    assert "origin" not in r.records
    raw = (tmp_path / "raw" / "origin.jsonl").read_text()
    assert '"verdict": "challenge"' in raw
