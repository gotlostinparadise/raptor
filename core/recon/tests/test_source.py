"""Tests for core.recon.source — the plugin interface, registry, and the
cross-source security conformance guard. Fully offline."""

from pathlib import Path

import pytest

from core.recon import source as S
from core.recon.model import DnsRecord, DISCOVERY_ACTIVE
from core.recon.source import (
    Assets, PROFILES, Profile, RunContext, Source, SourceResult,
)


# ─────────────────────────── fakes ───────────────────────────

class FakeSource(Source):
    name = "fake"
    egress_hosts = ("api.example.com",)
    credential_env_vars = ("FAKE_API_KEY",)
    consumes = ("ips",)
    produces = ("dns",)
    active = False

    def run(self, ctx: RunContext) -> SourceResult:
        return SourceResult(source=self.name)


class ActiveSource(Source):
    name = "active-fake"
    produces = ()
    active = True

    def run(self, ctx: RunContext) -> SourceResult:  # pragma: no cover - trivial
        return SourceResult(source=self.name)


@pytest.fixture
def clean_registry():
    """Snapshot and restore the module-global registry around a test."""
    saved = dict(S._REGISTRY)
    S._REGISTRY.clear()
    try:
        yield
    finally:
        S._REGISTRY.clear()
        S._REGISTRY.update(saved)


def _ctx(**overrides):
    base = dict(
        roots=("x.com",),
        assets=Assets(names={"x.com"}, ips={"1.2.3.4"}),
        profile=PROFILES["home"],
        raw_dir=Path("/tmp/raw"),
        normalized_dir=Path("/tmp/normalized"),
    )
    base.update(overrides)
    return RunContext(**base)


# ─────────────────────────── Assets ───────────────────────────

def test_assets_merge_unions_in_place():
    a = Assets(names={"a.x.com"}, ips={"1.1.1.1"})
    b = Assets(names={"b.x.com"}, ips={"1.1.1.1", "2.2.2.2"}, certs={"deadbeef"})
    ret = a.merge(b)
    assert ret is a
    assert a.names == {"a.x.com", "b.x.com"}
    assert a.ips == {"1.1.1.1", "2.2.2.2"}
    assert a.certs == {"deadbeef"}


def test_assets_copy_is_independent():
    a = Assets(names={"a.x.com"})
    c = a.copy()
    c.names.add("b.x.com")
    assert a.names == {"a.x.com"}


def test_assets_len_and_bool():
    assert not Assets()
    a = Assets(names={"a"}, ips={"1"}, certs={"c"})
    assert len(a) == 3
    assert bool(a)


# ─────────────────────────── profiles ───────────────────────────

def test_named_profiles_exist_with_expected_gates():
    assert set(PROFILES) >= {"passive", "home", "vps"}
    assert PROFILES["passive"].allow_active is False
    assert PROFILES["home"].allow_active is True
    assert PROFILES["home"].allow_massdns is False
    assert PROFILES["vps"].allow_massdns is True


def test_home_profile_carries_router_safety_knobs():
    knobs = PROFILES["home"].knobs
    assert knobs["dns_rate"] == 300
    assert knobs["resolvers"] == 5


# ─────────────────────────── Source contract ───────────────────────────

def test_bad_produces_rejected_at_class_definition():
    with pytest.raises(ValueError):
        class Bad(Source):        # noqa: unused - definition triggers the check
            name = "bad"
            produces = ("not-a-kind",)

            def run(self, ctx):   # pragma: no cover
                return SourceResult(source="bad")


def test_active_source_gated_by_profile():
    src = ActiveSource()
    assert src.enabled_for(PROFILES["home"]) is True
    assert src.enabled_for(PROFILES["passive"]) is False


def test_passive_source_runs_under_all_profiles():
    src = FakeSource()
    assert src.enabled_for(PROFILES["passive"]) is True


def test_has_credentials_reflects_context():
    src = FakeSource()
    assert src.has_credentials(_ctx()) is False
    assert src.has_credentials(_ctx(credentials={"FAKE_API_KEY": "k"})) is True


def test_available_requires_creds_and_profile():
    src = FakeSource()
    assert src.available(_ctx()) is False
    assert src.available(_ctx(credentials={"FAKE_API_KEY": "k"})) is True


# ─────────────────────────── registry ───────────────────────────

def test_register_get_all_unregister(clean_registry):
    S.register(FakeSource)
    assert S.get_source("fake") is FakeSource
    assert "fake" in S.all_sources()
    S.unregister("fake")
    assert "fake" not in S.all_sources()


def test_register_rejects_empty_name(clean_registry):
    class Nameless(Source):
        produces = ()

        def run(self, ctx):  # pragma: no cover
            return SourceResult(source="")

    with pytest.raises(ValueError):
        S.register(Nameless)


def test_register_rejects_name_collision(clean_registry):
    S.register(FakeSource)

    class Other(Source):
        name = "fake"
        produces = ()

        def run(self, ctx):  # pragma: no cover
            return SourceResult(source="fake")

    with pytest.raises(ValueError):
        S.register(Other)


def test_registered_credential_env_vars_unions(clean_registry):
    S.register(FakeSource)
    assert S.registered_credential_env_vars() == frozenset({"FAKE_API_KEY"})


# ─────────────────────────── RunContext ───────────────────────────

def test_http_client_uses_injected_factory():
    captured = {}

    def factory(hosts):
        captured["hosts"] = hosts
        return "stub-client"

    ctx = _ctx(http_factory=factory)
    client = ctx.http_client(FakeSource())
    assert client == "stub-client"
    assert captured["hosts"] == ["api.example.com"]


def test_credential_returns_none_when_absent():
    assert _ctx().credential("FAKE_API_KEY") is None
    assert _ctx(credentials={"FAKE_API_KEY": "k"}).credential("FAKE_API_KEY") == "k"


def test_path_helpers():
    ctx = _ctx(raw_dir=Path("/r"), normalized_dir=Path("/n"))
    assert ctx.raw_path("crtsh.jsonl") == Path("/r/crtsh.jsonl")
    assert ctx.normalized_path("hosts") == Path("/n/hosts.jsonl")


# ─────────────────────────── SourceResult ───────────────────────────

def test_result_add_record_and_tuple():
    res = SourceResult(source="fake")
    res.add(DnsRecord(name="a.x.com", a=["1.2.3.4"], discovery=DISCOVERY_ACTIVE))
    res.add(("hosts", {"ip": "1.2.3.4", "asn": "AS1"}))
    assert res.record_count() == 2
    assert res.records["dns"][0]["name"] == "a.x.com"
    assert res.records["hosts"][0]["ip"] == "1.2.3.4"


def test_result_add_unknown_kind_raises():
    res = SourceResult(source="fake")
    with pytest.raises(ValueError):
        res.add(("bogus", {"x": 1}))


# ─────────────────────── security conformance ───────────────────────

def test_no_recon_credential_leaks_into_safe_env(clean_registry, monkeypatch):
    """Every registered source's declared credential env var must be absent
    from RaptorConfig.SAFE_ENV_ALLOWLIST and stripped by get_safe_env().

    This is the generic form of temp-99's per-Censys assertion: it iterates the
    registry, so a source added later that forgets this is caught here.
    """
    from core.config import RaptorConfig

    class CredSource(Source):
        name = "cred-fake"
        credential_env_vars = ("CENSYS_API_KEY", "SHODAN_API_KEY")
        produces = ()

        def run(self, ctx):  # pragma: no cover
            return SourceResult(source="cred-fake")

    S.register(CredSource)
    declared = S.registered_credential_env_vars()
    assert {"CENSYS_API_KEY", "SHODAN_API_KEY"} <= declared

    for var in declared:
        monkeypatch.setenv(var, "secret-value")
        assert var not in RaptorConfig.SAFE_ENV_ALLOWLIST
        assert var not in RaptorConfig.get_safe_env()
