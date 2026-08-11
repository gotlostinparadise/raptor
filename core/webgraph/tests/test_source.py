"""Tests for core.webgraph.source — plugin interface, registry, profiles."""

import pytest

from core.webgraph import model as M
from core.webgraph.source import (
    DEFAULT_PROFILE, PROFILES, Profile, Source, SourceResult, Surface,
    all_sources, get_source, register, unregister,
)


def test_surface_merge_and_len():
    a = Surface(origins={"https://x.com"}, urls={"https://x.com/a"})
    b = Surface(urls={"https://x.com/b"}, endpoints={"GET /a"})
    a.merge(b)
    assert a.urls == {"https://x.com/a", "https://x.com/b"}
    assert len(a) == 4 and bool(a)


def test_profiles_gate_active_sources():
    assert PROFILES["passive"].allow_active is False
    assert PROFILES["safe"].allow_active is True
    assert DEFAULT_PROFILE == "safe"


def test_source_result_add_validates_kind():
    r = SourceResult(source="t")
    r.add(M.EndpointRecord(method="GET", path="/a"))
    r.add((M.PageRecord.KIND, {"url": "https://x.com/a"}))
    assert r.record_count() == 2
    with pytest.raises(ValueError):
        r.add(("bogus_kind", {}))


def test_bad_produces_rejected_at_class_definition():
    with pytest.raises(ValueError):
        class _Bad(Source):
            name = "_bad"
            produces = ("not_a_kind",)

            def run(self, ctx):  # pragma: no cover
                return SourceResult(source=self.name)


def test_enabled_for_respects_active_flag():
    class _Active(Source):
        name = "_active_probe"
        active = True
        produces = ("pages",)

        def run(self, ctx):  # pragma: no cover
            return SourceResult(source=self.name)

    s = _Active()
    assert s.enabled_for(PROFILES["safe"]) is True
    assert s.enabled_for(PROFILES["passive"]) is False


def test_registry_register_lookup_and_duplicate_guard():
    class _R(Source):
        name = "_reg_test"
        produces = ("origins",)

        def run(self, ctx):  # pragma: no cover
            return SourceResult(source=self.name)

    try:
        register(_R)
        assert get_source("_reg_test") is _R
        assert "_reg_test" in all_sources()
        with pytest.raises(ValueError):
            @register
            class _Dup(Source):
                name = "_reg_test"
                produces = ()

                def run(self, ctx):  # pragma: no cover
                    return SourceResult(source=self.name)
    finally:
        unregister("_reg_test")
