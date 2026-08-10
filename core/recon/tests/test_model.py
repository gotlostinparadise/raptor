"""Tests for core.recon.model — normalised record schema + vocabulary."""

from core.recon import graph
from core.recon import model as M


def test_record_types_map_matches_kinds():
    assert set(M.RECORD_TYPES) == set(M.RECORD_KINDS)
    for kind, cls in M.RECORD_TYPES.items():
        assert cls.KIND == kind


def test_node_types_match_graph_palette():
    # The model's node-type names must be exactly the graph's palette keys,
    # or a source could emit a node the renderer has no colour for.
    assert set(M.NODE_TYPES) == set(graph.TYPES)


def test_kind_classvar_not_in_row():
    rec = M.SubdomainRecord(name="a.x.com", root="x.com", sources=["crtsh"])
    row = rec.to_row()
    assert "KIND" not in row
    assert row == {"name": "a.x.com", "root": "x.com", "sources": ["crtsh"]}


def test_dns_discovery_defaults_passive_and_is_settable():
    passive = M.DnsRecord(name="a.x.com", a=["1.2.3.4"])
    assert passive.discovery == M.DISCOVERY_PASSIVE
    active = M.DnsRecord(name="b.x.com", a=["1.2.3.5"], discovery=M.DISCOVERY_ACTIVE)
    assert active.to_row()["discovery"] == "active"


def test_new_record_kinds_present():
    # ports / certs / netblock are the three kinds added over the prototype.
    for kind in ("ports", "certs", "netblock"):
        assert kind in M.RECORD_KINDS


def test_port_record_round_trip():
    rec = M.PortRecord(ip="1.2.3.4", port=22, proto="tcp", software="OpenSSH",
                       source="censys")
    assert rec.to_row() == {
        "ip": "1.2.3.4", "port": 22, "proto": "tcp",
        "software": "OpenSSH", "source": "censys",
    }


def test_normalized_filename():
    assert M.normalized_filename("hosts") == "hosts.jsonl"


def test_every_relation_constant_is_in_the_tuple():
    rels = {getattr(M, n) for n in dir(M) if n.startswith("REL_")}
    assert rels == set(M.EDGE_RELATIONS)
