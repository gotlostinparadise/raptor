"""Tests for core.recon.graph — the typed asset graph + exporters."""

import xml.etree.ElementTree as ET

from core.recon.graph import Graph, TYPES


def test_node_returns_key_and_creates_node():
    g = Graph()
    key = g.node("ip", "1.2.3.4")
    assert key == ("ip", "1.2.3.4")
    assert g.nodes[key]["type"] == "ip"
    assert g.nodes[key]["id"] == "1.2.3.4"


def test_node_id_coerced_to_str():
    g = Graph()
    key = g.node("service", 443)
    assert key == ("service", "443")


def test_node_merge_is_idempotent_on_key():
    g = Graph()
    g.node("ip", "1.2.3.4")
    g.node("ip", "1.2.3.4")
    assert len(g.nodes) == 1


def test_scalar_attr_is_first_writer_wins():
    g = Graph()
    g.node("ip", "1.2.3.4", org="First")
    g.node("ip", "1.2.3.4", org="Second")
    assert g.nodes[("ip", "1.2.3.4")]["attrs"]["org"] == "First"


def test_list_attr_unions_without_duplicates_and_preserves_order():
    g = Graph()
    g.node("subdomain", "a.x.com", sources=["subfinder", "crtsh"])
    g.node("subdomain", "a.x.com", sources=["crtsh", "censys"])
    assert g.nodes[("subdomain", "a.x.com")]["attrs"]["sources"] == [
        "subfinder", "crtsh", "censys"
    ]


def test_empty_values_are_ignored():
    g = Graph()
    g.node("ip", "1.2.3.4", org="", city=None, tags=[], meta={})
    assert g.nodes[("ip", "1.2.3.4")]["attrs"] == {}


def test_edge_idempotent_on_src_dst_rel():
    g = Graph()
    a = g.node("root", "x.com")
    b = g.node("subdomain", "a.x.com")
    g.edge(a, b, "has_subdomain")
    g.edge(a, b, "has_subdomain")
    assert len(g.edges) == 1


def test_edge_with_none_endpoint_is_dropped():
    g = Graph()
    a = g.node("root", "x.com")
    g.edge(a, None, "has_subdomain")
    g.edge(None, a, "has_subdomain")
    assert g.edges == {}


def test_to_json_indexes_nodes_and_colours_them():
    g = Graph()
    g.node("root", "x.com")
    data = g.to_json()
    assert data["nodes"][0]["id"] == "root:x.com"
    assert data["nodes"][0]["color"] == TYPES["root"]["color"]
    assert data["nodes"][0]["label"] == "x.com"


def test_to_json_omits_edges_with_missing_endpoints():
    g = Graph()
    a = g.node("root", "x.com")
    # dst node was never created via node(); edge references a phantom key
    g.edge(a, ("subdomain", "ghost.x.com"), "has_subdomain")
    data = g.to_json()
    assert data["edges"] == []


def test_to_json_emits_edges_between_real_nodes():
    g = Graph()
    a = g.node("root", "x.com")
    b = g.node("subdomain", "a.x.com")
    g.edge(a, b, "has_subdomain")
    data = g.to_json()
    assert data["edges"] == [
        {"source": "root:x.com", "target": "subdomain:a.x.com", "rel": "has_subdomain"}
    ]


def test_stats_counts_by_type():
    g = Graph()
    g.node("ip", "1.1.1.1")
    g.node("ip", "2.2.2.2")
    g.node("root", "x.com")
    stats = g.to_json()["stats"]
    assert stats["node_count"] == 3
    assert stats["edge_count"] == 0
    assert stats["by_type"] == {"ip": 2, "root": 1}


def test_to_dot_contains_nodes_and_edges():
    g = Graph()
    a = g.node("root", "x.com")
    b = g.node("subdomain", "a.x.com")
    g.edge(a, b, "has_subdomain")
    dot = g.to_dot()
    assert dot.startswith("digraph recon {")
    assert '"root:x.com"' in dot
    assert '"root:x.com" -> "subdomain:a.x.com" [label="has_subdomain"];' in dot


def test_to_graphml_is_well_formed_and_escapes():
    g = Graph()
    a = g.node("root", "x&y.com")   # ampersand must be XML-escaped
    b = g.node("subdomain", "a.x.com")
    g.edge(a, b, "has_subdomain")
    xml = g.to_graphml()
    root = ET.fromstring(xml)   # raises if malformed
    ns = "{http://graphml.graphdrawing.org/xmlns}"
    nodes = root.findall(f".//{ns}node")
    assert len(nodes) == 2
    assert len(root.findall(f".//{ns}edge")) == 1
