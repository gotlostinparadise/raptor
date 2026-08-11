"""Tests for core.webgraph.graph — the typed app-layer graph + exporters."""

import xml.etree.ElementTree as ET

from core.webgraph.graph import Graph, TYPES


def test_node_returns_key_and_coerces_id_to_str():
    g = Graph()
    assert g.node("endpoint", "GET /a") == ("endpoint", "GET /a")
    assert g.node("origin", 1) == ("origin", "1")


def test_scalar_attr_first_writer_wins_lists_union_empty_dropped():
    g = Graph()
    g.node("endpoint", "GET /a", method="GET", owasp_focus=["API1"], path="")
    g.node("endpoint", "GET /a", method="POST", owasp_focus=["API1", "API3"])
    attrs = g.nodes[("endpoint", "GET /a")]["attrs"]
    assert attrs["method"] == "GET"                    # first-writer-wins
    assert attrs["owasp_focus"] == ["API1", "API3"]    # union, order-preserving
    assert "path" not in attrs                          # empty dropped


def test_edge_attrs_overwrite_on_repeat():
    g = Graph()
    i = g.node("identity", "user_a")
    e = g.node("endpoint", "GET /a/{id}")
    g.edge(i, e, "accessible_as", status=403)
    g.edge(i, e, "accessible_as", status=200)   # a re-replay: freshest wins
    assert g.edges[(i, e, "accessible_as")]["status"] == 200
    assert len(g.edges) == 1


def test_edge_with_none_endpoint_dropped():
    g = Graph()
    a = g.node("origin", "https://x.com")
    g.edge(a, None, "hosts")
    g.edge(None, a, "hosts")
    assert g.edges == {}


def test_to_json_colours_and_indexes():
    g = Graph()
    g.node("vuln", "V1")
    data = g.to_json()
    assert data["nodes"][0]["id"] == "vuln:V1"
    assert data["nodes"][0]["color"] == TYPES["vuln"]["color"]


def test_to_json_omits_edges_with_phantom_endpoints():
    g = Graph()
    a = g.node("origin", "https://x.com")
    g.edge(a, ("endpoint", "ghost"), "hosts")
    assert g.to_json()["edges"] == []


def test_stats_counts_by_type():
    g = Graph()
    g.node("endpoint", "GET /a")
    g.node("endpoint", "GET /b")
    g.node("identity", "user_a")
    stats = g.to_json()["stats"]
    assert stats["node_count"] == 3 and stats["by_type"] == {
        "endpoint": 2, "identity": 1
    }


def test_to_dot_header_and_edges():
    g = Graph()
    a = g.node("origin", "https://x.com")
    b = g.node("endpoint", "GET /a")
    g.edge(a, b, "hosts")
    dot = g.to_dot()
    assert dot.startswith("digraph webgraph {")
    assert '"origin:https://x.com" -> "endpoint:GET /a" [label="hosts"];' in dot


def test_to_graphml_well_formed_and_escapes():
    g = Graph()
    a = g.node("endpoint", "GET /a?x&y")   # ampersand must be escaped
    b = g.node("vuln", "V1")
    g.edge(a, b, "vulnerable_to")
    xml = g.to_graphml()
    root = ET.fromstring(xml)   # raises if malformed
    ns = "{http://graphml.graphdrawing.org/xmlns}"
    assert len(root.findall(f".//{ns}node")) == 2
    assert len(root.findall(f".//{ns}edge")) == 1
