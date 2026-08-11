"""Tests for core.webgraph.builder — records → graph."""

from core.webgraph import model as M
from core.webgraph.builder import build_graph


def _rows(*recs):
    """Group Record instances into the records_by_kind map the builder wants."""
    out = {}
    for r in recs:
        out.setdefault(r.KIND, []).append(r.to_row())
    return out


def test_endpoint_creates_node_and_origin_hosts_edge():
    recs = _rows(M.EndpointRecord(method="get", path="/api/users/1",
                                  origin="https://x.com", object_scoped=True))
    g = build_graph(recs, ["https://x.com"])
    # object ids collapse: endpoint id is templated
    assert ("endpoint", "GET /api/users/{id}") in g.nodes
    assert (("origin", "https://x.com"),
            ("endpoint", "GET /api/users/{id}"), M.REL_HOSTS) in g.edges


def test_two_object_ids_merge_onto_one_endpoint():
    recs = _rows(
        M.EndpointRecord(method="GET", path="/u/1", origin="https://x.com"),
        M.EndpointRecord(method="GET", path="/u/2", origin="https://x.com"),
    )
    g = build_graph(recs, ["https://x.com"])
    endpoints = [k for k in g.nodes if k[0] == "endpoint"]
    assert endpoints == [("endpoint", "GET /u/{id}")]


def test_parameter_attaches_to_endpoint():
    eid = "GET /u/{id}"
    recs = _rows(M.ParamRecord(endpoint_id=eid, name="sort", location=M.LOC_QUERY))
    g = build_graph(recs)
    pid = ("parameter", f"{eid}|query:sort")
    assert pid in g.nodes
    assert (("endpoint", eid), pid, M.REL_HAS_PARAM) in g.edges


def test_request_becomes_accessible_as_edge_with_evidence():
    eid = "GET /u/{id}"
    recs = _rows(M.RequestRecord(endpoint_id=eid, identity="user_b",
                                 status=200, resp_len=99, allowed=True))
    g = build_graph(recs)
    key = (("identity", "user_b"), ("endpoint", eid), M.REL_ACCESSIBLE_AS)
    assert key in g.edges
    assert g.edges[key]["status"] == 200 and g.edges[key]["allowed"] is True


def test_form_links_page_and_derives_submit_endpoint():
    recs = _rows(M.FormRecord(page_url="https://x.com/login", action="/session",
                              method="post", fields=["user", "pass"]))
    g = build_graph(recs, ["https://x.com"])
    assert any(k[0] == "form" for k in g.nodes)
    # action resolved against page origin, method upper-cased, templatised
    assert ("endpoint", "POST /session") in g.nodes
    assert any(rel == M.REL_SUBMITS_TO for (_s, _d, rel) in g.edges)


def test_vuln_links_endpoint_and_records_status():
    eid = "GET /u/{id}"
    recs = _rows(M.VulnRecord(id="V1", vuln_class="bola", endpoint_id=eid,
                              status=M.STATUS_CONFIRMED,
                              proof_kind=M.PROOF_AUTHZ_DIFF, severity="high"))
    g = build_graph(recs)
    assert ("vuln", "V1") in g.nodes
    assert g.nodes[("vuln", "V1")]["attrs"]["status"] == M.STATUS_CONFIRMED
    assert (("endpoint", eid), ("vuln", "V1"), M.REL_VULNERABLE_TO) in g.edges


def test_builder_is_pure_and_deterministic():
    recs = _rows(
        M.EndpointRecord(method="GET", path="/u/1", origin="https://x.com"),
        M.RequestRecord(endpoint_id="GET /u/{id}", identity="user_a", status=200),
    )
    g1 = build_graph(recs, ["https://x.com"])
    g2 = build_graph(recs, ["https://x.com"])
    assert g1.to_json() == g2.to_json()


def test_unknown_and_absent_kinds_ignored():
    g = build_graph({"nope": [{"x": 1}], "endpoints": []}, [])
    assert g.stats()["node_count"] == 0
