"""Pure tests for core.browser.capture — no browser needed."""

from core.browser.capture import (
    FormCapture, NetworkRequest, PageCapture, records_from_capture,
)
from core.webgraph import model as M


def _capture():
    return PageCapture(
        url="https://app.x.com/dash",
        final_url="https://app.x.com/dash",
        title="Dashboard",
        status=200,
        links=["https://app.x.com/orders", "https://evil.com/x"],
        forms=[FormCapture(action="https://app.x.com/search", method="GET",
                           fields=["q"])],
        requests=[
            NetworkRequest("https://app.x.com/api/items?page=2&sort=name",
                           method="GET", resource_type="fetch", status=200),
            NetworkRequest("https://app.x.com/logo.png", method="GET",
                           resource_type="image", status=200),  # asset, not API
        ],
    )


def test_api_requests_filters_out_assets():
    cap = _capture()
    apis = cap.api_requests()
    assert len(apis) == 1 and apis[0].resource_type == "fetch"


def test_records_from_capture_emits_page_endpoint_param_form_origin():
    recs = records_from_capture(_capture())
    assert set(recs) >= {"pages", "endpoints", "parameters", "forms", "origins"}

    page = recs["pages"][0]
    assert page["rendered"] is True and page["url"] == "https://app.x.com/dash"

    # runtime fetch became a templated endpoint + its query params
    ep = recs["endpoints"][0]
    assert ep["method"] == "GET" and ep["path"] == "/api/items"
    pnames = {p["name"] for p in recs["parameters"]}
    assert pnames == {"page", "sort"}
    assert all(p["location"] == M.LOC_QUERY for p in recs["parameters"])

    # the image asset did NOT become an endpoint
    assert all(e["path"] != "/logo.png" for e in recs["endpoints"])

    form = recs["forms"][0]
    assert form["action"] == "https://app.x.com/search" and form["fields"] == ["q"]


def test_records_feed_the_web_graph():
    from core.webgraph.builder import build_graph
    g = build_graph(records_from_capture(_capture()), ["https://app.x.com"])
    assert ("endpoint", "GET /api/items") in g.nodes
    assert ("page", "https://app.x.com/dash") in g.nodes
    # rendered page hangs off its origin
    assert (("origin", "https://app.x.com"), ("page", "https://app.x.com/dash"),
            M.REL_HOSTS) in g.edges
