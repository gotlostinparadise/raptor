"""Tests for core.recon.builder — records -> graph reconstruction."""

from core.recon import model as M
from core.recon.builder import build_graph, root_of

ROOTS = ["x.com"]


def _edges(g):
    """Set of (src_type:src_id, dst_type:dst_id, rel) for easy assertions."""
    return {
        (f"{s[0]}:{s[1]}", f"{d[0]}:{d[1]}", rel)
        for (s, d, rel) in g.edges
    }


def _attrs(g, ntype, nid):
    return g.nodes[(ntype, str(nid))]["attrs"]


# ─────────────────────────── roots / subdomains ───────────────────────────

def test_roots_become_root_nodes():
    g = build_graph({}, ROOTS)
    assert ("root", "x.com") in g.nodes


def test_subdomain_record_builds_node_and_edge():
    recs = {"subdomains": [{"name": "a.x.com", "root": "x.com", "sources": ["crtsh"]}]}
    g = build_graph(recs, ROOTS)
    assert _attrs(g, "subdomain", "a.x.com")["sources"] == ["crtsh"]
    assert ("root:x.com", "subdomain:a.x.com", "has_subdomain") in _edges(g)


def test_subdomain_record_skips_a_root_name():
    recs = {"subdomains": [{"name": "x.com", "root": "x.com", "sources": ["x"]}]}
    g = build_graph(recs, ROOTS)
    # x.com is a root, not a subdomain node
    assert ("subdomain", "x.com") not in g.nodes


# ─────────────────────────── dns ───────────────────────────

def test_dns_discovery_is_read_from_the_record_not_a_filename():
    # This is the active/passive fix: the field on the record decides.
    recs = {"dns": [
        {"name": "a.x.com", "a": ["1.2.3.4"], "discovery": "active"},
        {"name": "b.x.com", "a": ["1.2.3.5"], "discovery": "passive"},
    ]}
    g = build_graph(recs, ROOTS)
    assert _attrs(g, "subdomain", "a.x.com")["discovery"] == "active"
    assert _attrs(g, "subdomain", "b.x.com")["discovery"] == "passive"


def test_dns_builds_resolves_to_and_cname_edges():
    recs = {"dns": [{"name": "a.x.com", "a": ["1.2.3.4"], "aaaa": ["::1"],
                     "cname": ["cdn.example.net"]}]}
    g = build_graph(recs, ROOTS)
    e = _edges(g)
    assert ("subdomain:a.x.com", "ip:1.2.3.4", "resolves_to") in e
    assert ("subdomain:a.x.com", "ip:::1", "resolves_to") in e
    assert ("subdomain:a.x.com", "subdomain:cdn.example.net", "cname") in e


def test_dns_root_name_resolves_as_root_node():
    recs = {"dns": [{"name": "x.com", "a": ["1.2.3.4"], "discovery": "passive"}]}
    g = build_graph(recs, ROOTS)
    assert _attrs(g, "root", "x.com")["resolves"] is True
    assert ("root:x.com", "ip:1.2.3.4", "resolves_to") in _edges(g)


# ─────────────────────────── hosts (ipmeta + cdncheck) ───────────────────────────

def test_host_record_builds_org_and_announced_by():
    recs = {"hosts": [{"ip": "1.2.3.4", "asn": "AS123", "org": "Acme",
                       "country": "US", "city": "NYC"}]}
    g = build_graph(recs, ROOTS)
    assert _attrs(g, "ip", "1.2.3.4")["org"] == "Acme"
    assert _attrs(g, "ip", "1.2.3.4")["city"] == "NYC"
    assert ("ip:1.2.3.4", "org:Acme", "announced_by") in _edges(g)


def test_host_edge_classification_builds_edge_provider():
    # cdncheck classification now has a home in HostRecord.
    recs = {"hosts": [{"ip": "1.2.3.4", "edge_kind": "waf", "edge_name": "DDoS-Guard"}]}
    g = build_graph(recs, ROOTS)
    assert ("edge_provider", "DDoS-Guard") in g.nodes
    assert ("ip:1.2.3.4", "edge_provider:DDoS-Guard", "waf") in _edges(g)


def test_host_without_edge_classification_draws_no_edge_provider():
    recs = {"hosts": [{"ip": "1.2.3.4", "org": "Acme"}]}
    g = build_graph(recs, ROOTS)
    assert not any(t == "edge_provider" for (t, _i) in g.nodes)


# ─────────────────────────── http ───────────────────────────

def test_http_builds_service_tech_and_behind_edge():
    recs = {"http": [{"host": "x.com", "url": "https://x.com",
                      "status": 200, "server": "ddos-guard",
                      "tech": ["nginx"]}]}
    g = build_graph(recs, ROOTS)
    e = _edges(g)
    assert ("root:x.com", "service:https://x.com", "serves") in e
    assert ("service:https://x.com", "tech:nginx", "uses") in e
    # server == ddos-guard -> behind DDoS-Guard even without a tech hint
    assert ("service:https://x.com", "edge_provider:DDoS-Guard", "behind") in e


def test_http_service_id_falls_back_to_host_when_no_url():
    recs = {"http": [{"host": "a.x.com", "url": "", "status": 200}]}
    g = build_graph(recs, ROOTS)
    assert ("service", "http://a.x.com") in g.nodes


# ─────────────────────────── ports ───────────────────────────

def test_port_record_builds_service_and_exposes():
    recs = {"ports": [{"ip": "1.2.3.4", "port": 22, "proto": "tcp",
                       "software": "OpenSSH", "source": "naabu"}]}
    g = build_graph(recs, ROOTS)
    assert ("service", "1.2.3.4:22") in g.nodes
    assert _attrs(g, "service", "1.2.3.4:22")["port"] == 22
    assert ("ip:1.2.3.4", "service:1.2.3.4:22", "exposes") in _edges(g)


# ─────────────────────────── certs (data-keyed edges) ───────────────────────────

def test_cert_with_root_name_and_ip_builds_cert_origin():
    recs = {"certs": [{"source": "censys", "names": ["x.com"], "ip": "9.9.9.9"}]}
    g = build_graph(recs, ROOTS)
    assert ("ip:9.9.9.9", "root:x.com", "cert_origin") in _edges(g)


def test_cert_with_subdomain_name_and_ip_builds_tls_san():
    recs = {"certs": [{"source": "origin-tls", "names": ["a.x.com"], "ip": "9.9.9.9"}]}
    g = build_graph(recs, ROOTS)
    e = _edges(g)
    assert ("root:x.com", "subdomain:a.x.com", "has_subdomain") in e
    assert ("ip:9.9.9.9", "subdomain:a.x.com", "tls_san") in e


def test_cert_without_ip_still_yields_subdomain_but_no_edge_to_ip():
    # crt.sh certs have names but no IP.
    recs = {"certs": [{"source": "crtsh", "names": ["a.x.com", "x.com"]}]}
    g = build_graph(recs, ROOTS)
    assert ("subdomain", "a.x.com") in g.nodes
    assert not any(rel in ("tls_san", "cert_origin") for (_s, _d, rel) in g.edges)


def test_cert_names_are_normalised():
    recs = {"certs": [{"source": "crtsh", "names": ["*.A.X.com"]}]}
    g = build_graph(recs, ROOTS)
    assert ("subdomain", "a.x.com") in g.nodes


# ─────────────────────────── netblock ───────────────────────────

def test_netblock_builds_org_and_in_netblock_edge():
    recs = {"netblock": [{"cidr": "1.2.3.0/24", "org": "Registrar LLC",
                          "asn": "AS7", "ip": "1.2.3.4", "source": "rdap"}]}
    g = build_graph(recs, ROOTS)
    assert ("org", "Registrar LLC") in g.nodes
    assert ("ip:1.2.3.4", "org:Registrar LLC", "in_netblock") in _edges(g)


# ─────────────────────────── origin / vhost gating ───────────────────────────

def test_origin_only_builds_edge_on_exposed_verdict():
    recs = {"origin": [
        {"ip": "9.9.9.9", "host_header": "x.com", "verdict": "exposed_origin"},
        {"ip": "8.8.8.8", "host_header": "x.com", "verdict": "other"},
    ]}
    g = build_graph(recs, ROOTS)
    e = _edges(g)
    assert ("ip:9.9.9.9", "root:x.com", "exposed_origin") in e
    assert _attrs(g, "ip", "9.9.9.9")["exposed_origin"] is True
    assert not any(s == "ip:8.8.8.8" for (s, _d, _r) in e)


def test_vhost_only_builds_edge_on_reachable_verdict():
    recs = {"vhost": [
        {"host": "hidden.x.com", "ip": "9.9.9.9", "trick": "host_header",
         "verdict": "reachable_vhost"},
        {"host": "no.x.com", "ip": "9.9.9.9", "verdict": "default_vhost"},
    ]}
    g = build_graph(recs, ROOTS)
    assert _attrs(g, "subdomain", "hidden.x.com")["dns_less"] is True
    assert ("ip:9.9.9.9", "subdomain:hidden.x.com", "vhost_reachable") in _edges(g)
    assert ("subdomain", "no.x.com") not in g.nodes


# ─────────────────────────── helpers / determinism ───────────────────────────

def test_root_of():
    assert root_of("a.x.com", ROOTS) == "x.com"
    assert root_of("x.com", ROOTS) == "x.com"
    assert root_of("foo.bar.example.org", ROOTS) == "example.org"


def test_build_is_deterministic():
    recs = {
        "subdomains": [{"name": "a.x.com", "root": "x.com", "sources": ["crtsh"]}],
        "dns": [{"name": "a.x.com", "a": ["1.2.3.4"], "discovery": "active"}],
        "hosts": [{"ip": "1.2.3.4", "org": "Acme", "asn": "AS1"}],
    }
    g1 = build_graph(recs, ROOTS).to_json()
    g2 = build_graph(recs, ROOTS).to_json()
    assert g1 == g2
