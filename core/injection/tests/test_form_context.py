"""The form-context siblings must survive the orchestrator's dict round-trip.

Regression: the webpentest orchestrator re-serialised injection points to dicts
(method/path/param/location) and dropped `others`, so submit-gated vuln code
(DVWA's isset($_GET['Submit'])) never ran — sqli/cmdi silently failed while
name/page-based classes worked.
"""
from core.injection.config import from_dict


def test_point_others_survive_dict_roundtrip():
    cfg = from_dict({
        "base_url": "http://lab",
        "points": [{"method": "POST", "path": "/vulnerabilities/exec",
                    "param": "ip", "location": "body",
                    "others": {"Submit": "Submit"}}],
    })
    assert cfg.points[0].others == {"Submit": "Submit"}


def test_send_includes_siblings():
    from core.injection.config import InjectionPoint
    from core.injection.runner import _send
    sent = {}

    class _E:
        def request(self, ident, method, url, *, body=None, headers=None,
                    follow_redirects=False, raise_on_status=True):
            sent["url"] = url
            sent["body"] = body
            return type("R", (), {"status": 200, "body": b""})

    # body point: siblings go in the form body alongside the payload
    p = InjectionPoint("POST", "/exec", "ip", "body", others={"Submit": "Submit"})
    _send(_E(), "s", "http://lab", p, "PAYLOAD")
    assert b"ip=PAYLOAD" in sent["body"] and b"Submit=Submit" in sent["body"]
    # query point: siblings go in the query string
    p2 = InjectionPoint("GET", "/sqli", "id", "query", others={"Submit": "Submit"})
    _send(_E(), "s", "http://lab", p2, "1'")
    assert "Submit=Submit" in sent["url"] and "id=1" in sent["url"]
