"""Tests for core.injection.runner — vulnerable fake apps + oracle confirmation."""

import re
from urllib.parse import unquote

import pytest

from core.injection.config import from_dict
from core.injection.runner import run_injection
from core.labeled_attempts.view import Oracle, collect_outcomes
from core.oast.backend import InMemoryBackend
from core.oast.client import OastClient
from core.oast.interaction import Interaction, PROTO_DNS
from core.session.tests.fakes import FakeClient, resp

_AUTH = "authorized test fixture"


def _cfg(classes):
    return from_dict({
        "base_url": "https://app.test", "authorization": _AUTH,
        "points": [{"method": "GET", "path": "/item", "param": "q", "location": "query"}],
        "classes": classes,
    })


def _blob(url, body):
    return unquote(url) + (unquote(body.decode()) if body else "")


def _ssti_app():
    def h(method, url, headers, body):
        blob = _blob(url, body)
        ev = lambda m: str(int(m.group(1)) * int(m.group(2)))
        r = re.sub(r"\{\{(\d+)\*(\d+)\}\}", ev, blob)
        r = re.sub(r"\$\{(\d+)\*(\d+)\}", ev, r)
        return resp(200, body=r.encode())
    return lambda hosts: FakeClient(h)


def _sqli_error_app():
    def h(method, url, headers, body):
        if "'" in _blob(url, body):
            return resp(500, body=b"You have an error in your SQL syntax near ''")
        return resp(200, body=b"ok")
    return lambda hosts: FakeClient(h)


def _sqli_boolean_app():
    def h(method, url, headers, body):
        blob = _blob(url, body)
        if "'1'='2" in blob:
            return resp(200, body=b"no results")
        return resp(200, body=b"RESULT " * 40)
    return lambda hosts: FakeClient(h)


def _metadata_app():
    def h(method, url, headers, body):
        if "169.254.169.254" in _blob(url, body):
            return resp(200, body=b'{"ami-id":"ami-123","instance-id":"i-1"}')
        return resp(200, body=b"ok")
    return lambda hosts: FakeClient(h)


def test_dry_run_sends_nothing(tmp_path):
    run = run_injection(_cfg(["ssti"]), out_dir=tmp_path, active=False)
    assert run.requests_sent == 0 and run.findings and run.findings[0].get("planned")


def test_active_requires_authorization(tmp_path):
    cfg = _cfg(["ssti"]); cfg.authorization = ""
    with pytest.raises(ValueError):
        run_injection(cfg, out_dir=tmp_path, active=True, client_factory=_ssti_app())


def test_ssti_confirmed(tmp_path):
    run = run_injection(_cfg(["ssti"]), out_dir=tmp_path, active=True,
                        client_factory=_ssti_app(), producing_model="t")
    assert any(f["class"] == "ssti" for f in run.findings)
    # proof surfaced
    outs = collect_outcomes(tmp_path, project_root=tmp_path)
    assert any(o.oracle == Oracle.WEB for o in outs)


def test_sqli_error_confirmed(tmp_path):
    run = run_injection(_cfg(["sqli"]), out_dir=tmp_path, active=True,
                        client_factory=_sqli_error_app())
    assert any(f["class"] == "sqli" for f in run.findings)


def test_sqli_boolean_confirmed(tmp_path):
    run = run_injection(_cfg(["sqli"]), out_dir=tmp_path, active=True,
                        client_factory=_sqli_boolean_app())
    assert any(f["class"] == "sqli" for f in run.findings)


def test_ssrf_metadata_confirmed(tmp_path):
    run = run_injection(_cfg(["ssrf_metadata"]), out_dir=tmp_path, active=True,
                        client_factory=_metadata_app())
    assert any(f["class"] == "ssrf" for f in run.findings)


def _xss_reflecting_app(escape: bool):
    """Reflects q into HTML — escaped (safe) or raw (vulnerable)."""
    import html
    def h(method, url, headers, body):
        q = unquote(url.split("q=", 1)[1]) if "q=" in url else ""
        rendered = html.escape(q) if escape else q
        return resp(200, body=f"<div>results for {rendered}</div>".encode())
    return lambda hosts: FakeClient(h)


def test_xss_confirmed_on_unescaped_reflection(tmp_path):
    run = run_injection(_cfg(["xss"]), out_dir=tmp_path, active=True,
                        client_factory=_xss_reflecting_app(escape=False))
    assert any(f["class"] == "xss" for f in run.findings)


def test_xss_not_flagged_when_escaped(tmp_path):
    # regression: a properly HTML-encoding app must NOT be flagged (the raw tag
    # never appears — only &lt;img...&gt;). Escaped reflection is not XSS.
    run = run_injection(_cfg(["xss"]), out_dir=tmp_path, active=True,
                        client_factory=_xss_reflecting_app(escape=True))
    assert all(f["class"] != "xss" for f in run.findings)


def test_no_false_positive_on_safe_app(tmp_path):
    safe = lambda hosts: FakeClient(lambda *a: resp(200, body=b"static page"))
    run = run_injection(_cfg(["ssti", "sqli", "path_traversal"]), out_dir=tmp_path,
                        active=True, client_factory=safe)
    assert run.findings == []


def test_reflection_only_app_is_not_injection(tmp_path):
    # regression: an app that REFLECTS input verbatim (no evaluation/execution)
    # must NOT be flagged for cmdi or ssrf — reflection is not injection. Only a
    # computed/executed marker counts.
    def echo(method, url, headers, body):
        blob = unquote(url) + (unquote(body.decode()) if body else "")
        return resp(200, body=blob.encode())   # pure reflector, no eval

    run = run_injection(_cfg(["cmdi", "ssrf_metadata", "path_traversal"]),
                        out_dir=tmp_path, active=True,
                        client_factory=lambda h: FakeClient(echo))
    assert run.findings == []


def test_blind_ssrf_via_oast(tmp_path):
    backend = InMemoryBackend("oast.test")
    oast = OastClient(backend)

    # a fake vulnerable server: on seeing an oast host in the request, "call back"
    def h(method, url, headers, body):
        blob = _blob(url, body)
        m = re.search(r"([a-z0-9]+\.oast\.test)", blob)
        if m:
            backend.record(Interaction(token="", protocol=PROTO_DNS, host=m.group(1)))
        return resp(200, body=b"queued")

    run = run_injection(_cfg(["ssrf"]), out_dir=tmp_path, active=True,
                        client_factory=lambda hosts: FakeClient(h), oast=oast)
    assert any(f.get("proof") == "oast_callback" and f["class"] == "ssrf"
               for f in run.findings)


def test_blind_rfi_via_oast(tmp_path):
    # RFI: a file-include param that fetches a remote URL calls home → oast_callback,
    # classified rfi (CWE-98). Same proof plumbing as SSRF, distinct class.
    backend = InMemoryBackend("oast.test")
    oast = OastClient(backend)

    def h(method, url, headers, body):
        m = re.search(r"([a-z0-9]+\.oast\.test)", _blob(url, body))
        if m:
            backend.record(Interaction(token="", protocol=PROTO_DNS, host=m.group(1)))
        return resp(200, body=b"included")

    run = run_injection(_cfg(["rfi"]), out_dir=tmp_path, active=True,
                        client_factory=lambda hosts: FakeClient(h), oast=oast)
    assert any(f.get("proof") == "oast_callback" and f["class"] == "rfi"
               for f in run.findings)


def _cookie_echo_app(seen):
    """Records the Cookie header on every request; never confirms a finding."""
    def h(method, url, headers, body):
        seen.append(headers.get("Cookie"))
        return resp(200, body=b"static page")
    return lambda hosts: FakeClient(h)


def test_config_cookies_reach_injection_requests(tmp_path):
    # R2: a cookie set on InjectionConfig authenticates a standalone /inject run.
    seen = []
    cfg = _cfg(["sqli"])
    cfg.cookies = {"PHPSESSID": "abc123"}
    run_injection(cfg, out_dir=tmp_path, active=True, client_factory=_cookie_echo_app(seen))
    assert seen and all(c and "PHPSESSID=abc123" in c for c in seen)


def test_live_session_reused_and_injects_as_its_identity(tmp_path):
    # R2: a live SessionEngine (cookie jar + bearer) threaded via config.session
    # is reused; injection sends as its authenticated identity.
    from core.session.engine import SessionEngine
    from core.session.identity import Identity

    seen = []
    engine = SessionEngine(FakeClient(lambda m, u, h, b: (seen.append(h.get("Cookie")) or resp(200, body=b"ok"))))
    ident = Identity(name="session", authenticated=True)
    ident.jar.set("SESSION", "live-cookie", "app.test")
    engine.add_identity(ident)

    cfg = _cfg(["sqli"])
    cfg.session = engine
    run_injection(cfg, out_dir=tmp_path, active=True)
    assert seen and all(c and "SESSION=live-cookie" in c for c in seen)
