"""Tests for core.session.replay — the A/B/anonymous authorization oracle."""

from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.replay import RequestTemplate, authorization_diff, replay
from core.session.tests.fakes import FakeClient, resp

_OWNER_BODY = b'{"order":1,"owner":"user_a","total":999}'


def _broken_app():
    """A BOLA-vulnerable app: any authenticated identity gets order 1's body;
    anonymous is rejected. Access is NOT scoped to the owner."""
    def handler(method, url, headers, body):
        authed = bool(headers.get("Authorization") or headers.get("Cookie"))
        if not authed:
            return resp(401)
        return resp(200, body=_OWNER_BODY)   # <-- same object for everyone
    return handler


def _secure_app():
    """A correct app: only user_a's token reads order 1; others 403, anon 401."""
    def handler(method, url, headers, body):
        auth = headers.get("Authorization", "")
        if not auth and not headers.get("Cookie"):
            return resp(401)
        if auth == "Bearer TOKEN_A":
            return resp(200, body=_OWNER_BODY)
        return resp(403, body=b'{"error":"forbidden"}')
    return handler


def _engine(handler):
    eng = SessionEngine(FakeClient(handler))
    a = Identity(name="user_a"); a.set_bearer("TOKEN_A"); a.authenticated = True
    b = Identity(name="user_b"); b.set_bearer("TOKEN_B"); b.authenticated = True
    eng.add_identity(a)
    eng.add_identity(b)
    return eng


def test_replay_reports_allowed_and_body_hash():
    eng = _engine(_broken_app())
    obs = replay(eng, RequestTemplate("GET", "https://x.com/api/orders/1"), "user_a")
    assert obs.allowed and obs.status == 200 and obs.resp_len == len(_OWNER_BODY)


def test_bola_detected_when_other_identity_reads_owner_object():
    eng = _engine(_broken_app())
    verdict = authorization_diff(
        eng, RequestTemplate("GET", "https://x.com/api/orders/1", label="GET /api/orders/{id}"),
        owner="user_a",
    )
    assert verdict.violation is True
    assert "user_b" in verdict.offending
    assert "anonymous" not in verdict.offending          # anon was denied (401)


def test_no_violation_on_secure_app():
    eng = _engine(_secure_app())
    verdict = authorization_diff(
        eng, RequestTemplate("GET", "https://x.com/api/orders/1"), owner="user_a")
    assert verdict.violation is False
    assert verdict.offending == []


def test_no_verdict_without_valid_owner_baseline():
    # owner itself denied -> template mis-specified -> no violation claimed
    eng = _engine(_secure_app())
    verdict = authorization_diff(
        eng, RequestTemplate("GET", "https://x.com/api/orders/1"), owner="user_b")
    assert verdict.violation is False
    # only the owner baseline observation is recorded when baseline is denied
    assert [o.identity for o in verdict.observations] == ["user_b"]
