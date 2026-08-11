"""Tests for core.session.engine — per-identity state, CSRF, refresh."""

from core.session.engine import SessionEngine
from core.session.identity import Identity
from core.session.tests.fakes import FakeClient, resp


def test_set_cookie_captured_then_sent_next_request():
    seen_cookies = []

    def handler(method, url, headers, body):
        seen_cookies.append(headers.get("Cookie"))
        if url.endswith("/login"):
            return resp(200, **{"Set-Cookie": "session=SECRET; Path=/"})
        return resp(200)

    eng = SessionEngine(FakeClient(handler))
    eng.add_identity(Identity(name="user_a"))
    eng.request("user_a", "GET", "https://x.com/login")   # sets cookie
    eng.request("user_a", "GET", "https://x.com/dash")    # should send it
    assert seen_cookies == [None, "session=SECRET"]


def test_identities_are_isolated():
    def handler(method, url, headers, body):
        # each login sets a distinct session for whoever asks
        who = "A" if "a" in url else "B"
        return resp(200, **{"Set-Cookie": f"session=SESS_{who}; Path=/"})

    eng = SessionEngine(FakeClient(handler))
    eng.add_identity(Identity(name="user_a"))
    eng.add_identity(Identity(name="user_b"))
    eng.request("user_a", "GET", "https://x.com/a/login")
    eng.request("user_b", "GET", "https://x.com/b/login")
    assert eng.identity("user_a").jar.header_for("https://x.com/") == "session=SESS_A"
    assert eng.identity("user_b").jar.header_for("https://x.com/") == "session=SESS_B"


def test_csrf_double_submit_echoes_cookie_token_on_mutation():
    sent = {}

    def handler(method, url, headers, body):
        sent[method] = headers
        if method == "GET":
            return resp(200, **{"Set-Cookie": "XSRF-TOKEN=tok123; Path=/"})
        return resp(200)

    eng = SessionEngine(FakeClient(handler),
                        csrf_cookie="XSRF-TOKEN", csrf_header="X-XSRF-TOKEN")
    eng.add_identity(Identity(name="user_a"))
    eng.request("user_a", "GET", "https://x.com/form")     # captures token
    eng.request("user_a", "POST", "https://x.com/action")  # echoes it
    assert sent["POST"].get("X-XSRF-TOKEN") == "tok123"
    assert "X-XSRF-TOKEN" not in sent["GET"]               # not on safe methods


def test_refresh_on_401_retries_once():
    state = {"calls": 0, "token": "expired"}

    def handler(method, url, headers, body):
        state["calls"] += 1
        if headers.get("Authorization") == "Bearer good":
            return resp(200)
        return resp(401)

    def refresh(identity):
        state["token"] = "good"
        identity.set_bearer("good")

    eng = SessionEngine(FakeClient(handler))
    ident = Identity(name="user_a")
    ident.set_bearer("expired")
    eng.add_identity(ident, refresh=refresh)
    r = eng.request("user_a", "GET", "https://x.com/me")
    assert r.status == 200 and state["calls"] == 2


def test_anonymous_identity_exists_by_default():
    eng = SessionEngine(FakeClient(lambda *a: resp(200)))
    assert "anonymous" in eng.names()
    assert eng.identity("anonymous").is_anonymous()


def test_client_that_raises_on_4xx_is_normalised_to_a_response():
    # Real clients (UrllibClient/EgressClient) raise HttpError on non-2xx; the
    # engine must surface the status as data so the authz oracle can read it.
    from core.http import HttpError

    class _RaisingClient:
        def request(self, method, url, **kw):
            raise HttpError("HTTP 403", status=403)

    eng = SessionEngine(_RaisingClient())
    eng.add_identity(Identity(name="user_b"))
    r = eng.request("user_b", "GET", "https://x.com/api/orders/1")
    assert r.status == 403 and r.body == b""
