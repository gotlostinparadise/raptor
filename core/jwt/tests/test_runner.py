"""End-to-end runner tests against fake JWT-validating apps.

Each app applies a validation policy to the bearer token; the runner must confirm
a forgery ONLY when the app both (a) rejects a corrupted-signature control and
(b) accepts our forgery — and must confirm exactly the forgery the app actually
honours (alg:none vs weak-secret), never the other.
"""

import json
from pathlib import Path

from core.jwt.config import from_dict
from core.jwt.runner import run_jwt
from core.jwt.tokens import decode, encode, sign_hmac, signing_input, verify_hmac

_REAL = "R3al-Str0ng-Secret-not-in-any-wordlist"
_WEAK = "secret"    # present in DEFAULT_SECRETS


def _hs256(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    return encode(header, payload, sign_hmac(signing_input(header, payload), secret, "HS256"))


class _Resp:
    def __init__(self, status):
        self.status = status
        self.headers = {}
        self.body = b""


class _App:
    """A fake HTTP client applying ``policy(token)->status`` to the bearer token."""

    def __init__(self, policy):
        self.policy = policy
        self.calls = []

    def request(self, method, url, headers=None, **kw):
        raw = (headers or {}).get("Authorization", "")
        tok = raw[7:] if raw.startswith("Bearer ") else raw
        self.calls.append(tok)
        return _Resp(self.policy(tok))


def _alg_of(tok):
    try:
        return str(decode(tok)[0].get("alg", "")).lower()
    except ValueError:
        return ""


def _secure(tok):
    return 200 if verify_hmac(tok, _REAL) else 401


def _alg_none_vuln(tok):
    if _alg_of(tok) == "none":
        return 200                       # honours the "unsecured" JWS — the bug
    return 200 if verify_hmac(tok, _REAL) else 401


def _weak_secret_app(tok):
    return 200 if verify_hmac(tok, _WEAK) else 401


def _no_auth(tok):
    return 200                           # accepts anything, including garbage


def _cfg(token, **kw):
    base = {"base_url": "https://api.test", "authorization": "authorized lab",
            "protected_path": "/me", "token": token, "tamper": {"role": "admin"}}
    base.update(kw)
    return from_dict(base)


def _findings(tmp_path):
    return json.loads((Path(tmp_path) / "jwt-findings.json").read_text())


def test_secure_app_no_forgery_confirmed(tmp_path):
    app = _App(_secure)
    run = run_jwt(_cfg(_hs256({"sub": "alice"}, _REAL)), out_dir=tmp_path,
                  active=True, client_factory=lambda h: app)
    assert [f for f in run.findings if f.get("proof")] == []


def test_alg_none_confirmed(tmp_path):
    app = _App(_alg_none_vuln)
    run = run_jwt(_cfg(_hs256({"sub": "alice"}, _REAL)), out_dir=tmp_path,
                  active=True, client_factory=lambda h: app)
    confirmed = [f for f in run.findings if f.get("proof")]
    assert len(confirmed) == 1
    assert confirmed[0]["class"] == "jwt_alg_none"
    assert confirmed[0]["proof"] == "token_forged"


def test_weak_secret_confirmed_but_not_alg_none(tmp_path):
    # app validates HMAC under a weak secret; it rejects alg:none, so ONLY the
    # weak-secret forgery must confirm.
    app = _App(_weak_secret_app)
    run = run_jwt(_cfg(_hs256({"sub": "alice"}, _WEAK)), out_dir=tmp_path,
                  active=True, client_factory=lambda h: app)
    classes = {f["class"] for f in run.findings if f.get("proof")}
    assert classes == {"jwt_weak_secret"}


def test_no_auth_endpoint_is_not_a_forgery(tmp_path):
    # accepts the corrupted control → not signature validation → suppressed
    app = _App(_no_auth)
    run = run_jwt(_cfg(_hs256({"sub": "alice"}, _REAL)), out_dir=tmp_path,
                  active=True, client_factory=lambda h: app)
    assert [f for f in run.findings if f.get("proof")] == []
    assert any("does not validate" in w or "broken" in w for w in run.warnings)


def test_dry_run_sends_nothing(tmp_path):
    app = _App(_secure)
    run = run_jwt(_cfg(_hs256({"sub": "alice"}, _REAL)), out_dir=tmp_path,
                  active=False, client_factory=lambda h: app)
    assert run.requests_sent == 0
    assert app.calls == []
    assert run.forgeries_tried >= 1              # planned, not sent


def test_confirmed_forgery_is_a_verified_outcome(tmp_path):
    app = _App(_alg_none_vuln)
    run_jwt(_cfg(_hs256({"sub": "alice"}, _REAL)), out_dir=tmp_path,
            active=True, client_factory=lambda h: app)
    vulns_file = Path(tmp_path) / "normalized" / "vulns.jsonl"
    assert vulns_file.exists()
    rows = [json.loads(l) for l in vulns_file.read_text().splitlines() if l.strip()]
    assert any(r.get("proof_kind") == "token_forged"
               and r.get("vuln_class") == "jwt_alg_none" for r in rows)
