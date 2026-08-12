"""Tests for the JWT primitives, forgery generators, and the acceptance oracle."""

from core.jwt.attacks import (
    DEFAULT_SECRETS, alg_none_variants, corrupt_signature, generate_forgeries,
    recover_hmac_secret, tamper_claims, weak_secret_forgery,
)
from core.jwt.oracle import forgery_confirmed, is_accepted
from core.jwt.tokens import decode, encode, sign_hmac, signing_input, verify_hmac


def _hs256(payload, secret, header=None):
    header = header or {"alg": "HS256", "typ": "JWT"}
    si = signing_input(header, payload)
    return encode(header, payload, sign_hmac(si, secret, "HS256"))


# ─────────────────────────── tokens ───────────────────────────

def test_encode_decode_roundtrip():
    tok = _hs256({"sub": "alice", "role": "user"}, "secret")
    header, payload, sig, si = decode(tok)
    assert header["alg"] == "HS256" and payload["sub"] == "alice"
    assert verify_hmac(tok, "secret")
    assert not verify_hmac(tok, "wrong")


def test_decode_rejects_malformed():
    for bad in ("", "a.b", "a.b.c.d", "notbase64!.x.y"):
        try:
            decode(bad)
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass


def test_verify_hmac_false_for_non_hmac_alg():
    tok = encode({"alg": "none"}, {"sub": "x"}, b"")
    assert verify_hmac(tok, "secret") is False


# ─────────────────────────── attacks ───────────────────────────

def test_alg_none_variants_are_unsigned_and_tampered():
    forgeries = alg_none_variants({"alg": "HS256"}, {"sub": "alice", "exp": 100},
                                  {"role": "admin"})
    algs = {f.detail["alg"] for f in forgeries}
    assert algs == {"none", "None", "NONE", "nOnE"}
    for f in forgeries:
        header, payload, sig, _ = decode(f.token)
        assert sig == b""                       # unsigned
        assert payload["role"] == "admin"       # claim escalated
        assert payload["exp"] == 4102444800     # exp bumped to the future


def test_recover_weak_secret_from_wordlist():
    tok = _hs256({"sub": "bob"}, "changeme")
    assert recover_hmac_secret(tok, DEFAULT_SECRETS) == "changeme"
    assert recover_hmac_secret(_hs256({"sub": "bob"}, "Zx9-not-in-list"), DEFAULT_SECRETS) is None


def test_weak_secret_forgery_is_valid_under_recovered_secret():
    header = {"alg": "HS256", "typ": "JWT"}
    f = weak_secret_forgery(header, {"sub": "bob", "role": "user"}, "secret",
                            {"role": "admin"})
    assert verify_hmac(f.token, "secret")       # correctly signed
    _h, payload, _s, _si = decode(f.token)
    assert payload["role"] == "admin"


def test_generate_forgeries_hs_includes_weak_secret_when_crackable():
    tok = _hs256({"sub": "carol", "exp": 1}, "password")
    forgeries = generate_forgeries(tok, changes={"role": "admin"})
    classes = {f.vuln_class for f in forgeries}
    assert "jwt_alg_none" in classes and "jwt_weak_secret" in classes


def test_generate_forgeries_omits_weak_secret_when_uncrackable():
    tok = _hs256({"sub": "carol"}, "a-very-strong-secret-not-in-any-list-42")
    classes = {f.vuln_class for f in generate_forgeries(tok)}
    assert classes == {"jwt_alg_none"}


def test_corrupt_signature_breaks_verification():
    tok = _hs256({"sub": "alice"}, "secret")
    bad = corrupt_signature(tok)
    assert bad != tok
    assert not verify_hmac(bad, "secret")       # control token is genuinely invalid


def test_tamper_claims_only_bumps_exp_when_present():
    assert "exp" not in tamper_claims({"sub": "x"})
    assert tamper_claims({"sub": "x", "exp": 1})["exp"] == 4102444800


# ─────────────────────────── oracle ───────────────────────────

def test_oracle_confirms_only_on_the_right_triple():
    # baseline accepted, control rejected, forgery accepted → confirmed
    assert forgery_confirmed(200, 401, 200) is True
    # endpoint accepts the corrupted control (no validation) → NOT a forgery
    assert forgery_confirmed(200, 200, 200) is False
    # forgery rejected → not confirmed
    assert forgery_confirmed(200, 401, 403) is False
    # no valid baseline → cannot conclude
    assert forgery_confirmed(401, 401, 200) is False


def test_is_accepted_only_2xx():
    assert is_accepted(200) and is_accepted(204)
    assert not is_accepted(401) and not is_accepted(302) and not is_accepted(None)
