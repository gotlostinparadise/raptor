"""Hardening tests for core.waf — pins branches uncovered by test_waf.py.

Covers, without duplicating the existing 7 tests:
  * detection no-WAF negatives (rich benign response + empty inputs),
  * the ``detect_from_response`` wrapper (untouched elsewhere),
  * single-vendor fingerprint disambiguation (cookie- and body-driven),
  * per-family evasion round-trip / semantic-preservation contracts, and
  * the mutations() de-dup *skip* branch (no-op transforms dropped).

All assertions are on the public API (``detect.detect``,
``detect.detect_from_response``, ``evasion.mutations``). No network, no sleeps.
"""

from urllib.parse import unquote

from core.waf import detect, evasion
from core.waf.detect import detect_from_response


class _Resp:
    """Minimal core.http.Response-like stub for detect_from_response()."""

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body


# --------------------------------------------------------------------------- #
# Detection: no-WAF negatives                                                  #
# --------------------------------------------------------------------------- #

def test_detect_clean_response_no_false_positive():
    # A fully benign 200 (ordinary server banner, ordinary session cookie,
    # ordinary HTML) must not attribute any vendor, and neither must empties.
    clean = detect.detect(
        200,
        {"Server": "Apache/2.4.52", "Content-Type": "text/html",
         "Set-Cookie": "session=abc123; Path=/; HttpOnly"},
        b"<html><body>Welcome to the site</body></html>",
    )
    assert clean == []
    assert detect.detect(0, {}, b"") == []


# --------------------------------------------------------------------------- #
# Detection: detect_from_response wrapper + disambiguation                     #
# --------------------------------------------------------------------------- #

def test_detect_from_response_wrapper_negative_and_imperva():
    # Wrapper reads .status/.headers/.body off the object. Clean -> []; an
    # Incapsula session cookie -> imperva_incapsula and nothing else.
    assert detect_from_response(_Resp(200, {"Server": "nginx"}, b"ok")) == []
    hits = detect_from_response(
        _Resp(403, {"Set-Cookie": "incap_ses_42=Zm9v; path=/"}, b"blocked"))
    assert hits == ["imperva_incapsula"]


def test_detect_akamai_by_cookie_disambiguated():
    # ak_bmsc cookie is Akamai's alone; a benign server/body must keep the
    # attribution to akamai and off every other vendor.
    hits = detect.detect(
        200, {"Server": "nginx", "Set-Cookie": "ak_bmsc=ABC123; path=/"}, b"OK")
    assert hits == ["akamai"]
    for other in ("cloudflare", "imperva_incapsula", "f5_big_ip", "aws_waf"):
        assert other not in hits


def test_detect_f5_by_body_disambiguated():
    # F5 BIG-IP's block page phrasing is distinctive; body-only match must
    # resolve to f5_big_ip and not bleed into other vendors.
    body = (b"The requested URL was rejected. Please consult with your "
            b"administrator. Your support ID is: 9876543210")
    hits = detect.detect(403, {"Server": "nginx"}, body)
    assert hits == ["f5_big_ip"]
    for other in ("cloudflare", "akamai", "modsecurity", "sucuri"):
        assert other not in hits


# --------------------------------------------------------------------------- #
# Evasion: per-family round-trip / semantic-preservation contracts            #
# --------------------------------------------------------------------------- #

_PAYLOAD = "' UNION SELECT 1"   # has both spaces and case-toggleable keywords


def _matches(variants, pred):
    return [v for v in variants if v != _PAYLOAD and pred(v)]


def test_evasion_url_encode_roundtrips():
    # Exactly the single-URL-encoded variant decodes back in one unquote().
    hits = _matches(_PAYLOAD_VARIANTS(), lambda v: unquote(v) == _PAYLOAD)
    assert hits, "no single-URL-encoded variant found"
    assert all("%20" in v for v in hits)          # surface form actually changed


def test_evasion_double_url_encode_roundtrips():
    # Double-encoded: one unquote is NOT enough, two recover the original.
    hits = _matches(
        _PAYLOAD_VARIANTS(),
        lambda v: unquote(v) != _PAYLOAD and unquote(unquote(v)) == _PAYLOAD)
    assert hits, "no double-URL-encoded variant found"
    assert all("%25" in v for v in hits)          # a literal '%' got encoded


def test_evasion_mixed_case_preserves_semantics():
    # Case toggling changes the surface but keeps the payload case-insensitively
    # identical (no chars added/removed/reordered).
    hits = _matches(_PAYLOAD_VARIANTS(),
                    lambda v: v.lower() == _PAYLOAD.lower())
    assert hits, "no case-toggled variant found"


def test_evasion_comment_spaces_normalizes_back():
    # Spaces -> /**/; replacing the comments with spaces restores the original.
    hits = _matches(_PAYLOAD_VARIANTS(),
                    lambda v: "/**/" in v and v.replace("/**/", " ") == _PAYLOAD)
    assert hits, "no comment-for-space variant found"


def test_evasion_whitespace_tab_normalizes_back():
    # Spaces -> tabs; replacing tabs with spaces restores the original.
    hits = _matches(_PAYLOAD_VARIANTS(),
                    lambda v: "\t" in v and v.replace("\t", " ") == _PAYLOAD)
    assert hits, "no whitespace-alt (tab) variant found"


def test_evasion_keyword_split_comment_normalizes_back():
    # Keyword-internal /**/ (UNION -> UN/**/ION); stripping the comments
    # (not replacing with space) restores the original keyword stream.
    hits = _matches(_PAYLOAD_VARIANTS(),
                    lambda v: "/**/" in v and v.replace("/**/", "") == _PAYLOAD)
    assert hits, "no keyword-split-comment variant found"


def test_evasion_null_byte_appends_and_prefix_preserved():
    # Null-byte trick appends %00; the original payload survives as an exact
    # prefix (recoverable by stripping the trailing marker).
    hits = _matches(_PAYLOAD_VARIANTS(),
                    lambda v: v.endswith("%00") and v[:-3] == _PAYLOAD)
    assert hits == [_PAYLOAD + "%00"]


# --------------------------------------------------------------------------- #
# Evasion: de-dup / no-op-skip branch + non-empty                             #
# --------------------------------------------------------------------------- #

def test_mutations_dedup_skips_noop_transforms():
    # "abc" has no spaces and no keywords, so url/double/case/comment/tab/split
    # all reproduce the input and must be skipped as duplicates; only the
    # null-byte transform yields something new. Pins original-first + non-empty
    # + the "v not in seen" skip branch.
    variants = evasion.mutations("abc")
    assert variants == ["abc", "abc%00"]
    assert variants[0] == "abc"
    assert len(variants) == len(set(variants))


def _PAYLOAD_VARIANTS():
    return evasion.mutations(_PAYLOAD)
