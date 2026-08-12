"""Tests for core.session.bodydiff — volatile-noise normalization for authz-diff.

The contract has two halves that must both hold:
  * recall — two responses for the SAME object that differ only in volatile
    fields (timestamps, CSRF tokens, request-ids, key order, pagination) match;
  * soundness — two DIFFERENT objects never match (no fuzzy/length path), so
    normalization can only remove known noise, never manufacture a break.
"""

from core.session.bodydiff import bodies_match, normalize, norm_sha256


# ─────────────────────────── recall: same object, volatile noise ───────────────────────────

def test_json_timestamp_difference_normalizes_equal():
    a = b'{"id":1,"owner":"alice","balance":500,"updated_at":"2026-08-12T07:00:00Z"}'
    b = b'{"id":1,"owner":"alice","balance":500,"updated_at":"2026-08-12T09:59:59Z"}'
    assert a != b
    match, kind = bodies_match(a, "application/json", b, "application/json")
    assert match and kind == "normalized"


def test_json_key_order_irrelevant():
    a = b'{"id":1,"owner":"alice","balance":500}'
    b = b'{"balance":500,"owner":"alice","id":1}'
    assert normalize(a) == normalize(b)


def test_json_csrf_and_requestid_dropped():
    a = b'{"id":7,"data":"x","csrf_token":"AAA","requestId":"r1"}'
    b = b'{"id":7,"data":"x","csrf_token":"BBB","requestId":"r2"}'
    match, kind = bodies_match(a, "application/json", b, "application/json")
    assert match and kind == "normalized"


def test_json_pagination_counters_dropped():
    a = b'{"items":[{"id":1}],"page":1,"cursor":"abc"}'
    b = b'{"items":[{"id":1}],"page":2,"cursor":"xyz"}'
    assert normalize(a) == normalize(b)


def test_exact_bytes_report_exact_kind():
    a = b'{"id":1}'
    match, kind = bodies_match(a, "application/json", a, "application/json")
    assert match and kind == "exact"


def test_html_csrf_hidden_input_stripped():
    a = (b'<form><input type="hidden" name="user_token" value="abc123">'
         b'<p>Secret memo for alice</p></form>')
    b = (b'<form><input type="hidden" name="user_token" value="zzz999">'
         b'<p>Secret memo for alice</p></form>')
    match, kind = bodies_match(a, "text/html", b, "text/html")
    assert match and kind == "normalized"


def test_html_iso_timestamp_masked():
    a = b'<div>Order 1 placed 2026-08-12T07:00:00Z by alice</div>'
    b = b'<div>Order 1 placed 2026-08-12T22:15:43Z by alice</div>'
    assert normalize(a, "text/html") == normalize(b, "text/html")


# ─────────────────────────── soundness: distinct objects stay distinct ───────────────────────────

def test_different_object_id_does_not_match():
    a = b'{"id":1,"owner":"alice","balance":500}'
    b = b'{"id":2,"owner":"bob","balance":500}'
    match, kind = bodies_match(a, "application/json", b, "application/json")
    assert not match and kind == "differ"


def test_different_resource_value_does_not_match():
    # only a non-volatile value differs → must NOT be called equal
    a = b'{"id":1,"owner":"alice","balance":500,"ts":"2026-08-12T07:00:00Z"}'
    b = b'{"id":1,"owner":"alice","balance":9999,"ts":"2026-08-12T07:00:00Z"}'
    assert not bodies_match(a, "application/json", b, "application/json")[0]


def test_similar_html_pages_for_different_users_do_not_match():
    # same template, different object content — a fuzzy/length match would false
    # positive here; normalization must keep them distinct.
    a = b'<html><nav>alice</nav><main>Order #1: Widget, $10</main></html>'
    b = b'<html><nav>alice</nav><main>Order #2: Gadget, $99</main></html>'
    assert not bodies_match(a, "text/html", b, "text/html")[0]


def test_norm_sha256_stable_and_distinct():
    a = b'{"id":1,"timestamp":"2026-08-12T07:00:00Z"}'
    b = b'{"id":1,"timestamp":"2026-08-12T08:00:00Z"}'
    c = b'{"id":2,"timestamp":"2026-08-12T07:00:00Z"}'
    assert norm_sha256(a) == norm_sha256(b)      # volatile-only diff → same
    assert norm_sha256(a) != norm_sha256(c)      # identity diff → different


def test_json_non_volatile_date_value_is_kept():
    # a meaningful date under a non-volatile key identifies the object — it must
    # NOT be masked (that would conflate two different objects).
    a = b'{"id":1,"due_date":"2026-08-12T07:00:00Z"}'
    b = b'{"id":1,"due_date":"2026-12-31T07:00:00Z"}'
    assert norm_sha256(a) != norm_sha256(b)
