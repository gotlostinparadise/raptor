"""Tests for core.injection oracles, payloads, markers (pure)."""

from core.injection import oracles, payloads
from core.injection.markers import MarkerFactory
from core.session.tests.fakes import resp


def test_markers_unique_and_ssti_product():
    f = MarkerFactory()
    m1, m2 = f.next(), f.next()
    assert m1.token != m2.token
    assert m1.product == m1.a * m1.b


def test_ssti_payload_expected_is_computed_product():
    f = MarkerFactory()
    m = f.next()
    pairs = payloads.ssti(m)
    payload, expected = pairs[0]
    assert str(m.product) in expected and m.token in expected
    assert f"{m.a}*{m.b}" in payload


def test_sql_error_oracle_matches_signatures():
    assert oracles.sql_error(resp(500, body=b"You have an error in your SQL syntax")) == "mysql"
    assert oracles.sql_error(resp(200, body=b"ORA-01756: quoted string")) == "oracle"
    assert oracles.sql_error(resp(200, body=b"totally fine")) is None


def test_reflected_and_ssti_confirmed():
    assert oracles.reflected(resp(200, body=b"prefix RAPXYZ suffix"), "RAPXYZ")
    assert oracles.ssti_confirmed(resp(200, body=b"rap1z36863rap1z"), "rap1z36863rap1z")
    assert not oracles.ssti_confirmed(resp(200, body=b"rap1z{{191*193}}rap1z"), "rap1z36863rap1z")


def test_metadata_leak_oracle():
    assert oracles.metadata_leak(resp(200, body=b'{"ami-id":"ami-1","instance-id":"i-9"}'))
    assert not oracles.metadata_leak(resp(200, body=b"regular page"))
    # regression: a REFLECTED metadata URL (contains "computeMetadata"/"meta-data")
    # must NOT be a leak — the signatures key on response content, not URL paths
    assert not oracles.metadata_leak(
        resp(200, body=b"http://metadata.google.internal/computeMetadata/v1/"))
    assert not oracles.metadata_leak(
        resp(200, body=b"you requested http://169.254.169.254/latest/meta-data/"))


def test_cmdi_expected_is_computed_not_bare_token():
    # the cmdi marker is a COMPUTED product (reflection-proof), not a bare token
    from core.injection.markers import MarkerFactory
    m = MarkerFactory().next()
    payload, expected = payloads.cmdi(m)[0]
    assert str(m.product) in expected           # expected carries the product
    assert f"$(({m.a}*{m.b}))" in payload        # payload uses shell arithmetic
    assert str(m.product) not in payload         # product is NOT in the raw payload


def test_boolean_diff_oracle():
    baseline = resp(200, body=b"RESULT " * 20)
    true_r = resp(200, body=b"RESULT " * 20)
    false_r = resp(200, body=b"no results")
    assert oracles.boolean_diff(baseline, true_r, false_r)
    # a page identical in all three cases is NOT a boolean-blind signal
    assert not oracles.boolean_diff(baseline, true_r, resp(200, body=b"RESULT " * 20))


def test_stable_boolean_confirms_and_resists_jitter():
    base = resp(200, body=b"RESULT " * 40)
    true1 = resp(200, body=b"RESULT " * 40)
    true2 = resp(200, body=b"RESULT " * 40)
    false_r = resp(200, body=b"empty")
    assert oracles.stable_boolean(base, true1, true2, false_r)
    # jitter: the TRUE branch is unstable (true1 != true2 by >5%) → abstain,
    # even though true1~baseline and false diverges (would FP under boolean_diff)
    jitter_true2 = resp(200, body=b"RESULT " * 80)   # 2x length — unstable
    assert not oracles.stable_boolean(base, true1, jitter_true2, false_r)


def test_blind_payloads_embed_host():
    host = "tok.oast.test"
    assert host in payloads.ssrf(host)[0]
    assert host in payloads.xxe(host)
    assert any(host in c for c in payloads.cmdi_blind(host))
    assert any(host in p for p in payloads.sqli_oob(host))
