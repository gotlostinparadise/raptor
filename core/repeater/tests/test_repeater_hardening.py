"""Hardening tests for core.repeater — pins uncovered branches around PoC
shell-injection safety, round-trip fidelity across the three PoC formats,
generated-Python syntactic validity, and RequestSpec tamper semantics.

Companion to test_repeater.py; no overlap. Fully offline/deterministic: no
network, no sleeps, and NO generated PoC is ever executed (Python PoCs are only
compiled, never run; curl is only tokenized with shlex, never shelled out).
"""

import shlex

from core.repeater import poc
from core.repeater.request import RequestSpec


# --------------------------------------------------------------------------
# Shell-injection safety of the curl PoC
# --------------------------------------------------------------------------

def test_curl_shell_injection_payload_is_inert_literal():
    """INJECTION SAFETY: attacker-influenced header + body values containing
    single quotes, double quotes, spaces, a newline, `$(id)` command
    substitution, and backtick substitution must be carried faithfully yet
    stay quoted, so a POSIX shell treats them as literal data — never as
    command words. Proven by tokenizing the emitted curl with shlex (models a
    shell's quote-removal) and asserting the exact argv the shell would see.
    """
    payload = "closeq'brk $(id) `whoami` \"dq\" ; rm -rf / && echo p0wn\nnl"
    spec = RequestSpec(method="POST", url="https://api.test/x",
                       headers={"X-Evil": payload}, body="body-" + payload)
    curl = poc.to_curl(spec)

    # The dangerous text is present verbatim (faithful, not silently stripped).
    assert "$(id)" in curl and "`whoami`" in curl

    # A POSIX shell tokenizer reconstructs EXACTLY these words. If any value had
    # broken out of quoting, argv would differ (or shlex would raise on an
    # unbalanced quote). The payload stays wholly inside single argument words.
    argv = shlex.split(curl)
    assert argv == [
        "curl", "-i", "-s", "-X", "POST", "https://api.test/x",
        "-H", "X-Evil: " + payload,
        "--data-raw", "body-" + payload,
    ]

    # Negative check: the metachars/command fragments never surface as their own
    # shell words (they would, split on their surrounding spaces, if unquoted).
    tokens = set(argv)
    assert not (tokens & {"$(id)", "`whoami`", "rm", "-rf", "/", "echo", "p0wn"})

    # And the escaping is single-quote based (shlex.quote), the mechanism that
    # disables $()/backtick/variable expansion.
    assert shlex.quote("X-Evil: " + payload) in curl


def test_curl_lone_single_quote_value_stays_quoted():
    """A header value that is a bare single quote stresses shlex.quote's
    '"'"' escape sequence — the trickiest quoting boundary. The shell must
    still see the literal quote as data, not an opened/dangling quote.
    """
    spec = RequestSpec(method="GET", url="https://api.test/a",
                       headers={"X-Q": "'"})
    curl = poc.to_curl(spec)
    argv = shlex.split(curl)              # would raise if quoting were unbalanced
    assert "X-Q: '" in argv


# --------------------------------------------------------------------------
# Round-trip fidelity: method + query + custom headers + body -> all 3 formats
# --------------------------------------------------------------------------

def _fidelity_spec():
    return RequestSpec(
        method="PUT",
        url="https://api.test/search?q=cats&page=2",
        headers={"X-Custom": "v1", "Accept": "application/json"},
        body='{"k":"v"}',
    )


def test_roundtrip_curl_preserves_method_query_headers_body():
    argv = shlex.split(poc.to_curl(_fidelity_spec()))
    assert argv[argv.index("-X") + 1] == "PUT"                      # method
    assert "https://api.test/search?q=cats&page=2" in argv          # query survives
    assert "X-Custom: v1" in argv and "Accept: application/json" in argv  # headers
    assert argv[argv.index("--data-raw") + 1] == '{"k":"v"}'        # body


def test_roundtrip_python_preserves_method_query_headers_body():
    script = poc.to_python(_fidelity_spec())
    compile(script, "<poc>", "exec")                               # valid Python
    assert "method='PUT'" in script                                # method
    assert "q=cats&page=2" in script                               # query survives
    assert "req.add_header('X-Custom', 'v1')" in script            # header
    assert "req.add_header('Accept', 'application/json')" in script
    assert "'{\"k\":\"v\"}'.encode()" in script                    # body


def test_roundtrip_http_raw_preserves_method_query_headers_body():
    raw = poc.to_http_raw(_fidelity_spec())
    assert raw.startswith("PUT /search?q=cats&page=2 HTTP/1.1")    # method + query
    assert "Host: api.test" in raw
    assert "X-Custom: v1" in raw and "Accept: application/json" in raw  # headers
    assert raw.endswith('{"k":"v"}')                               # body last


# --------------------------------------------------------------------------
# Generated Python PoC is syntactically valid even with adversarial content
# --------------------------------------------------------------------------

def test_python_poc_with_adversarial_content_compiles():
    """repr()-based codegen must stay valid Python when values carry quotes,
    backslashes, and newlines (the tokens most likely to break naive string
    interpolation). Compile only — never execute.
    """
    spec = RequestSpec(
        method="POST",
        url="https://api.test/p?x=a b",
        headers={"X-Tricky": "he said \"hi\"\nand 'bye'\\done"},
        body="line1\nline2 'q' \"dq\" \\ end",
    )
    script = poc.to_python(spec)
    compile(script, "<poc>", "exec")     # SyntaxError here would fail the test


# --------------------------------------------------------------------------
# Tamper semantics: method / query / header / body mutations
# --------------------------------------------------------------------------

def test_tamper_change_method_and_falsy_fallback():
    s = RequestSpec(method="GET", url="https://api.test/a", body="keep")
    assert s.tamper(method="DELETE").method == "DELETE"            # method replaced
    # Falsy method falls back via `method or self.method`; body/url untouched.
    fallback = s.tamper(method="")
    assert fallback.method == "GET" and fallback.body == "keep"


def test_with_query_adds_new_and_replaces_existing():
    s = RequestSpec(method="GET", url="https://api.test/orders?id=1#frag")
    assert s.with_query("page", "3").url == "https://api.test/orders?id=1&page=3#frag"  # add branch
    assert s.with_query("id", "2").url == "https://api.test/orders?id=2#frag"           # replace branch


def test_set_header_add_and_replace():
    s = RequestSpec(method="GET", url="https://api.test/a", headers={"A": "1"})
    assert s.with_header("B", "2").headers == {"A": "1", "B": "2"}  # add new
    assert s.with_header("A", "9").headers == {"A": "9"}            # overwrite existing
    assert s.tamper(A="7").headers == {"A": "7"}                    # tamper overrides header
    assert s.headers == {"A": "1"}                                  # original immutable


def test_tamper_replace_body_distinguishes_empty_from_unset():
    s = RequestSpec(method="POST", url="https://api.test/a", body="orig")
    assert s.tamper(body="new").body == "new"                      # replaced
    assert s.tamper(body="").body == ""                            # empty string DOES empty it
    assert s.tamper().body == "orig"                               # unset (None) keeps original
