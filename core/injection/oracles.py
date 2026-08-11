"""Detection oracles — the mechanical verdicts for injection findings.

Each oracle turns a response (or a set of responses) into a boolean/labelled
verdict with no LLM in the loop:

  - :func:`sql_error` — a database error signature in the body (error-based SQLi).
  - :func:`reflected` / :func:`ssti_confirmed` — a *computed* marker in the body
    (SSTI/command-echo): the value proves evaluation, not mere reflection.
  - :func:`boolean_diff` — true-payload response matches the baseline while the
    false-payload response diverges (blind boolean SQLi / NoSQLi).
  - :func:`metadata_leak` — cloud-metadata content returned (SSRF → metadata).

OAST callback confirmation (blind SSRF/RCE/XXE/OOB-SQLi) is handled by
:mod:`core.oast` directly and adapted in the runner.
"""

from __future__ import annotations

import re
from typing import Optional

# Database error signatures — presence in a response body is strong evidence of
# error-based SQL injection. Case-insensitive.
_SQL_ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "mysql"),
    (r"warning:\s*mysqli?", "mysql"),
    (r"unclosed quotation mark after the character string", "mssql"),
    (r"quoted string not properly terminated", "oracle"),
    (r"ORA-\d{5}", "oracle"),
    (r"syntax error at or near", "postgres"),
    (r"pg_query\(\)|pg_exec\(\)", "postgres"),
    (r"sqlite3?\.(OperationalError|DatabaseError)", "sqlite"),
    (r"SQLite/JDBCDriver|SQLITE_ERROR", "sqlite"),
    (r"java\.sql\.SQLException|org\.hibernate", "jdbc"),
    (r"SQLSTATE\[", "generic"),
    (r"Microsoft OLE DB Provider for SQL Server", "mssql"),
]

_SQL_ERROR_RE = [(re.compile(p, re.I), db) for p, db in _SQL_ERROR_SIGNATURES]

# Cloud-metadata content signatures. Deliberately limited to strings that appear
# in a metadata *response body*, NOT in the request URL we send — otherwise an
# endpoint that merely reflects the payload URL (which contains ``computeMetadata``,
# ``meta-data/...``) would false-positive as SSRF without any fetch happening.
_METADATA_SIGNATURES = [
    r"ami-id", r"instance-id", r"AccessKeyId", r"SecretAccessKey",
    r"InstanceProfileArn", r"\"privateIpv4\"", r"security-credentials/",
]
_METADATA_RE = [re.compile(p, re.I) for p in _METADATA_SIGNATURES]


def _text(resp) -> str:
    body = getattr(resp, "body", b"") or b""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def sql_error(resp) -> Optional[str]:
    """Return the matched DB label if a SQL error signature is present, else None."""
    text = _text(resp)
    for rx, db in _SQL_ERROR_RE:
        if rx.search(text):
            return db
    return None


def reflected(resp, needle: str) -> bool:
    """True when ``needle`` appears verbatim in the response body."""
    return bool(needle) and needle in _text(resp)


def ssti_confirmed(resp, expected: str) -> bool:
    """True when the *computed* SSTI marker product is in the body."""
    return reflected(resp, expected)


def xss_reflected(resp, expected: str) -> bool:
    """True when the *unescaped* XSS fragment appears verbatim in the response.

    ``expected`` is a raw HTML fragment (``<img ... onerror="tok">``). If the app
    HTML-encodes the input, the ``<``/``"`` become entities and the fragment is
    absent — so a safely-escaped reflection is NOT flagged. A raw match means the
    tag is injected into the markup and would execute in a browser.
    """
    return reflected(resp, expected)


def metadata_leak(resp) -> bool:
    """True when the body looks like cloud-metadata content (SSRF→metadata)."""
    text = _text(resp)
    return any(rx.search(text) for rx in _METADATA_RE)


def _fingerprint(resp):
    body = getattr(resp, "body", b"") or b""
    return (getattr(resp, "status", None), len(body))


def _similar(a, b, *, len_tol: float = 0.05) -> bool:
    """Two responses look the same: same status and near-equal length."""
    (sa, la), (sb, lb) = _fingerprint(a), _fingerprint(b)
    if sa != sb:
        return False
    hi = max(la, lb, 1)
    return abs(la - lb) / hi <= len_tol


def boolean_diff(baseline, true_resp, false_resp) -> bool:
    """Blind boolean oracle.

    Confirmed when the TRUE-condition response resembles the baseline while the
    FALSE-condition response diverges — the app is branching on our injected
    predicate. Requires a real divergence (true ≠ false) so a page that always
    looks identical can't produce a false positive.
    """
    return _similar(baseline, true_resp) and not _similar(true_resp, false_resp)


def stable_boolean(baseline, true1, true2, false_resp) -> bool:
    """Jitter-resistant boolean oracle.

    The TRUE payload is sent twice; a confirmation requires the two TRUE
    responses to be *stable* (``true1`` ≈ ``true2``) as well as
    ``true`` ≈ ``baseline`` and ``true`` ≠ ``false``. If the page has natural
    length jitter (nonces, timestamps, ads), ``true1`` and ``true2`` diverge and
    the oracle abstains — killing the false positive that plain
    :func:`boolean_diff` would produce on a dynamic page.
    """
    return (_similar(true1, true2)
            and _similar(baseline, true1)
            and not _similar(true1, false_resp))


__all__ = [
    "sql_error", "reflected", "ssti_confirmed", "metadata_leak", "boolean_diff",
]
