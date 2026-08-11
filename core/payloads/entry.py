"""Payload catalog vocabulary — the oracle-tagged, slotted payload entry.

The catalog is RAPTOR's payload *knowledge storage*: a growing, enrichable set of
attack payloads, each tagged with (a) the vulnerability class it targets, (b) the
reflection **context** it belongs in (HTML body, an attribute, a JS string, a URI…),
(c) the **oracle** that can mechanically confirm it, and (d) whether it is
**destructive** (destructive payloads are never sent).

The oracle tag is the load-bearing field: in RAPTOR an LLM may *propose* which
payloads to try, but only a mechanical oracle *confirms* — so every entry must
declare how a hit is verified. Templates carry slots the renderer fills:

  ``{tok}``  a unique marker token          ``{a}`` ``{b}`` ``{prod}``  arithmetic (a*b)
  ``{oast}`` an out-of-band callback host

An entry with no fillable oracle signal (a raw payload the runner can't verify)
does not belong here — that is what keeps the catalog from diluting soundness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple

# ─────────────────────────── oracle kinds ───────────────────────────
# How a hit is mechanically confirmed (the ONLY thing that makes a finding).
ORACLE_UNESCAPED = "unescaped"        # the raw payload appears un-encoded in the body
ORACLE_COMPUTED = "computed"          # a computed value (a*b) appears → evaluation/exec
ORACLE_DOM = "dom"                    # a sentinel set in a real browser → DOM execution
ORACLE_ERROR_SIGNATURE = "error_sig"  # a database/interpreter error signature appears
ORACLE_CONTENT = "content"            # oracle-specific content (file leak, metadata)
ORACLE_OAST = "oast"                  # an out-of-band callback correlates
ORACLES = (ORACLE_UNESCAPED, ORACLE_COMPUTED, ORACLE_DOM, ORACLE_ERROR_SIGNATURE,
           ORACLE_CONTENT, ORACLE_OAST)

# ─────────────────────────── reflection contexts ───────────────────────────
CTX_ANY = "any"
CTX_HTML_BODY = "html_body"
CTX_ATTR_DOUBLE = "attr_double"
CTX_ATTR_SINGLE = "attr_single"
CTX_JS_STRING = "js_string"
CTX_URI = "uri"
CTX_COMMENT = "comment"
CONTEXTS = (CTX_ANY, CTX_HTML_BODY, CTX_ATTR_DOUBLE, CTX_ATTR_SINGLE,
            CTX_JS_STRING, CTX_URI, CTX_COMMENT)


@dataclass(frozen=True)
class PayloadEntry:
    id: str
    vuln_class: str
    template: str
    oracle: str = ORACLE_UNESCAPED
    context: str = CTX_ANY
    technique: str = ""
    destructive: bool = False
    source: str = "seed"
    tags: Tuple[str, ...] = ()

    def render(self, *, tok: str = "", a: int = 0, b: int = 0, oast: str = "") -> str:
        """Fill the template's slots. ``{prod}`` is the a*b product."""
        return (self.template
                .replace("{tok}", tok)
                .replace("{a}", str(a))
                .replace("{b}", str(b))
                .replace("{prod}", str(a * b))
                .replace("{oast}", oast))

    def expected(self, *, tok: str = "", a: int = 0, b: int = 0) -> str:
        """The mechanical oracle's expected substring for this rendered payload.

        - ``unescaped``: the rendered payload itself (its raw presence == injection).
        - ``computed``: the token-wrapped product (``tok`` + a*b + ``tok``) — a value
          that only appears if the target *evaluated* the payload, never on reflection.
        - others: empty (those oracles match on their own signatures/side effects).
        """
        if self.oracle == ORACLE_UNESCAPED:
            return self.render(tok=tok, a=a, b=b)
        if self.oracle == ORACLE_COMPUTED:
            return f"{tok}{a * b}{tok}"
        return ""


__all__ = [
    "PayloadEntry", "ORACLES", "CONTEXTS",
    "ORACLE_UNESCAPED", "ORACLE_COMPUTED", "ORACLE_DOM", "ORACLE_ERROR_SIGNATURE",
    "ORACLE_CONTENT", "ORACLE_OAST",
    "CTX_ANY", "CTX_HTML_BODY", "CTX_ATTR_DOUBLE", "CTX_ATTR_SINGLE",
    "CTX_JS_STRING", "CTX_URI", "CTX_COMMENT",
]
