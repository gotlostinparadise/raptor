"""Browser-backed DOM-XSS confirmation — the strongest XSS proof: execution.

The reflected-HTML oracle (:func:`core.injection.oracles.xss_reflected`) catches
*server*-reflected XSS, but SPA/DOM XSS only fires after client-side rendering —
the payload never appears raw in the HTTP response. This drives the payload
through a real headless Chromium (:mod:`core.browser`) and confirms the injected
handler actually **executed**: the payload sets a unique sentinel on ``window``,
and a match means the browser ran our code. Execution — not reflection — is the
verdict, so there is no false positive from a merely-reflected-but-inert string.

Pure of Playwright itself: it takes a ``harness`` (anything exposing
``new_session()`` → a session with ``navigate`` / ``eval_js`` / ``close``), so it
is unit-testable with a stub and works with the real
:class:`core.browser.harness.BrowserHarness` in production.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.injection.markers import MarkerFactory


def _url_with(base_url: str, point, value: str) -> str:
    parts = urlsplit(f"{base_url}{point.path}")
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
         if k != point.param]
    q.append((point.param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def confirm_dom_xss(
    harness: Any,
    base_url: str,
    points: Sequence[Any],
    *,
    markers: Optional[MarkerFactory] = None,
    session_headers: Optional[Dict[str, str]] = None,
    model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return the query-param points whose XSS payload *executed* in the browser.

    Draws its vectors from the payload catalog's DOM-capable XSS entries (each
    sets a unique ``window.__raptor_xss`` sentinel), proposer-ordered — so it
    tries not just ``img/onerror`` but the ``<iframe src="javascript:…">``
    sanitiser-bypass that catches Angular DOM-XSS. A match proves execution, not
    reflection. Only ``query`` points are driven (GET navigation); ``session_headers``
    seed an authenticated context.
    """
    from core.payloads import default_store, propose
    markers = markers or MarkerFactory(salt="domxss")
    vectors = [e for e in propose(default_store(), "xss", model=model)
               if "dom" in e.tags]
    findings: List[Dict[str, Any]] = []
    for point in points:
        if getattr(point, "location", "query") != "query":
            continue
        confirmed = False
        for entry in vectors:
            if confirmed:
                break
            tok = markers.next().token
            payload = entry.render(tok=tok)     # sets window.__raptor_xss='tok'
            url = _url_with(base_url, point, payload)
            session = (harness.new_session(extra_http_headers=session_headers)
                       if session_headers else harness.new_session())
            fired = None
            try:
                session.navigate(url)
                try:
                    session.eval_js("new Promise(r => setTimeout(r, 150))")
                except Exception:
                    pass
                fired = session.eval_js("window.__raptor_xss")
            except Exception:
                fired = None
            finally:
                try:
                    session.close()
                except Exception:
                    pass
            if fired == tok:
                findings.append({"point": point, "token": tok, "payload": payload,
                                 "entry": entry.id, "context": "dom-executed"})
                confirmed = True
    return findings


__all__ = ["confirm_dom_xss"]
