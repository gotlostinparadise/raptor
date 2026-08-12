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

from typing import Any, Callable, Dict, List, Optional, Sequence

from core.injection.config import build_target_url
from core.injection.markers import MarkerFactory


def _execution_fires(harness: Any, url: str, tok: str,
                     session_headers: Optional[Dict[str, str]]) -> bool:
    """Navigate ``url`` and poll for our ``window.__raptor_xss`` sentinel.

    An SPA renders (and runs the injected handler) asynchronously, so we poll for
    up to ~2s and return the instant the sentinel equals ``tok`` — execution, not
    reflection, is the verdict. Shared by the reflected/DOM and stored oracles.
    """
    session = (harness.new_session(extra_http_headers=session_headers)
               if session_headers else harness.new_session())
    fired = None
    try:
        session.navigate(url)
        for _ in range(20):
            try:
                fired = session.eval_js("window.__raptor_xss")
            except Exception:
                fired = None
            if fired == tok:
                break
            try:
                session.eval_js("new Promise(r => setTimeout(r, 100))")
            except Exception:
                break
    except Exception:
        fired = None
    finally:
        try:
            session.close()
        except Exception:
            pass
    return fired == tok


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
    reflection. ``query`` points (real query string) and ``fragment`` points (SPA
    hash-routes like ``/#/search?q=…``) are both driven by GET navigation — the
    fragment case is where SPA/DOM XSS actually lives; ``session_headers`` seed an
    authenticated context.
    """
    from core.payloads import default_store, propose
    markers = markers or MarkerFactory(salt="domxss")
    vectors = [e for e in propose(default_store(), "xss", model=model)
               if "dom" in e.tags]
    findings: List[Dict[str, Any]] = []
    for point in points:
        if getattr(point, "location", "query") not in ("query", "fragment"):
            continue
        for entry in vectors:
            tok = markers.next().token
            payload = entry.render(tok=tok)     # sets window.__raptor_xss='tok'
            url = build_target_url(base_url, point, payload)
            if _execution_fires(harness, url, tok, session_headers):
                findings.append({"point": point, "token": tok, "payload": payload,
                                 "entry": entry.id, "context": "dom-executed"})
                break
    return findings


def confirm_stored_xss(
    harness: Any,
    base_url: str,
    write_points: Sequence[Any],
    render_urls: Sequence[str],
    *,
    writer: Callable[[Any, str], Any],
    markers: Optional[MarkerFactory] = None,
    session_headers: Optional[Dict[str, str]] = None,
    model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Confirm STORED XSS: a payload persisted at one endpoint executes on another.

    Unlike reflected/DOM XSS, the write target and the render target are
    **decoupled** — the payload is POSTed once (``writer(point, payload)``) then
    the stored copy renders on some *other* page. For each write point we plant a
    DOM-capable vector (it sets ``window.__raptor_xss``), then re-navigate each
    candidate ``render_urls`` page in a fresh browser session and poll for the
    sentinel. A hit proves the stored payload executed on that page — a confirmed
    stored XSS (``PROOF_STATE_ORACLE``), with no false positive from mere
    reflection. ``writer`` performs the persist (an HTTP POST via the session
    engine in production; a stub in tests); the browser only reads back.
    """
    from core.payloads import default_store, propose
    markers = markers or MarkerFactory(salt="storedxss")
    vectors = [e for e in propose(default_store(), "xss", model=model)
               if "dom" in e.tags]
    findings: List[Dict[str, Any]] = []
    for point in write_points:
        if getattr(point, "location", "query") not in ("query", "body"):
            continue
        confirmed = False
        for entry in vectors:
            if confirmed:
                break
            tok = markers.next().token
            payload = entry.render(tok=tok)
            try:
                writer(point, payload)          # persist the payload
            except Exception:
                continue
            for url in render_urls:
                full = url if "://" in url else f"{base_url}{url}"
                if _execution_fires(harness, full, tok, session_headers):
                    findings.append({
                        "point": point, "render_url": url, "token": tok,
                        "payload": payload, "entry": entry.id,
                        "context": "stored-dom-executed"})
                    confirmed = True
                    break
    return findings


__all__ = ["confirm_dom_xss", "confirm_stored_xss"]
