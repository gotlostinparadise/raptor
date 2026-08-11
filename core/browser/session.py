"""A single browser session — navigate, capture, and evaluate JS on a page.

Wraps one Playwright context+page and installs the capture hooks that make the
harness worth having: every network request/response (so runtime XHR/fetch
endpoints are recorded), console output, and ``window.postMessage`` traffic
(via an injected listener). :meth:`capture` snapshots the page into a
:class:`~core.browser.capture.PageCapture` ready for
:func:`~core.browser.capture.records_from_capture`.
"""

from __future__ import annotations

from typing import Any, List, Optional
from urllib.parse import urlsplit

from core.browser.capture import (
    ConsoleMessage, FormCapture, NetworkRequest, PageCapture, PostMessageEvent,
)
from core.browser.harness import BrowserEgressError

# Injected before any page script runs: record inbound postMessage events so a
# later evaluate() can read them. Kept tiny and defensive (never throws).
_PM_HOOK = """
window.__raptor_pm = window.__raptor_pm || [];
window.addEventListener('message', function (e) {
  try {
    window.__raptor_pm.push({
      origin: e.origin,
      data: (typeof e.data === 'string') ? e.data : JSON.stringify(e.data)
    });
  } catch (x) {}
}, false);
"""

_FORMS_JS = """
() => Array.from(document.forms).map(f => ({
  action: f.action || location.href,
  method: (f.method || 'GET').toUpperCase(),
  fields: Array.from(f.elements).map(e => e.name).filter(Boolean)
}))
"""


class BrowserSession:
    def __init__(self, harness: Any, context: Any) -> None:
        self.harness = harness
        self._context = context
        self._page = context.new_page()
        self._requests: List[NetworkRequest] = []
        self._console: List[ConsoleMessage] = []
        self._last_status: Optional[int] = None

        self._page.add_init_script(_PM_HOOK)
        self._page.on("response", self._on_response)
        self._page.on("console", self._on_console)

    # ------------------------------------------------------------------
    # capture hooks
    # ------------------------------------------------------------------
    def _on_response(self, response: Any) -> None:
        try:
            req = response.request
            self._requests.append(NetworkRequest(
                url=req.url, method=req.method,
                resource_type=req.resource_type, status=response.status,
            ))
        except Exception:
            pass

    def _on_console(self, msg: Any) -> None:
        try:
            self._console.append(ConsoleMessage(level=msg.type, text=msg.text))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # egress-gated navigation
    # ------------------------------------------------------------------
    def _egress_ok(self, url: str) -> bool:
        parts = urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme in ("file", "data", "about"):
            return True
        host = (parts.hostname or "").lower()
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
            return True
        return self.harness.proxy_configured or self.harness.allow_unproxied

    def navigate(self, url: str, *, wait_until: str = "load") -> Optional[int]:
        """Load ``url`` (egress-gated). Returns the top-level HTTP status."""
        if not self._egress_ok(url):
            raise BrowserEgressError(
                f"refusing to navigate to {url!r}: remote host with no egress "
                f"proxy configured (pass proxy_hosts=[...] or allow_unproxied)"
            )
        resp = self._page.goto(url, wait_until=wait_until,
                               timeout=self.harness.nav_timeout_ms)
        self._last_status = resp.status if resp is not None else None
        return self._last_status

    # ------------------------------------------------------------------
    # inspection
    # ------------------------------------------------------------------
    def eval_js(self, script: str) -> Any:
        return self._page.evaluate(script)

    def content(self) -> str:
        return self._page.content()

    def links(self) -> List[str]:
        return self._page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")

    def forms(self) -> List[FormCapture]:
        raw = self._page.evaluate(_FORMS_JS)
        return [FormCapture(action=f.get("action", ""), method=f.get("method", "GET"),
                            fields=list(f.get("fields") or [])) for f in raw]

    def postmessages(self) -> List[PostMessageEvent]:
        raw = self._page.evaluate("window.__raptor_pm || []")
        return [PostMessageEvent(origin=e.get("origin", ""), data=str(e.get("data", "")))
                for e in raw]

    def screenshot(self, path: str) -> str:
        self._page.screenshot(path=path)
        return path

    def capture(self) -> PageCapture:
        """Snapshot the current page into a :class:`PageCapture`."""
        try:
            title = self._page.title()
        except Exception:
            title = ""
        return PageCapture(
            url=self._page.url, final_url=self._page.url, title=title,
            status=self._last_status, links=self.links(), forms=self.forms(),
            requests=list(self._requests), console=list(self._console),
            postmessages=self.postmessages(),
        )

    def close(self) -> None:
        try:
            self._page.close()
        finally:
            self._context.close()


__all__ = ["BrowserSession"]
