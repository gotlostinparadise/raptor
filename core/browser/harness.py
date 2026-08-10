"""Headless-Chromium harness — Playwright lifecycle + egress discipline.

The single biggest gap in RAPTOR's web testing was that it never executed
JavaScript: a non-JS fetch of a modern SPA sees an empty shell. This harness
closes it by driving a real headless Chromium via Playwright.

Egress discipline is not optional. A browser will fetch whatever a page tells it
to, so an active crawl MUST be constrained: when ``proxy_hosts`` is given the
harness routes Chromium through RAPTOR's in-process egress proxy
(:func:`core.sandbox.proxy.get_proxy`), whose hostname allowlist refuses any
CONNECT outside the target — the same guarantee ``EgressClient`` gives app-level
HTTP. Navigations to a remote host with neither a proxy nor an explicit
``allow_unproxied`` opt-out are refused (see :meth:`core.browser.session.BrowserSession.navigate`).
Loopback / ``file:`` / ``data:`` targets need no proxy (no third-party egress).

Playwright + Chromium are an optional dependency; :meth:`available` reports
whether they are installed so callers degrade gracefully (``playwright install
chromium``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, Sequence


class BrowserUnavailable(RuntimeError):
    """Playwright and/or its Chromium build is not installed."""


class BrowserEgressError(RuntimeError):
    """A navigation would leave the allowlisted egress envelope."""


def available() -> bool:
    """True when Playwright imports and its Chromium build is on disk."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as pw:
            path = pw.chromium.executable_path
        return bool(path) and Path(path).exists()
    except Exception:
        return False


class BrowserHarness:
    """Owns the Playwright + Chromium process; hands out sessions.

    Use as a context manager::

        with BrowserHarness(proxy_hosts=["app.example.com"]) as h:
            s = h.new_session()
            s.navigate("https://app.example.com/")
            cap = s.capture()
    """

    def __init__(
        self,
        *,
        headless: bool = True,
        proxy_hosts: Sequence[str] = (),
        allow_unproxied: bool = False,
        nav_timeout_ms: int = 15000,
    ) -> None:
        self.headless = headless
        self.proxy_hosts = tuple(proxy_hosts)
        self.allow_unproxied = allow_unproxied
        self.nav_timeout_ms = nav_timeout_ms
        self._pw = None
        self._browser = None
        self._sessions: List[Any] = []

    @property
    def proxy_configured(self) -> bool:
        return bool(self.proxy_hosts)

    def __enter__(self) -> "BrowserHarness":
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - env without playwright
            raise BrowserUnavailable(
                "playwright not installed; run `pip install playwright && "
                "playwright install chromium`"
            ) from exc
        self._pw = sync_playwright().start()
        launch_kwargs: dict = {"headless": self.headless}
        if self.proxy_configured:
            from core.sandbox.proxy import get_proxy
            proxy = get_proxy()
            proxy.add_hosts(list(self.proxy_hosts))
            proxy.register_sandbox("browser-harness")
            launch_kwargs["proxy"] = {"server": f"http://127.0.0.1:{proxy.port}"}
        self._browser = self._pw.chromium.launch(**launch_kwargs)
        return self

    def __exit__(self, *exc: Any) -> None:
        for s in self._sessions:
            try:
                s.close()
            except Exception:
                pass
        self._sessions.clear()
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._pw is not None:
            try:
                self._pw.stop()
            except Exception:
                pass
            self._pw = None

    def new_session(
        self,
        *,
        extra_http_headers: Optional[dict] = None,
        cookies: Optional[Sequence[dict]] = None,
    ) -> Any:
        """Create an isolated browser context + page (its own cookie jar).

        ``extra_http_headers`` and ``cookies`` seed the context as a session
        identity (see :func:`core.browser.auth.context_args_for_identity`) so the
        crawl runs authenticated; both default to none for an anonymous session.
        """
        if self._browser is None:
            raise RuntimeError("harness not started; use `with BrowserHarness(...)`")
        from core.browser.session import BrowserSession
        ctx_kwargs: dict = {}
        if extra_http_headers:
            ctx_kwargs["extra_http_headers"] = dict(extra_http_headers)
        context = self._browser.new_context(**ctx_kwargs)
        if cookies:
            context.add_cookies(list(cookies))
        session = BrowserSession(self, context)
        self._sessions.append(session)
        return session


__all__ = ["BrowserHarness", "BrowserUnavailable", "BrowserEgressError", "available"]
