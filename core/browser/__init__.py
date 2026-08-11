"""Headless-browser harness — the JS-execution primitive RAPTOR lacked.

HTTP-only tooling is blind on modern single-page apps: if the app renders
client-side, a non-JS fetch sees an empty shell. This subsystem drives a real
headless Chromium (via Playwright) so RAPTOR can see the rendered DOM, the
endpoints a SPA calls at runtime, the forms it injects, its ``postMessage``
channels, and its console output — unlocking DOM XSS, client-side prototype
pollution, postMessage abuse, and JS-heavy endpoint discovery.

Pieces:

  - :mod:`core.browser.harness` — Playwright + Chromium lifecycle and the egress
    envelope (Chromium routed through RAPTOR's hostname-allowlist proxy).
  - :mod:`core.browser.session` — one page: navigate (egress-gated), evaluate JS,
    capture network/console/postMessage/forms, screenshot.
  - :mod:`core.browser.capture` — captured artifacts (Playwright-free) + their
    projection to :mod:`core.webgraph` records.
  - :mod:`core.browser.crawl_source` — a DOM-aware crawl registered as a web-graph
    source, landing on the same nodes as the static crawl and spec import.

Playwright + Chromium are an optional dependency; :func:`core.browser.harness.available`
reports installation so callers degrade with a clear ``playwright install
chromium`` hint.
"""

from core.browser.harness import (
    BrowserEgressError, BrowserHarness, BrowserUnavailable, available,
)

__all__ = ["BrowserHarness", "BrowserUnavailable", "BrowserEgressError", "available"]
