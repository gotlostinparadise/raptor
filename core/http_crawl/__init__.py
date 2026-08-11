"""Static HTTP crawl — the server-rendered counterpart to the browser crawl.

Where :mod:`core.browser.crawl_source` drives headless Chromium to render an SPA,
this subsystem needs nothing but an HTTP client: it fetches an app's HTML over
:mod:`core.http`, follows same-origin ``<a href>`` links, and turns each page's
links + forms into the ``(type, id)`` web graph's page / endpoint / parameter /
form records. That maps the large class of classic, server-rendered apps (DVWA,
WebGoat, most non-SPA sites) whose injectable/authz surface the browser crawl and
API-spec import miss.

Two pieces, mirroring the recon / webgraph source split:

  - :mod:`core.http_crawl.parse` — pure HTML → links / forms / fields extraction
    (stdlib :class:`html.parser.HTMLParser`; no network, no new dependency).
  - :mod:`core.http_crawl.source` — the :class:`~core.webgraph.source.Source`
    plugin (``http_crawl``) that drives the breadth-first crawl and emits records.

Authenticated crawl: when the run carries a :class:`core.session.SessionEngine`,
every fetch goes *through* that engine as the logged-in identity, so its cookie
jar + auth headers ride along and the crawl reaches the post-login surface.
"""

__all__ = ["parse", "source"]
