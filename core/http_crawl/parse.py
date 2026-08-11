"""Static HTML parsing for the HTTP crawler — links, forms, and their fields.

Pure functions over an HTML string: no network, no framework. The crawler source
(:mod:`core.http_crawl.source`) fetches a page and hands the body here to extract
the two things a server-rendered app exposes without JavaScript:

  * ``<a href>`` hyperlinks — the crawl frontier and, when a link carries a query
    string, an endpoint + its query parameters.
  * ``<form action method>`` + its named fields (``input`` / ``select`` /
    ``textarea`` / ``button``) — the injectable write surface (a POST form's
    fields are body params, a GET form's are query params).

Everything is stdlib (:class:`html.parser.HTMLParser`) so the crawler gains no new
dependency; a malformed page degrades to "as much as we could parse" rather than
raising. Hrefs and form actions are resolved to absolute URLs against the page
URL here, so the source never re-implements URL joining.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional
from urllib.parse import urljoin

# Field-bearing tags whose ``name`` attribute becomes a form parameter.
_FIELD_TAGS = {"input", "select", "textarea", "button"}
# Non-navigational href schemes / pure in-page anchors we never enqueue.
_SKIP_PREFIXES = ("javascript:", "mailto:", "tel:", "data:", "vbscript:")


@dataclass
class ParsedForm:
    """An HTML form: its (absolute) submit target, method, and named fields."""

    action: str
    method: str = "GET"
    fields: List[str] = field(default_factory=list)


@dataclass
class ParsedPage:
    """The links + forms + title harvested from one page's HTML."""

    url: str
    title: str = ""
    links: List[str] = field(default_factory=list)   # absolute hrefs
    forms: List[ParsedForm] = field(default_factory=list)


def _skip_href(href: str) -> bool:
    """True for a pure fragment / non-navigational scheme that is not a crawl target."""
    if not href or href.startswith("#"):
        return True
    return href.lower().startswith(_SKIP_PREFIXES)


class _PageParser(HTMLParser):
    """Collect hyperlinks, forms + their fields, and the document title."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base = base_url
        self.links: List[str] = []
        self.forms: List[ParsedForm] = []
        self.title = ""
        self._form: Optional[ParsedForm] = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a":
            href = a.get("href", "").strip()
            if not _skip_href(href):
                self.links.append(urljoin(self._base, href))
        elif tag == "form":
            method = (a.get("method") or "GET").strip().upper()
            action = a.get("action", "").strip()
            # A form with no/relative action submits back to the page it lives on.
            self._form = ParsedForm(
                action=urljoin(self._base, action) if action else self._base,
                method=method if method in ("GET", "POST") else "GET",
            )
            self.forms.append(self._form)
        elif tag in _FIELD_TAGS and self._form is not None:
            name = a.get("name", "").strip()
            if name and name not in self._form.fields:
                self._form.fields.append(name)
        elif tag == "title":
            self._in_title = True

    def handle_startendtag(self, tag, attrs):
        # Self-closing tags (``<input .../>``) still carry a field name.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def parse_page(html_text: str, page_url: str) -> ParsedPage:
    """Extract links, forms, and title from ``html_text`` (fetched from ``page_url``).

    Hrefs / form actions come back absolute (resolved against ``page_url``). A
    parse error never propagates — the partial result gathered so far is returned.
    """
    parser = _PageParser(page_url)
    try:
        parser.feed(html_text)
    except Exception:  # malformed HTML: keep what we parsed, don't abort the crawl
        pass
    return ParsedPage(url=page_url, title=parser.title.strip(),
                      links=parser.links, forms=parser.forms)


__all__ = ["ParsedForm", "ParsedPage", "parse_page"]
