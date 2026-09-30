"""
core/parser/urls.py
URL extraction from plain-text and HTML email bodies.

Plain text uses a regex.  HTML uses :class:`html.parser.HTMLParser` (stdlib)
to extract ``href``, ``src``, and ``action`` attributes without executing
JavaScript or fetching any remote resources.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser


# ---------------------------------------------------------------------------
# Regex for plain-text URL extraction
# ---------------------------------------------------------------------------

_RE_URL = re.compile(
    r"(https?://[^\s<>\"'`\)\]\}]+|ftp://[^\s<>\"'`\)\]\}]+)",
    re.IGNORECASE,
)

_TRAILING_PUNCT = re.compile(r"[.,;:!?\)\]\}>]+$")


# ---------------------------------------------------------------------------
# HTML attribute extractor (stdlib, no external deps)
# ---------------------------------------------------------------------------

class _HTMLURLExtractor(HTMLParser):
    """Extract ``href`` / ``src`` / ``action`` URLs from HTML tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for attr, value in attrs:
            if attr in ("href", "src", "action") and value:
                value = value.strip()
                if value.startswith(("http://", "https://", "ftp://")):
                    self.urls.append(value)

    def error(self, message: str) -> None:  # pragma: no cover
        """Suppress errors on malformed HTML (deprecated in 3.5+)."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_urls_from_text(text: str) -> list[str]:
    """Extract unique URLs from plain text using regex.

    Trailing punctuation (``.``, ``,``, ``;``, etc.) is stripped.
    """
    seen: set[str] = set()
    urls: list[str] = []
    for match in _RE_URL.finditer(text):
        url = _TRAILING_PUNCT.sub("", match.group(1))
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def extract_urls_from_html(html: str) -> list[str]:
    """Extract unique URLs from HTML ``href``/``src``/``action`` attributes."""
    extractor = _HTMLURLExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass  # malformed HTML — return what we collected so far

    seen: set[str] = set()
    urls: list[str] = []
    for url in extractor.urls:
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def extract_all_urls(body_plain: str, body_html: str) -> list[str]:
    """Union of URLs from both plain-text and HTML bodies (deduplicated)."""
    seen: set[str] = set()
    urls: list[str] = []

    for url in extract_urls_from_text(body_plain):
        if url not in seen:
            seen.add(url)
            urls.append(url)

    for url in extract_urls_from_html(body_html):
        if url not in seen:
            seen.add(url)
            urls.append(url)

    return urls
