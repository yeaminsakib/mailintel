"""
core/parser/text.py
Turn an HTML mail body into inert plain text for storage and display.

Only text nodes are kept: tags, ``<script>``, ``<style>`` and comments are
dropped, so nothing from the mail can be rendered or executed later.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

#: Upper bound for the body text kept in the database (characters).
MAX_BODY_CHARS: int = 100_000

_SKIP_TAGS = frozenset({"script", "style", "head", "title"})
_BLOCK_TAGS = frozenset({"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table"})
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_BLANKS_RE = re.compile(r"\n{3,}")


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def html_to_text(html: str) -> str:
    """Return the visible text of *html* (empty string for empty/invalid input)."""
    if not html:
        return ""
    extractor = _TextExtractor()
    try:
        extractor.feed(html)
        extractor.close()
    except Exception:  # malformed HTML: keep what was collected
        pass
    return _clean(extractor.text())


def body_text_for_storage(body_plain: str, body_html: str) -> str:
    """Pick the plain body, else the text of the HTML body; cap its length."""
    text = _clean(body_plain) if body_plain and body_plain.strip() else html_to_text(body_html)
    return text[:MAX_BODY_CHARS]


def _clean(text: str) -> str:
    lines = (_WS_RE.sub(" ", line).strip() for line in text.replace("\r\n", "\n").split("\n"))
    return _BLANKS_RE.sub("\n\n", "\n".join(lines)).strip()
