"""
app/graph_view.py
Hardened QWebEnginePage for the threat graph.

The graph HTML embeds attacker-controlled strings (subjects, senders, URLs),
so the page is treated as untrusted:

- remote and file:// access from the local page is disabled, so script that
  slips through cannot beacon out or read local files;
- every navigation away from the rendered page is refused;
- node clicks arrive as ``mailintel://`` console messages and are turned into
  Qt signals (a custom-scheme navigation never reaches Qt).
"""
from __future__ import annotations

from urllib.parse import unquote

from PyQt6.QtCore import QUrl, pyqtSignal
from PyQt6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings

_NODE_PREFIX = "mailintel://node/"
_DESELECT = "mailintel://deselect"


class GraphPage(QWebEnginePage):
    """Web page that blocks navigation and reports graph node clicks."""

    nodeSelected = pyqtSignal(str)
    nodeDeselected = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        settings = self.settings()
        if settings is not None:
            attr = QWebEngineSettings.WebAttribute
            settings.setAttribute(attr.LocalContentCanAccessRemoteUrls, False)
            settings.setAttribute(attr.LocalContentCanAccessFileUrls, False)
            settings.setAttribute(attr.LocalStorageEnabled, False)
            settings.setAttribute(attr.PluginsEnabled, False)
            settings.setAttribute(attr.JavascriptCanOpenWindows, False)

    def javaScriptConsoleMessage(  # noqa: N802 (Qt override)
        self,
        level: QWebEnginePage.JavaScriptConsoleMessageLevel,
        message: str | None,
        line: int,
        source: str | None,
    ) -> None:
        """Graph click bridge: the page logs ``mailintel://`` URLs to the console."""
        if not message:
            return
        if message.startswith(_NODE_PREFIX):
            self.nodeSelected.emit(unquote(message[len(_NODE_PREFIX):]))
        elif message.startswith(_DESELECT):
            self.nodeDeselected.emit()

    def acceptNavigationRequest(  # noqa: N802 (Qt override)
        self, url: QUrl, nav_type: QWebEnginePage.NavigationType, is_main_frame: bool
    ) -> bool:
        # setHtml() content loads as a data: URL; refuse everything else.
        return url.scheme() in ("data", "about", "")

    def createWindow(self, _type):  # noqa: N802 (Qt override)
        return None
