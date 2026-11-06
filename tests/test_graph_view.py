"""
tests/test_graph_view.py
Real Qt WebEngine tests for the hardened graph page (app/graph_view.py).

These start an actual Chromium page (offscreen), so they cover what unit tests
on the generated HTML cannot: that attacker-controlled text is shown as text,
that node clicks reach Qt, and that the page cannot navigate away.
"""
from __future__ import annotations

import pytest
from PyQt6.QtWebEngineWidgets import QWebEngineView

from app.graph_view import GraphPage
from core.correlation.graph_builder import ThreatGraphBuilder

PAYLOAD = "<img src=x onerror=\"document.title='PWNED'\">"


@pytest.fixture(scope="module")
def graph_html() -> str:
    builder = ThreatGraphBuilder()
    builder.build_graph(
        [{"id": 1, "subject": PAYLOAD, "from_addr": f"\"{PAYLOAD}\" <a@evil.com>", "filename": "x.eml"}], {}
    )
    return builder.generate_html()


@pytest.fixture
def loaded_page(qtbot, graph_html):
    view = QWebEngineView()
    page = GraphPage(view)
    view.setPage(page)
    qtbot.addWidget(view)
    with qtbot.waitSignal(page.loadFinished, timeout=30_000) as blocker:
        view.setHtml(graph_html)
    assert blocker.args == [True]
    return view, page


def _js(qtbot, page: GraphPage, script: str):
    """Run *script* in the page and return its (JSON-able) result."""
    result: list = []
    page.runJavaScript(script, result.append)
    qtbot.waitUntil(lambda: bool(result), timeout=10_000)
    return result[0]


def test_payload_is_not_present_unescaped_in_generated_html(graph_html: str) -> None:
    assert PAYLOAD not in graph_html


def test_tooltip_shows_payload_as_text_and_does_not_run_it(qtbot, loaded_page) -> None:
    _view, page = loaded_page
    inner = _js(qtbot, page, "(function(){var t = network.body.nodes['email_1'].options.title;"
                             " return t && t.innerHTML ? t.innerHTML : 'none';})()")
    assert "&lt;img" in inner
    assert "<img" not in inner
    qtbot.wait(500)  # give an injected onerror handler time to fire if it existed
    assert _js(qtbot, page, "document.title") != "PWNED"


def test_node_selection_reaches_qt_as_a_signal(qtbot, loaded_page) -> None:
    _view, page = loaded_page
    with qtbot.waitSignal(page.nodeSelected, timeout=10_000) as blocker:
        page.runJavaScript("network.body.emitter.emit('selectNode', {nodes:['email_1']});")
    assert blocker.args == ["email_1"]


def test_deselect_reaches_qt_as_a_signal(qtbot, loaded_page) -> None:
    _view, page = loaded_page
    with qtbot.waitSignal(page.nodeDeselected, timeout=10_000):
        page.runJavaScript("network.body.emitter.emit('deselectNode', {nodes:[]});")


def test_page_refuses_to_navigate_away(qtbot, loaded_page) -> None:
    view, page = loaded_page
    page.runJavaScript("window.location.href = 'https://example.com/';")
    qtbot.wait(1500)
    assert view.url().scheme() == "data"
    assert "example.com" not in view.url().toString()[:100]
