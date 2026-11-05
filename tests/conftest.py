"""
tests/conftest.py
Global pytest configuration for MailIntel.
Ensures QtWebEngineWidgets is initialized before any QApplication is instantiated.
"""
import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--disable-gpu --no-sandbox --disable-software-rasterizer"

try:
    from PyQt6.QtCore import QCoreApplication, Qt
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
    from PyQt6.QtWebEngineWidgets import QWebEngineView  # noqa: F401
except ImportError:
    pass


import sys  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_default_database(tmp_path, monkeypatch):
    """Never let a test open the real ``mailintel.db`` in the project root.

    Code paths that fall back to the default database (``Database()``, the CLI
    without ``--db``, ``DashboardWindow()`` without ``db_path``) are redirected
    to a throw-away file inside the test's own temp directory.
    """
    safe = tmp_path / "default_mailintel.db"
    monkeypatch.setattr("core.storage.database._DEFAULT_DB_PATH", safe)
    dashboard = sys.modules.get("app.dashboard")
    if dashboard is not None:
        monkeypatch.setattr(dashboard, "_DB_PATH", safe)
