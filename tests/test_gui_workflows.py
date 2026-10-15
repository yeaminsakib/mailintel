"""
tests/test_gui_workflows.py
Automated PyQt6 GUI tests using pytest-qt for MailIntel Phase 5 verification.

Verifies:
1. Dashboard window opens cleanly.
2. KPI cards start in an EMPTY state (0) before any scan (no fake/mock data).
3. Scanning fixtures folder fills the IOC table and updates KPI cards from DB.
4. UI responsiveness: progress bar and worker cancellation.
5. Search bar filter dynamically filters table rows.
6. Cases, Graph, Intel, and Config pages contain no mock text.
7. Config "Test API key" button executes provider test_connectivity with real/invalid keys.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

from app.dashboard import DashboardWindow
from app.workers import ScanWorker
from core.enrichment.abuseipdb import AbuseIPDBProvider
from core.storage.database import Database


@pytest.fixture
def empty_db(tmp_path: Path) -> Path:
    """Create a completely empty SQLite database."""
    db_file = tmp_path / "empty_gui.db"
    db = Database(db_file)
    db.close()
    return db_file


def test_gui_window_opens_and_empty_state_kpis(qapp, qtbot, empty_db):
    """Verify window opens cleanly and KPI cards display EMPTY state (0), not fake numbers."""
    window = DashboardWindow(db_path=empty_db)
    qtbot.addWidget(window)

    # 1. Verify window properties
    assert "MailIntel" in window.windowTitle()
    assert window.ioc_table.rowCount() == 0

    # 2. Verify KPI cards show genuine empty counts
    assert window.kpi_cards["total_emails"].text() == "0"
    assert window.kpi_cards["unique_iocs"].text() == "0"
    assert window.kpi_cards["high_risk"].text() == "0"
    assert window.kpi_cards["active_cases"].text() == "0"


def test_gui_scan_fixtures_and_populate_table(qapp, qtbot, empty_db):
    """Simulate Select Folder & Analyze on tests/fixtures and verify real data in UI."""
    window = DashboardWindow(db_path=empty_db)
    qtbot.addWidget(window)

    fixtures_dir = str(Path("tests/fixtures").resolve())

    # Create worker as main.py does
    worker = ScanWorker(fixtures_dir, db_path=str(empty_db))
    window.show_scan_progress()
    assert not window.progress_frame.isHidden()
    assert window.analyze_button.isEnabled() is False

    # Connect progress and finished
    worker.progress.connect(window.update_scan_progress)
    worker.finished.connect(window.hide_scan_progress)

    # Run scan
    worker.run()

    # Verify progress bar hid and button re-enabled
    assert window.progress_frame.isHidden()
    assert window.analyze_button.isEnabled() is True

    # Verify database populated and table filled
    assert window.ioc_table.rowCount() > 0
    assert int(window.kpi_cards["unique_iocs"].text()) > 0
    assert int(window.kpi_cards["total_emails"].text()) > 0


def test_gui_worker_cancellation(qapp, qtbot, empty_db):
    """Verify worker cancellation maintains responsive UI state."""
    window = DashboardWindow(db_path=empty_db)
    qtbot.addWidget(window)

    fixtures_dir = str(Path("tests/fixtures").resolve())
    worker = ScanWorker(fixtures_dir, db_path=str(empty_db))
    window.show_scan_progress()

    # Cancel immediately
    worker.cancel()
    worker.finished.connect(window.hide_scan_progress)
    worker.run()

    assert window.progress_frame.isHidden()
    assert window.analyze_button.isEnabled() is True


def test_gui_search_filter(qapp, qtbot, empty_db):
    """Verify search input dynamically filters IOC table rows."""
    # Seed data
    db = Database(empty_db)
    i1 = db.upsert_ioc("domain", "paypa1.com")
    i2 = db.upsert_ioc("url", "http://evil-actor.net/landing")
    i3 = db.upsert_ioc("ipv4", "89.160.20.156")
    db.close()

    window = DashboardWindow(db_path=empty_db)
    qtbot.addWidget(window)
    assert window.ioc_table.rowCount() == 3

    # Search for paypa1
    window.search_bar.setText("paypa1")
    assert window.ioc_table.rowCount() == 1
    assert "paypa1.com" in window.ioc_table.item(0, 0).text()

    # Clear search
    window.search_bar.setText("")
    assert window.ioc_table.rowCount() == 3


def test_gui_pages_no_hardcoded_mock_text(qapp, qtbot, empty_db):
    """Verify Cases, Graph, Intel, and Config pages load real data from SQLite/YAML without mock text."""
    window = DashboardWindow(db_path=empty_db)
    qtbot.addWidget(window)

    # Cases page
    window.select_nav_button(1)
    assert window.cases_table.rowCount() == 0
    assert window.case_metric_labels["total"].text() == "0"
    assert window.case_metric_labels["open"].text() == "0"

    # Graph page: empty state before any emails ingested
    window.select_nav_button(2)
    assert "No emails ingested in database yet" in window.graph_stats_label.text()


    # Intel page
    window.select_nav_button(3)
    assert window.mitre_table.rowCount() > 0
    for provider in ("virustotal", "abuseipdb", "otx", "abusech", "rdap"):
        assert provider in window.feed_status_widgets

    # Config page
    window.select_nav_button(4)
    assert len(window.whitelist_editor.toPlainText()) > 0
    assert len(window.weights_editor.toPlainText()) > 0


def test_gui_config_test_api_key_invalid_behavior(qapp, qtbot, empty_db):
    """Verify Config 'Test API key' button executes a real request and handles invalid key with real error."""
    window = DashboardWindow(db_path=empty_db)
    qtbot.addWidget(window)
    window.select_nav_button(4)

    # Patch QMessageBox to capture the real result without popping up blocking dialog
    captured_messages = []
    with patch.object(QMessageBox, "information", side_effect=lambda parent, title, text: captured_messages.append((title, text))):
        with patch("app.dashboard.get_api_key", return_value="DELIBERATELY_INVALID_TEST_KEY_99999"):
            window.handle_test_feed_connectivity("abuseipdb")

    assert len(captured_messages) == 1
    title, text = captured_messages[0]
    assert "ABUSEIPDB Connectivity" in title
    # Should report real authentication / invalid key error from AbuseIPDB API
    assert "✕" in text or "fail" in text.lower() or "401" in text or "429" in text or "error" in text.lower()
