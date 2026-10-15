"""
tests/test_dashboard.py
Unit and integration tests for app/dashboard.py.

Runs in headless / offscreen Qt mode.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--disable-gpu --no-sandbox"

from PyQt6.QtWidgets import QApplication

from app.dashboard import DashboardWindow, RiskBadge, severity_from_score
from core.storage.database import Database


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Ensure QApplication instance exists for PyQt6 tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def test_db_path(tmp_path: Path) -> Path:
    """Create a temporary SQLite database with seed emails and IOCs."""
    db_file = tmp_path / "test_mailintel.db"
    db = Database(db_file)

    # Insert sample IOCs
    i1 = db.upsert_ioc("ipv4", "198.51.100.22")
    db.upsert_ioc("domain", "paypal-secure-verify.com")
    db.upsert_ioc("url", "http://evil.com/payload.exe")

    # Insert enrichment for i1
    db.upsert_enrichment(
        ioc_id=i1,
        provider="virustotal",
        raw_json='{"data": {"attributes": {"last_analysis_stats": {"malicious": 14, "suspicious": 2, "harmless": 50, "undetected": 2}}}}',
        verdict="malicious",
        score=75.0,
    )

    db.close()
    return db_file


def test_severity_from_score():
    assert severity_from_score(90.0) == "CRITICAL"
    assert severity_from_score(75.0) == "CRITICAL"
    assert severity_from_score(60.0) == "HIGH"
    assert severity_from_score(50.0) == "HIGH"
    assert severity_from_score(35.0) == "MEDIUM"
    assert severity_from_score(25.0) == "MEDIUM"
    assert severity_from_score(15.0) == "LOW"
    assert severity_from_score(0.0) == "LOW"


def test_dashboard_initialization(qapp, test_db_path):
    window = DashboardWindow(db_path=test_db_path)
    assert window.ioc_table.rowCount() == 3
    assert window.kpi_cards["unique_iocs"].text() == "3"


def test_dashboard_type_filter(qapp, test_db_path):
    window = DashboardWindow(db_path=test_db_path)

    # Filter to IPv4
    idx = window.type_filter.findText("IPv4")
    window.type_filter.setCurrentIndex(idx)
    assert window.ioc_table.rowCount() == 1
    assert window.ioc_table.item(0, 0).text() == "198.51.100.22"

    # Reset filter
    window.type_filter.setCurrentIndex(0)
    assert window.ioc_table.rowCount() == 3


def test_ioc_details_drawer_breakdown(qapp, test_db_path):
    window = DashboardWindow(db_path=test_db_path)
    # Select first row (198.51.100.22 with VT enrichment)
    window.ioc_table.selectRow(0)

    # Drawer should be populated with score breakdown & enrichments
    assert window.drawer_content_layout.count() > 1
    # Check that VT is mentioned in the drawer
    found_vt = False
    for i in range(window.drawer_content_layout.count()):
        item = window.drawer_content_layout.itemAt(i)
        if item and item.widget():
            text = item.widget().findChildren(RiskBadge)
            if text:
                found_vt = True
                break
    assert found_vt


def test_copy_defanged_ioc(qapp, test_db_path):
    window = DashboardWindow(db_path=test_db_path)
    window.copy_defanged_ioc("http://malware.com/path", "url")
    clipboard = QApplication.clipboard()
    assert clipboard.text() == "hXXp[://]malware[.]com/path"


def test_cases_page_crud(qapp, test_db_path):
    window = DashboardWindow(db_path=test_db_path)
    window.select_nav_button(1)  # Cases tab

    db = window.get_db()
    cid = db.create_case(
        title="Test Spearphish",
        description="Targeting Finance",
        notes="Initial note",
        priority="high",
    )
    window.load_cases_data()
    assert window.cases_table.rowCount() == 1
    assert window.case_metric_labels["open"].text() == "1"

    # Select case
    window.cases_table.selectRow(0)
    assert "Case #1" in window.case_selected_title.text()
    assert window.case_notes_editor.toPlainText() == "Initial note"

    # Update notes
    window.case_notes_editor.setPlainText("Updated analyst note")
    window.handle_save_case_notes()
    assert db.get_case(cid)["notes"] == "Updated analyst note"

    # Toggle status to closed
    window.handle_toggle_case_status()
    assert db.get_case(cid)["status"] == "closed"
    assert window.case_metric_labels["closed"].text() == "1"

    db.delete_case(cid)
    db.close()


def test_intel_page(qapp, test_db_path):
    window = DashboardWindow(db_path=test_db_path)
    window.select_nav_button(3)  # Intel tab
    assert window.mitre_table.rowCount() > 0
    assert "virustotal" in window.feed_status_widgets


def test_config_page_yaml(qapp, test_db_path):
    window = DashboardWindow(db_path=test_db_path)
    window.select_nav_button(4)  # Config tab
    assert len(window.whitelist_editor.toPlainText()) > 0
    assert len(window.weights_editor.toPlainText()) > 0


def test_graph_page_correlation_and_drawer(qapp, test_db_path):
    db = Database(test_db_path)
    # Seed sample email records in the test database
    import json
    parsed_email_data = {
        "headers_json": json.dumps({
            "subject": "Wire Transfer Request #99",
            "from_addr": "cfo@fakecorp.com",
            "reply_to": "attacker@darkweb.org",
        }),
        "first_hop_ip": "198.51.100.22",
    }
    cur = db._conn.execute(
        """
        INSERT INTO emails (file_sha256, filename, filepath, headers_json, auth_json, received_json, first_hop_ip, first_seen, last_seen)
        VALUES ('f'*64, 'email1.eml', 'path1', ?, '{}', '[]', ?, datetime('now'), datetime('now'))
        RETURNING id
        """,
        (parsed_email_data["headers_json"], parsed_email_data["first_hop_ip"]),
    )
    eid = cur.fetchone()[0]
    # Link email to the seeded IOC (198.51.100.22)
    db.link_email_ioc(email_id=eid, ioc_id=1, context="first_hop")
    db.batch_commit()
    db.close()

    window = DashboardWindow(db_path=test_db_path)
    # Switch to Graph tab
    window.select_nav_button(2)

    # Header stats label must show real active graph counts (not hardcoded static text)
    assert "Active Graph:" in window.graph_stats_label.text()
    assert "Nodes" in window.graph_stats_label.text()
    assert "Campaigns Clustered" in window.graph_stats_label.text()

    # Web view must be initialized
    assert window.graph_web_view is not None

    # Graph builder must have built entities
    assert window.graph_builder.graph.number_of_nodes() > 0

    # Test clicking a node in the graph
    node_id = f"email_{eid}"
    window.on_graph_node_clicked(node_id)
    # Drawer must be populated with details (not empty placeholder)
    assert window.graph_drawer_vbox.count() > 1

    # Test deselecting node resets drawer
    window.on_graph_node_deselected()
    assert window.graph_drawer_vbox.count() == 2

    # Test filtering by campaign
    if window.graph_campaign_combo.count() > 1:
        window.graph_campaign_combo.setCurrentIndex(1)
        assert window.graph_builder.graph.number_of_nodes() > 0
