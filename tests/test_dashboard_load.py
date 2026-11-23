"""
tests/test_dashboard_load.py
Dashboard shows only the mails of the current folder load:
counters for that load, "Clean All", right-click "Delete from this load",
and clicking an indicator opens its mail on the right.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from PyQt6.QtWidgets import QComboBox, QInputDialog, QLabel, QMenu, QPlainTextEdit, QTableWidget

from app.dashboard import NOTHING_LOADED_TEXT, DashboardWindow
from core.storage.database import Database
from core.storage.scan import scan_folder
from core.storage.schema import SCHEMA_VERSION


def _eml(path: Path, *, ip: str, sender: str, to: str, subject: str, url: str, body: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"Received: from relay.example.net ([{ip}]) by mx.corp.com; Mon, 2 Nov 2026 10:00:00 +0000\n"
        f"From: {sender}\nTo: {to}\nSubject: {subject}\nDate: Mon, 2 Nov 2026 10:00:00 +0000\n"
        f"Message-ID: <{subject.replace(' ', '')}@x>\n\n{body or 'Please open'} {url}\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def folders(tmp_path: Path) -> dict[str, Path]:
    a, b = tmp_path / "batch_a", tmp_path / "batch_b"
    _eml(a / "a1.eml", ip="185.220.101.10", sender="x@old-spam.org", to="alice@corp.com",
         subject="Old campaign", url="http://old-spam.org/x")
    _eml(b / "b1.eml", ip="45.33.32.20", sender="y@new-spam.net", to="alice@corp.com",
         subject="New lure one", url="http://new-spam.net/login", body="Verify your account")
    _eml(b / "b2.eml", ip="45.33.32.20", sender="z@new-spam.net", to="bob@corp.com",
         subject="New lure two", url="http://new-spam.net/pay")
    return {"a": a, "b": b, "db": tmp_path / "dash.db"}


def _scan(window: DashboardWindow, folder: Path) -> dict:
    """Scan like the GUI does and hand the result to the Dashboard."""
    db = Database(window.db_path)
    try:
        result = {**scan_folder(folder, db).to_dict(), "iocs_found": 0}
    finally:
        db.close()
    window.hide_scan_progress(result)
    return result


def _table_values(window: DashboardWindow) -> set[str]:
    return {window.ioc_table.item(r, 0).text() for r in range(window.ioc_table.rowCount())}


def _all_types_including_urls(window: DashboardWindow) -> None:
    window.type_filter.setCurrentIndex(window.type_filter.findText("URL"))


@pytest.fixture
def window(folders, qtbot) -> DashboardWindow:
    w = DashboardWindow(db_path=folders["db"])
    qtbot.addWidget(w)
    return w


# ---------------------------------------------------------------------------
# Storage: loads
# ---------------------------------------------------------------------------

class TestLoadStorage:
    def test_scan_records_a_load_with_new_and_duplicate_mails(self, folders) -> None:
        db = Database(folders["db"])
        first = scan_folder(folders["b"], db)
        again = scan_folder(folders["b"], db)                 # rescan: duplicates
        assert first.load_id and again.load_id and again.load_id != first.load_id
        assert db.get_load_email_count(first.load_id) == 2
        assert db.get_load_email_count(again.load_id) == 2   # duplicates still belong to the new load
        loads = db.get_loads()
        assert [load["id"] for load in loads] == [again.load_id, first.load_id]
        assert loads[0]["emails_duplicate"] == 2 and loads[0]["email_count"] == 2
        db.close()

    def test_no_load_when_nothing_was_read(self, tmp_path: Path) -> None:
        (tmp_path / "empty.eml").write_bytes(b"")
        db = Database(":memory:")
        assert scan_folder(tmp_path, db).load_id is None
        assert db.get_loads() == []

    def test_load_iocs_are_only_those_of_the_load(self, folders) -> None:
        db = Database(folders["db"])
        a = scan_folder(folders["a"], db).load_id
        b = scan_folder(folders["b"], db).load_id
        values_b = {r["value"] for r in db.get_load_iocs(b)}
        assert "185.220.101.10" not in values_b and "45.33.32.20" in values_b
        ip = next(r for r in db.get_load_iocs(b) if r["value"] == "45.33.32.20")
        assert ip["load_frequency"] == 2                        # in both mails of load b
        assert db.count_load_iocs(b) == len(values_b)
        assert db.count_load_iocs(b, exclude_ids={ip["id"]}) == len(values_b) - 1
        assert [r["value"] for r in db.get_load_iocs(b, ioc_type="ipv4")] == ["45.33.32.20"]
        assert {r["value"] for r in db.get_load_iocs(b, search="pay")} == {"http://new-spam.net/pay"}
        assert {m["subject"] for m in db.get_load_emails_for_ioc(b, ip["id"])} == {"New lure one", "New lure two"}
        assert db.get_load_emails_for_ioc(a, ip["id"]) == []
        db.close()

    def test_old_database_gets_the_load_tables(self, tmp_path: Path) -> None:
        path = tmp_path / "v2.db"
        db = Database(path)
        db._conn.executescript("DROP TABLE load_emails; DROP TABLE loads; PRAGMA user_version = 2;")
        db.close()
        db = Database(path)
        assert db.schema_version() == SCHEMA_VERSION == 3
        assert db.get_loads() == []
        db.close()


# ---------------------------------------------------------------------------
# Dashboard: only the loaded mails
# ---------------------------------------------------------------------------

class TestCurrentLoad:
    def test_starts_empty(self, window) -> None:
        assert window.ioc_table.rowCount() == 0
        assert window.load_info_label.text() == NOTHING_LOADED_TEXT
        assert not window.clean_all_btn.isEnabled()

    def test_shows_only_the_latest_load(self, window, folders) -> None:
        _scan(window, folders["a"])
        assert "185.220.101.10" in _table_values(window)
        _scan(window, folders["b"])
        values = _table_values(window)
        assert "45.33.32.20" in values
        assert "185.220.101.10" not in values and "x@old-spam.org" not in values   # previous load hidden
        assert window.kpi_cards["total_emails"].text() == "2"
        assert "2 mail(s) from" in window.load_info_label.text()
        assert window.clean_all_btn.isEnabled()

    def test_counters_cover_the_whole_load(self, window, folders) -> None:
        _scan(window, folders["b"])
        db = Database(window.db_path)
        expected = db.count_load_iocs(window.current_load_id)
        ip_id = next(r["id"] for r in db.get_load_iocs(window.current_load_id) if r["value"] == "45.33.32.20")
        db.upsert_enrichment(ioc_id=ip_id, provider="virustotal", verdict="malicious", score=100.0, raw_json=json.dumps(
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 60, "suspicious": 0, "harmless": 0,
                                                             "undetected": 0}}}}))
        db.upsert_enrichment(ioc_id=ip_id, provider="abuseipdb", verdict="malicious", score=100.0,
                             raw_json=json.dumps({"data": {"abuseConfidenceScore": 100}}))
        db.close()
        window.show_load(window.current_load_id)              # re-score
        assert window.kpi_cards["unique_iocs"].text() == str(expected)     # URLs included in the count
        assert window.kpi_cards["high_risk"].text() == "1"

    def test_rescan_of_the_same_folder_shows_it_again(self, window, folders) -> None:
        _scan(window, folders["b"])
        window.clean_dashboard()
        _scan(window, folders["b"])                             # all duplicates now
        assert window.kpi_cards["total_emails"].text() == "2"
        assert "45.33.32.20" in _table_values(window)
        assert "0 new, 2 already stored" in window.load_info_label.text()

    def test_active_cases_counts_all_open_cases(self, window, folders) -> None:
        db = Database(window.db_path)
        db.create_case(title="One", description="", notes="", priority="low")
        db.create_case(title="Two", description="", notes="", priority="low")
        db.close()
        _scan(window, folders["b"])
        assert window.kpi_cards["active_cases"].text() == "2"
        window.clean_dashboard()
        assert window.kpi_cards["active_cases"].text() == "2"


class TestCleanAll:
    def test_clears_the_dashboard_but_keeps_stored_data(self, window, folders) -> None:
        _scan(window, folders["b"])
        window.clean_dashboard()
        assert window.ioc_table.rowCount() == 0
        assert [window.kpi_cards[k].text() for k in ("total_emails", "unique_iocs", "high_risk")] == ["0", "0", "0"]
        assert window.load_info_label.text() == NOTHING_LOADED_TEXT
        assert not window.clean_all_btn.isEnabled() and window.add_to_case_btn.isHidden()
        db = Database(window.db_path)
        assert db.get_email_count() == 2 and db.get_ioc_count() > 0       # nothing deleted
        db.close()


class TestRemoveFromLoad:
    def _ip_row(self, window) -> tuple[int, dict]:
        for r in range(window.ioc_table.rowCount()):
            data = window.ioc_table.item(r, 0).data(0x0100)              # Qt.ItemDataRole.UserRole
            if data["value"] == "45.33.32.20":
                return r, data
        raise AssertionError("IP row not found")

    def test_delete_hides_one_indicator_and_updates_counters(self, window, folders) -> None:
        _scan(window, folders["b"])
        before = int(window.kpi_cards["unique_iocs"].text())
        _row, data = self._ip_row(window)
        window.remove_ioc_from_load(data["id"], data["value"])
        assert "45.33.32.20" not in _table_values(window)
        assert int(window.kpi_cards["unique_iocs"].text()) == before - 1
        assert "(1 removed)" in window.record_count_label.text()
        db = Database(window.db_path)
        assert any(i["value"] == "45.33.32.20" for i in db.get_all_iocs())   # still stored
        db.close()
        window.restore_removed_iocs()
        assert "45.33.32.20" in _table_values(window)
        assert int(window.kpi_cards["unique_iocs"].text()) == before

    def test_delete_key_removes_the_selected_row(self, window, folders) -> None:
        _scan(window, folders["b"])
        row, _data = self._ip_row(window)
        window.ioc_table.selectRow(row)
        window.delete_selected_ioc()
        assert "45.33.32.20" not in _table_values(window)

    def test_right_click_menu_offers_delete(self, window, folders, monkeypatch) -> None:
        _scan(window, folders["b"])
        row, _data = self._ip_row(window)
        seen: list[str] = []

        def fake_exec(menu, *args):
            seen.extend(a.text() for a in menu.actions())
            return next(a for a in menu.actions() if a.text().startswith("🗑"))

        monkeypatch.setattr(QMenu, "exec", fake_exec)
        pos = window.ioc_table.visualItemRect(window.ioc_table.item(row, 0)).center()
        window.on_ioc_context_menu(pos)
        assert any("Delete from this load" in t for t in seen)
        assert "45.33.32.20" not in _table_values(window)

    def test_new_load_forgets_removed_indicators(self, window, folders) -> None:
        _scan(window, folders["b"])
        _row, data = self._ip_row(window)
        window.remove_ioc_from_load(data["id"], data["value"])
        _scan(window, folders["b"])
        assert "45.33.32.20" in _table_values(window)


# ---------------------------------------------------------------------------
# Mail view on the right
# ---------------------------------------------------------------------------

def _drawer_texts(window: DashboardWindow) -> str:
    return " | ".join(lbl.text() for lbl in window.drawer_content.findChildren(QLabel))


class TestMailView:
    def test_clicking_an_indicator_shows_its_mail(self, window, folders) -> None:
        _scan(window, folders["b"])
        _all_types_including_urls(window)
        row = next(r for r in range(window.ioc_table.rowCount())
                   if window.ioc_table.item(r, 0).text() == "http://new-spam.net/login")
        window.ioc_table.selectRow(row)
        texts = _drawer_texts(window)
        assert "New lure one" in texts and "y@new-spam.net" in texts and "alice@corp.com" in texts
        assert "WHY THIS SCORE" in texts and "INDICATORS IN THIS MAIL" in texts
        bodies = window.drawer_content.findChildren(QPlainTextEdit)
        assert bodies and "Verify your account" in bodies[-1].toPlainText()
        tables = window.drawer_content.findChildren(QTableWidget)
        ioc_table = next(t for t in tables if t.horizontalHeaderItem(1).text() == "Value")
        selected = ioc_table.selectionModel().selectedRows()
        assert selected and ioc_table.item(selected[0].row(), 1).text() == "http://new-spam.net/login"

    def test_indicator_in_several_mails_offers_a_choice(self, window, folders) -> None:
        _scan(window, folders["b"])
        row = next(r for r in range(window.ioc_table.rowCount())
                   if window.ioc_table.item(r, 0).text() == "45.33.32.20")
        window.ioc_table.selectRow(row)
        assert "FOUND IN 2 MAIL(S) OF THIS LOAD" in _drawer_texts(window)
        selector = window.mail_selector
        assert isinstance(selector, QComboBox) and selector.count() == 2 and not selector.isHidden()
        first_subject = "New lure two"                          # newest first
        assert first_subject in _drawer_texts(window)
        selector.setCurrentIndex(1)
        assert "New lure one" in " | ".join(lbl.text() for lbl in window.mail_body_widget.findChildren(QLabel))

    def test_mail_text_is_shown_as_plain_text(self, window, tmp_path) -> None:
        folder = tmp_path / "evil"
        _eml(folder / "x.eml", ip="185.220.101.77", sender="a@b.org", to="c@d.org",
             subject="<b>bold?</b> <img src=x>", url="http://e.org/")
        _scan(window, folder)
        window.ioc_table.selectRow(0)
        subject = next(lbl for lbl in window.drawer_content.findChildren(QLabel) if "<b>bold?</b>" in lbl.text())
        assert subject.textFormat().name == "PlainText"


# ---------------------------------------------------------------------------
# Small things
# ---------------------------------------------------------------------------

def test_analyze_button_shows_the_ampersand(window) -> None:
    assert window.analyze_button.text() == "Select .eml Folder && Analyze"     # '&&' displays as '&'
    window.show_scan_progress()
    window.hide_scan_progress(None)
    assert window.analyze_button.text() == "Select .eml Folder && Analyze"


def test_add_to_case_links_only_the_loaded_mails(window, folders, monkeypatch) -> None:
    db = Database(window.db_path)
    case_id = db.create_case(title="Phish", description="", notes="", priority="high")
    db.close()
    _scan(window, folders["a"])
    _scan(window, folders["b"])
    monkeypatch.setattr(QInputDialog, "getItem", staticmethod(lambda *a, **k: (f"#{case_id}: Phish (open)", True)))
    window.handle_add_scan_to_case()
    db = Database(window.db_path)
    assert {e["subject"] for e in db.get_emails_for_case(case_id)} == {"New lure one", "New lure two"}
    db.close()
