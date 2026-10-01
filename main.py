"""
main.py
MailIntel Application Entry Point
Initializes PyQt6 QApplication, applies a global Threat Intelligence dark theme (QSS),
and launches the main dashboard window.

All scanning runs on a background QThread (ScanWorker) so the UI never blocks.
The database is the source of truth: after a scan completes the table and KPIs
are refreshed from SQLite, not from in-memory dicts.
"""

import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox
from PyQt6.QtGui import QFont

from app.theme import DARK_THEME_QSS
from app.dashboard import DashboardWindow
from app.workers import ScanWorker
from core.storage.database import Database


# Resolve DB path relative to this file (project root)
_DB_PATH: Path = Path(__file__).resolve().parent / "mailintel.db"


def handle_select_folder_and_analyze(window: DashboardWindow) -> None:
    """Controller for 'Select .eml Folder & Analyze'.

    Opens a QFileDialog, spins up a ScanWorker thread, wires
    progress/finished/error signals to the dashboard, and starts
    the background scan.  The UI remains responsive throughout.
    """
    folder_path = QFileDialog.getExistingDirectory(
        window,
        "Select .eml Folder for DFIR Threat Analysis",
        "",
        QFileDialog.Option.ShowDirsOnly,
    )

    if not folder_path:
        return

    # Show progress UI
    window.show_scan_progress()

    # Create the worker (parented to window so Qt handles cleanup)
    worker = ScanWorker(
        folder_path=folder_path,
        db_path=str(_DB_PATH),
        parent=window,
    )

    # Wire cancel button
    window.cancel_button.clicked.connect(worker.cancel)

    # Progress → update bar
    worker.progress.connect(window.update_scan_progress)

    # Finished → refresh table from DB, hide progress
    def on_finished(result: dict) -> None:
        window.hide_scan_progress(result)

        # Refresh table and KPIs from the database (source of truth)
        db = Database(str(_DB_PATH))
        window.populate_table_from_db(db)
        window.update_kpi_from_db(db)
        db.close()

        # Stash the worker ref so it isn't GC'd before it's truly done
        window._scan_worker = None  # type: ignore[attr-defined]

    # Error → show message box and hide progress
    def on_error(msg: str) -> None:
        window.hide_scan_progress()
        QMessageBox.critical(window, "Scan Error", msg)
        window._scan_worker = None  # type: ignore[attr-defined]

    worker.finished.connect(on_finished)
    worker.error.connect(on_error)

    # Keep a reference so the thread isn't garbage-collected
    window._scan_worker = worker  # type: ignore[attr-defined]
    worker.start()


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("MailIntel")

    # Set base font
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    # Apply global dark threat intelligence QSS theme
    app.setStyleSheet(DARK_THEME_QSS)

    # Launch dashboard window
    window = DashboardWindow()

    # On startup, populate table and KPIs from existing DB data (if any)
    db = Database(str(_DB_PATH))
    window.populate_table_from_db(db)
    window.update_kpi_from_db(db)
    db.close()

    # Wire up the 'Select .eml Folder & Analyze' button
    window.analyze_button.clicked.connect(
        lambda: handle_select_folder_and_analyze(window)
    )

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
