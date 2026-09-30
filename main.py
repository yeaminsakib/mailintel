"""
main.py
MailIntel Application Entry Point
Initializes PyQt6 QApplication, applies a global Threat Intelligence dark theme (QSS),
and launches the main dashboard window.
"""

import sys
from PyQt6.QtWidgets import QApplication, QFileDialog
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

from app.theme import DARK_THEME_QSS
from app.dashboard import DashboardWindow
from core.ioc.engine import parse_eml_folder


def handle_select_folder_and_analyze(window: DashboardWindow) -> None:
    """
    Controller function for 'Select .eml Folder & Analyze'.
    Opens QFileDialog, calls parse_eml_folder() to extract per-email IOC events,
    and populates the QTableWidget on the Dash page with one row per .eml file.
    The case log CSV is written automatically by the backend.
    """
    folder_path = QFileDialog.getExistingDirectory(
        window,
        "Select .eml Folder for DFIR Threat Analysis",
        "",
        QFileDialog.Option.ShowDirsOnly
    )

    if folder_path:
        result     = parse_eml_folder(folder_path)
        email_logs = result.get("email_logs", [])
        window.populate_table_with_iocs(email_logs, folder_path=folder_path)


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

    # Wire up the 'Select .eml Folder & Analyze' button (single controller)
    window.analyze_button.clicked.connect(lambda: handle_select_folder_and_analyze(window))

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
