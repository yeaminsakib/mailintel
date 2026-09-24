"""
main.py
MailIntel Application Entry Point
Initializes PyQt6 QApplication, applies a global Threat Intelligence dark theme (QSS),
and launches the main dashboard window.
"""

import sys
from PyQt6.QtWidgets import QApplication, QFileDialog
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt

from ui_dashboard import DashboardWindow
from ioc_engine import parse_eml_folder


DARK_THEME_QSS = """
/* ========================================================================= */
/* MailIntel Threat Intelligence Theme                                       */
/* Deep Navy/Charcoal (#1a1d24), Slate Grey (#64748b), Electric Neon (#00f0ff)*/
/* ========================================================================= */

* {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #e2e8f0;
}

QMainWindow, QWidget#contentContainer {
    background-color: #1a1d24;
}

/* ---------------- LEFT SIDEBAR ---------------- */
QFrame#leftSidebar {
    background-color: #13151b;
    border-right: 1px solid #232834;
}

QLabel#brandLogo {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00f0ff, stop:1 #0284c7);
    color: #0a0e17;
    font-size: 16px;
    font-weight: 900;
    border-radius: 12px;
    letter-spacing: 1px;
}

QFrame#sidebarDivider {
    color: #262c3a;
    background-color: #262c3a;
    max-height: 1px;
}

QPushButton#navButton {
    background-color: transparent;
    color: #94a3b8;
    border: none;
    border-radius: 8px;
    font-size: 10px;
    font-weight: 600;
    padding: 6px;
}

QPushButton#navButton:hover {
    background-color: #1f2533;
    color: #00f0ff;
}

QPushButton#navButtonActive {
    background-color: rgba(0, 240, 255, 0.15);
    color: #00f0ff;
    border: 1px solid rgba(0, 240, 255, 0.6);
    border-radius: 8px;
    font-size: 10px;
    font-weight: 700;
    padding: 6px;
}

QLabel#statusLive {
    color: #10b981;
    font-size: 11px;
    font-weight: 700;
    padding: 4px 8px;
    background-color: rgba(16, 185, 129, 0.12);
    border-radius: 10px;
}

/* ---------------- TOP HEADER ---------------- */
QLabel#headerTitle {
    font-size: 22px;
    font-weight: 800;
    color: #ffffff;
    letter-spacing: 0.5px;
}

QLabel#headerSubtitle {
    font-size: 12px;
    color: #64748b;
    font-weight: 500;
}

QLineEdit#searchBar {
    background-color: #12141a;
    border: 1px solid #2d3545;
    border-radius: 8px;
    padding: 8px 14px;
    font-size: 13px;
    color: #f1f5f9;
}

QLineEdit#searchBar:focus {
    border: 1px solid #00f0ff;
    background-color: #151821;
}

QPushButton#alertBadgeButton {
    background-color: #162432;
    color: #00f0ff;
    border: 1px solid rgba(0, 240, 255, 0.45);
    border-radius: 8px;
    padding: 6px 14px;
    font-size: 12px;
    font-weight: 700;
}

QPushButton#alertBadgeButton:hover {
    background-color: rgba(0, 240, 255, 0.2);
}

/* ---------------- CENTER AREA: CRITICAL IP CARD ---------------- */
QFrame#criticalIpCard {
    background-color: #202530;
    border: 1px solid #2b3242;
    border-left: 4px solid #00f0ff;
    border-radius: 10px;
}

QLabel#cardBadge {
    color: #00f0ff;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.2px;
}

QLabel#criticalIpLabel {
    font-size: 28px;
    font-weight: 900;
    color: #ffffff;
    font-family: "Consolas", "Fira Code", monospace;
}

QLabel#criticalIpMeta {
    font-size: 12px;
    color: #94a3b8;
}

QLabel#criticalScoreValue {
    font-size: 24px;
    font-weight: 900;
    color: #00f0ff;
}

QLabel#criticalScoreLabel {
    font-size: 10px;
    font-weight: 700;
    color: #64748b;
    letter-spacing: 0.8px;
}

/* ---------------- EXTRACTED IOC TABLE ---------------- */
QFrame#tableContainer {
    background-color: #202530;
    border: 1px solid #2a3140;
    border-radius: 10px;
}

QLabel#sectionTitle {
    font-size: 16px;
    font-weight: 700;
    color: #f8fafc;
}

QLabel#recordCountLabel {
    font-size: 12px;
    font-weight: 600;
    color: #94a3b8;
    background-color: #151821;
    border-radius: 6px;
    padding: 3px 10px;
}

QTableWidget#iocTable {
    background-color: #161922;
    border: none;
    border-radius: 8px;
    gridline-color: transparent;
    selection-background-color: rgba(0, 240, 255, 0.2);
    selection-color: #ffffff;
}

/* Dark and borderless table header */
QHeaderView::section {
    background-color: #12141c;
    color: #94a3b8;
    padding: 10px 14px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    border: none;
    border-bottom: 2px solid #232835;
}

QTableWidget#iocTable QTableCornerButton::section {
    background-color: #12141c;
    border: none;
}

QTableWidget#iocTable::item {
    padding: 6px 12px;
    border-bottom: 1px solid #1f2533;
    color: #cbd5e1;
}

QTableWidget#iocTable::item:selected {
    background-color: rgba(0, 240, 255, 0.25);
    color: #ffffff;
}

/* Button below table */
QPushButton#analyzeButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00f0ff, stop:1 #0284c7);
    color: #0a0e17;
    font-size: 14px;
    font-weight: 800;
    letter-spacing: 0.5px;
    border: 1px solid #00f0ff;
    border-radius: 8px;
    padding: 10px 24px;
}

QPushButton#analyzeButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #38bdf8, stop:1 #00f0ff);
    border: 1px solid #38bdf8;
    color: #0a0e17;
}

QPushButton#analyzeButton:pressed {
    background-color: #0369a1;
    border: 1px solid #0369a1;
    color: #ffffff;
}

/* ---------------- RIGHT SIDEBAR ---------------- */
QFrame#rightSidebar {
    background-color: #202530;
    border: 1px solid #2a3140;
    border-radius: 10px;
}

QLabel#rightSidebarTitle {
    font-size: 12px;
    font-weight: 800;
    color: #94a3b8;
    letter-spacing: 1px;
}

QFrame#metricCard {
    background-color: #161922;
    border: 1px solid #242a38;
    border-radius: 8px;
    padding: 12px;
}

QLabel#metricSubTitle {
    font-size: 10px;
    font-weight: 700;
    color: #64748b;
    letter-spacing: 0.8px;
}

QLabel#severityValueLabel {
    font-size: 18px;
    font-weight: 800;
    color: #00f0ff;
}

QLabel#categoryValueLabel {
    font-size: 14px;
    font-weight: 600;
    color: #e2e8f0;
}

QFrame#incidentsCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #102635, stop:1 #141824);
    border: 1px solid rgba(0, 240, 255, 0.45);
    border-radius: 8px;
    padding: 14px;
}

QLabel#incidentsLargeLabel {
    font-size: 22px;
    font-weight: 900;
    color: #00f0ff;
}

QLabel#incidentsSubText {
    font-size: 11px;
    color: #94a3b8;
    line-height: 1.4;
}

QLabel#intelBullet {
    font-size: 11px;
    color: #cbd5e1;
    padding: 2px 0px;
}

/* ---------------- SCROLLBAR STYLING ---------------- */
QScrollBar:vertical {
    border: none;
    background: #161922;
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #334155;
    min-height: 24px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #00f0ff;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""


def handle_select_folder_and_analyze(window: DashboardWindow):
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


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("MailIntel")

    # Set base font
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    # Apply global dark threat intelligence QSS theme
    app.setStyleSheet(DARK_THEME_QSS)

    # Launch dashboard window
    window = DashboardWindow()

    # Wire up the 'Select .eml Folder & Analyze' button functionality in main.py
    try:
        window.analyze_button.clicked.disconnect()
    except (TypeError, RuntimeError):
        pass
    window.analyze_button.clicked.connect(lambda: handle_select_folder_and_analyze(window))

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
