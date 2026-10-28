"""
app/dashboard.py
MailIntel - Threat Intelligence & DFIR Dashboard

Wires the PyQt6 dashboard to real SQLite database data and core intelligence engines:
- Dash page: KPI cards from SQLite, IOC table with type filter, severity badges
  from risk score, details drawer showing score breakdown and enrichment results,
  and right-click "copy defanged IOC" and "re-enrich".
- Cases page: Real cases from SQLite with create, close, and analyst notes.
- Intel page: Real enrichment status (VirusTotal, AbuseIPDB, OTX, URLhaus, RDAP)
  and real ATT&CK techniques seen across the corpus.
- Config page: API keys management via keyring, live whitelist editor, and
  scoring weights editor.
"""
from __future__ import annotations

import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml
from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtGui import QColor, QCursor, QFont
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.workers import EnrichWorker
from core.correlation import (
    ENTITY_COLORS,
    Campaign,
    CampaignClusterer,
    ThreatGraphBuilder,
)
from core.enrichment.abusech import AbuseCHProvider
from core.enrichment.abuseipdb import AbuseIPDBProvider
from core.enrichment.keys import get_api_key, set_api_key
from core.enrichment.otx import OTXProvider
from core.enrichment.rdap import RDAPProvider
from core.enrichment.virustotal import VirusTotalProvider
from core.export import MispExporter, ReportExporter, StixExporter
from core.ioc.defang import defang
from core.mapping.mitre_attack import MitreMapper
from core.scoring.risk_score import RiskScorer
from core.storage.database import Database

logger = logging.getLogger(__name__)

# Paths resolved relative to project root
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
_DB_PATH: Path = _PROJECT_ROOT / "mailintel.db"
_DATA_DIR: Path = _PROJECT_ROOT / "data"
_WHITELIST_PATH: Path = _DATA_DIR / "whitelist.yaml"
_WEIGHTS_PATH: Path = _DATA_DIR / "scoring_weights.yaml"


def severity_from_score(score: float) -> str:
    """Map a 0-100 risk score to a qualitative severity badge."""
    if score >= 75.0:
        return "CRITICAL"
    if score >= 50.0:
        return "HIGH"
    if score >= 25.0:
        return "MEDIUM"
    return "LOW"


# =============================================================================
# REUSABLE UI BADGES & WIDGETS
# =============================================================================

class RiskBadge(QLabel):
    """Custom styled badge for IOC risk levels in dark DFIR theme."""

    def __init__(self, risk_level: str = "LOW", parent: QWidget | None = None) -> None:
        cleaned_risk = (risk_level or "LOW").upper()
        super().__init__(cleaned_risk, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(24)

        color_map = {
            "CRITICAL": ("#ef4444", "rgba(239, 68, 68, 0.15)", "rgba(239, 68, 68, 0.55)"),
            "HIGH":     ("#f97316", "rgba(249, 115, 22, 0.15)", "rgba(249, 115, 22, 0.55)"),
            "MEDIUM":   ("#eab308", "rgba(234, 179, 8, 0.15)", "rgba(234, 179, 8, 0.55)"),
            "LOW":      ("#10b981", "rgba(16, 185, 129, 0.15)", "rgba(16, 185, 129, 0.55)"),
        }
        text_col, bg_col, border_col = color_map.get(
            cleaned_risk, ("#38bdf8", "rgba(56, 189, 248, 0.15)", "rgba(56, 189, 248, 0.55)")
        )

        self.setStyleSheet(f"""
            QLabel {{
                background-color: {bg_col};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 5px;
                font-weight: 800;
                font-size: 10px;
                padding: 2px 8px;
                letter-spacing: 0.6px;
            }}
        """)


class CreateCaseDialog(QDialog):
    """Modal dialog to create a new investigation case in SQLite."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Create Investigation Case")
        self.setFixedSize(480, 360)
        self.setStyleSheet("background-color: #1a1d24; color: #e2e8f0;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        form = QFormLayout()
        form.setSpacing(10)

        self.title_input = QLineEdit()
        self.title_input.setObjectName("searchBar")
        self.title_input.setPlaceholderText("e.g. Spear-phishing Campaign #2026-04")
        form.addRow("Case Title*:", self.title_input)

        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["low", "medium", "high", "critical"])
        self.priority_combo.setCurrentText("high")
        form.addRow("Priority:", self.priority_combo)

        self.desc_input = QLineEdit()
        self.desc_input.setObjectName("searchBar")
        self.desc_input.setPlaceholderText("Brief scope or targeted department")
        form.addRow("Description:", self.desc_input)

        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Initial analyst notes, indicators or hypothesis...")
        self.notes_input.setFixedHeight(100)
        form.addRow("Initial Notes:", self.notes_input)

        layout.addLayout(form)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def validate_and_accept(self) -> None:
        if not self.title_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Case title is required.")
            return
        self.accept()

    def get_data(self) -> dict[str, str]:
        return {
            "title": self.title_input.text().strip(),
            "priority": self.priority_combo.currentText(),
            "description": self.desc_input.text().strip(),
            "notes": self.notes_input.toPlainText().strip(),
        }


# =============================================================================
# MAIN DASHBOARD WINDOW
# =============================================================================

class DashboardWindow(QMainWindow):
    """Main MailIntel Threat Intelligence Dashboard."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        super().__init__()
        self.setWindowTitle("MailIntel - Email DFIR Threat Intelligence Dashboard")
        self.resize(1380, 860)
        self.setMinimumSize(1100, 720)

        self.db_path = str(db_path or _DB_PATH)
        self.scorer = RiskScorer()
        self.mitre_mapper = MitreMapper()
        self.clusterer = CampaignClusterer(risk_scorer=self.scorer)
        self.graph_builder = ThreatGraphBuilder(risk_scorer=self.scorer)
        self._current_campaigns: list[Campaign] = []

        # Active worker references
        self._enrich_workers: list[EnrichWorker] = []

        # Central widget and root layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Build Sidebar and Stacked Pages
        self.init_left_sidebar()
        self.init_stacked_area()

        # Connect initial selection (Index 0: Dash)
        self.select_nav_button(0)

        # Do NOT pre-load DB data on startup.
        # Data will only show after the user selects an .eml folder and scans.
        self._clear_dash_to_empty_state()

    # -------------------------------------------------------------------------
    # DATABASE HELPER
    # -------------------------------------------------------------------------
    def get_db(self) -> Database:
        """Create a fresh Database connection instance."""
        return Database(self.db_path)

    # =========================================================================
    # LEFT SIDEBAR & NAVIGATION SYSTEM
    # =========================================================================
    def init_left_sidebar(self) -> None:
        self.sidebar_frame = QFrame()
        self.sidebar_frame.setObjectName("leftSidebar")
        self.sidebar_frame.setFixedWidth(82)
        self.sidebar_frame.setStyleSheet("""
            QFrame#leftSidebar {
                background-color: #1a1d24;
                border-right: 1px solid #282f3d;
            }
        """)

        sidebar_layout = QVBoxLayout(self.sidebar_frame)
        sidebar_layout.setContentsMargins(10, 20, 10, 20)
        sidebar_layout.setSpacing(14)
        sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)

        # Brand / Logo Icon
        logo_label = QLabel("MI")
        logo_label.setObjectName("brandLogo")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setFixedSize(50, 50)
        sidebar_layout.addWidget(logo_label)

        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setFixedHeight(1)
        divider.setStyleSheet("background-color: #2a3242; border: none;")
        sidebar_layout.addWidget(divider)

        # 5 Navigation tool-buttons: Dash, Cases, Graph, Intel, Config
        nav_definitions = [
            ("⚡", "Dash", 0),
            ("📁", "Cases", 1),
            ("🌐", "Graph", 2),
            ("🛡️", "Intel", 3),
            ("⚙️", "Config", 4),
        ]

        self.nav_buttons: list[QPushButton] = []
        for icon, label, idx in nav_definitions:
            btn = QPushButton(f"{icon}\n{label}")
            btn.setFixedSize(62, 58)
            btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(lambda _, index=idx: self.select_nav_button(index))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        status_dot = QLabel("● Live")
        status_dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_dot.setStyleSheet("""
            color: #10b981;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 8px;
            background-color: rgba(16, 185, 129, 0.12);
            border-radius: 10px;
        """)
        sidebar_layout.addWidget(status_dot)

        self.main_layout.addWidget(self.sidebar_frame)

    def select_nav_button(self, selected_index: int) -> None:
        self.stacked_widget.setCurrentIndex(selected_index)

        active_style = """
            QPushButton {
                background-color: rgba(0, 210, 255, 0.14);
                color: #00f0ff;
                border: 1px solid #00d2ff;
                border-radius: 8px;
                font-size: 11px;
                font-weight: 700;
                padding: 6px;
            }
        """
        inactive_style = """
            QPushButton {
                background-color: transparent;
                color: #94a3b8;
                border: 1px solid transparent;
                border-radius: 8px;
                font-size: 10px;
                font-weight: 600;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #222836;
                color: #38bdf8;
                border: 1px solid rgba(56, 189, 248, 0.35);
            }
        """

        for idx, btn in enumerate(self.nav_buttons):
            btn.setStyleSheet(active_style if idx == selected_index else inactive_style)

        # Trigger page-specific data refresh on tab switch
        if selected_index == 0:
            self.load_dash_data()
        elif selected_index == 1:
            self.load_cases_data()
        elif selected_index == 2:
            self.load_graph_data()
        elif selected_index == 3:
            self.load_intel_data()
        elif selected_index == 4:
            self.load_config_data()

    # =========================================================================
    # CENTER STACKED WIDGET & PAGES
    # =========================================================================
    def init_stacked_area(self) -> None:
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("mainStackedWidget")

        self.dash_page = self.create_dashboard_page()
        self.stacked_widget.addWidget(self.dash_page)

        self.cases_page = self.create_cases_page()
        self.stacked_widget.addWidget(self.cases_page)

        self.graph_page = self.create_graph_page()
        self.stacked_widget.addWidget(self.graph_page)

        self.intel_page = self.create_intel_page()
        self.stacked_widget.addWidget(self.intel_page)

        self.config_page = self.create_config_page()
        self.stacked_widget.addWidget(self.config_page)

        self.main_layout.addWidget(self.stacked_widget)

    # -------------------------------------------------------------------------
    # PAGE 0: DASHBOARD PAGE
    # -------------------------------------------------------------------------
    def create_dashboard_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("contentContainer")

        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # Header Row: Title & Action Controls
        header_row = QHBoxLayout()
        header_row.setSpacing(14)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.header_title = QLabel("Indicator of Compromise Intelligence")
        self.header_title.setObjectName("headerTitle")
        header_sub = QLabel("Real Forensics Database & Explainable Risk Scoring Engine")
        header_sub.setObjectName("headerSubtitle")
        title_box.addWidget(self.header_title)
        title_box.addWidget(header_sub)
        header_row.addLayout(title_box)

        header_row.addStretch()

        # Type Filter Dropdown
        self.type_filter = QComboBox()
        self.type_filter.setFixedHeight(38)
        self.type_filter.setMinimumWidth(150)
        self.type_filter.addItems([
            "All Types", "IPv4", "IPv6", "Domain", "URL", "Email",
            "Hash MD5", "Hash SHA1", "Hash SHA256"
        ])
        self.type_filter.currentIndexChanged.connect(self.on_ioc_filter_changed)
        header_row.addWidget(self.type_filter)

        # Search Bar
        self.search_bar = QLineEdit()
        self.search_bar.setObjectName("searchBar")
        self.search_bar.setPlaceholderText("Search IOC value, IP, domain, hash...")
        self.search_bar.setFixedWidth(280)
        self.search_bar.setFixedHeight(38)
        self.search_bar.textChanged.connect(self.on_ioc_filter_changed)
        header_row.addWidget(self.search_bar)

        layout.addLayout(header_row)

        # 1. TOP ROW: 4 KPI SUMMARY CARDS
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(14)
        self.kpi_cards: dict[str, QLabel] = {}

        kpi_defs = [
            ("total_emails", "TOTAL EMAILS", "0", "Corpus parsed files in DB", "#00f0ff"),
            ("unique_iocs", "UNIQUE IOCS", "0", "Extracted indicators", "#38bdf8"),
            ("high_risk", "HIGH / CRITICAL RISK", "0", "Threat score >= 50", "#ef4444"),
            ("active_cases", "ACTIVE CASES", "0", "Open forensic dossiers", "#f59e0b"),
        ]

        for key, title, def_val, subtext, accent in kpi_defs:
            card = QFrame()
            card.setObjectName("kpiCard")
            card.setStyleSheet(f"""
                QFrame#kpiCard {{
                    background-color: #202530;
                    border: 1px solid #2a3242;
                    border-top: 3px solid {accent};
                    border-radius: 8px;
                }}
            """)
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 12, 14, 12)
            cl.setSpacing(4)

            t_lbl = QLabel(title)
            t_lbl.setObjectName("metricSubTitle")
            v_lbl = QLabel(def_val)
            v_lbl.setStyleSheet(f"""
                font-size: 22px; font-weight: 800; color: {accent};
                font-family: 'Consolas', 'Segoe UI', monospace;
            """)
            s_lbl = QLabel(subtext)
            s_lbl.setStyleSheet("font-size: 11px; color: #64748b; font-weight: 500;")

            cl.addWidget(t_lbl)
            cl.addWidget(v_lbl)
            cl.addWidget(s_lbl)
            kpi_row.addWidget(card, 1)
            self.kpi_cards[key] = v_lbl

        layout.addLayout(kpi_row)

        # 2. MAIN SPLITTER: IOC TABLE (LEFT) + DETAILS DRAWER (RIGHT)
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setChildrenCollapsible(False)

        # Left Container: IOC Table
        table_container = QFrame()
        table_container.setObjectName("tableContainer")
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(16, 14, 16, 14)
        table_layout.setSpacing(10)

        tbl_header_box = QHBoxLayout()
        tbl_title = QLabel("Extracted Indicators of Compromise")
        tbl_title.setObjectName("sectionTitle")
        self.record_count_label = QLabel("No data — select an .eml folder to begin analysis")
        self.record_count_label.setObjectName("recordCountLabel")

        tbl_header_box.addWidget(tbl_title)
        tbl_header_box.addStretch()
        tbl_header_box.addWidget(self.record_count_label)
        table_layout.addLayout(tbl_header_box)

        self.ioc_table = QTableWidget()
        self.ioc_table.setObjectName("iocTable")
        self.ioc_table.setColumnCount(6)
        self.ioc_table.setHorizontalHeaderLabels([
            "Indicator Value", "Type", "Severity", "Score", "Frequency", "Last Seen"
        ])
        self.ioc_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.ioc_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.ioc_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.ioc_table.setShowGrid(False)
        self.ioc_table.verticalHeader().setVisible(False)
        self.ioc_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ioc_table.customContextMenuRequested.connect(self.on_ioc_context_menu)
        self.ioc_table.itemSelectionChanged.connect(self.on_ioc_table_selection_changed)

        hdr = self.ioc_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        table_layout.addWidget(self.ioc_table)
        main_splitter.addWidget(table_container)

        # Right Container: Details Drawer
        self.drawer_frame = QFrame()
        self.drawer_frame.setObjectName("rightSidebar")
        self.drawer_frame.setMinimumWidth(380)
        self.drawer_frame.setMaximumWidth(460)

        drawer_layout = QVBoxLayout(self.drawer_frame)
        drawer_layout.setContentsMargins(16, 14, 16, 14)
        drawer_layout.setSpacing(12)

        drawer_header = QLabel("INDICATOR DETAILS DRAWER")
        drawer_header.setObjectName("rightSidebarTitle")
        drawer_layout.addWidget(drawer_header)

        # Scrollable Area inside drawer
        self.drawer_scroll = QScrollArea()
        self.drawer_scroll.setWidgetResizable(True)
        self.drawer_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.drawer_scroll.setStyleSheet("background: transparent;")

        self.drawer_content = QWidget()
        self.drawer_content_layout = QVBoxLayout(self.drawer_content)
        self.drawer_content_layout.setContentsMargins(0, 0, 0, 0)
        self.drawer_content_layout.setSpacing(12)

        # Default placeholder when nothing is selected
        self.drawer_empty_label = QLabel(
            "Select an indicator from the table to inspect risk breakdown, "
            "contributing factors, and threat intelligence enrichments."
        )
        self.drawer_empty_label.setStyleSheet("color: #64748b; font-size: 12px; line-height: 1.4;")
        self.drawer_empty_label.setWordWrap(True)
        self.drawer_content_layout.addWidget(self.drawer_empty_label)
        self.drawer_content_layout.addStretch()

        self.drawer_scroll.setWidget(self.drawer_content)
        drawer_layout.addWidget(self.drawer_scroll)

        main_splitter.addWidget(self.drawer_frame)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 2)
        layout.addWidget(main_splitter, 1)

        # 3. BOTTOM BUTTON ROW & PROGRESS
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.analyze_button = QPushButton("Select .eml Folder & Analyze")
        self.analyze_button.setObjectName("analyzeButton")
        self.analyze_button.setFixedHeight(44)
        self.analyze_button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_row.addWidget(self.analyze_button, 1)

        # "Add to Case" button — hidden until a scan completes
        self.add_to_case_btn = QPushButton("📁 Add Scan Results to Case")
        self.add_to_case_btn.setFixedHeight(44)
        self.add_to_case_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.add_to_case_btn.setVisible(False)
        self.add_to_case_btn.setStyleSheet("""
            QPushButton {
                background: rgba(16, 185, 129, 0.15); color: #10b981;
                border: 1px solid #10b981; border-radius: 6px;
                font-weight: 700; font-size: 12px; padding: 0 16px;
            }
            QPushButton:hover { background: #10b981; color: #0a0e17; }
        """)
        self.add_to_case_btn.clicked.connect(self.handle_add_scan_to_case)
        btn_row.addWidget(self.add_to_case_btn)

        layout.addLayout(btn_row)

        # Progress bar frame
        self.progress_frame = QFrame()
        self.progress_frame.setObjectName("progressFrame")
        self.progress_frame.setStyleSheet("""
            QFrame#progressFrame {
                background-color: #202530; border: 1px solid #2a3242;
                border-radius: 8px; padding: 6px;
            }
        """)
        pf_layout = QHBoxLayout(self.progress_frame)
        pf_layout.setContentsMargins(12, 6, 12, 6)
        pf_layout.setSpacing(12)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(24)
        pf_layout.addWidget(self.progress_bar, 1)

        self.progress_label = QLabel("Scanning...")
        self.progress_label.setStyleSheet("font-size: 11px; color: #94a3b8; font-weight: 600;")
        pf_layout.addWidget(self.progress_label)

        self.cancel_button = QPushButton("✕ Cancel")
        self.cancel_button.setFixedSize(90, 26)
        self.cancel_button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.cancel_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(239, 68, 68, 0.15); color: #ef4444;
                border: 1px solid rgba(239, 68, 68, 0.5); border-radius: 5px; font-weight: 700;
            }
            QPushButton:hover { background-color: #ef4444; color: #ffffff; }
        """)
        pf_layout.addWidget(self.cancel_button)
        self.progress_frame.setVisible(False)
        layout.addWidget(self.progress_frame)

        return page

    # =========================================================================
    # DASH PAGE DATA LOGIC & CONTROLLER
    # =========================================================================
    def _clear_dash_to_empty_state(self) -> None:
        """Reset the Dash page to an empty state (no data shown)."""
        self.ioc_table.setRowCount(0)
        self._scored_iocs_cache = []
        self.record_count_label.setText("No data — select an .eml folder to begin analysis")
        for key, default in [("total_emails", "0"), ("unique_iocs", "0"),
                             ("high_risk", "0"), ("active_cases", "0")]:
            if key in self.kpi_cards:
                self.kpi_cards[key].setText(default)

    def load_dash_data(self) -> None:
        """Load KPI cards and IOC table data directly from SQLite.

        If the database has no emails yet (i.e. no scan has been run),
        the table is left empty so the user is prompted to select a folder.
        """
        db = self.get_db()
        try:
            # 1. Check if any scan has been run
            email_count = db.get_email_count()
            if email_count == 0:
                # Nothing scanned yet — keep dashboard in empty state
                self._clear_dash_to_empty_state()
                return

            ioc_count = db.get_ioc_count()
            case_stats = db.get_case_stats()

            # 2. Get IOCs matching filter
            raw_type = self.type_filter.currentText()
            type_filter = "" if raw_type == "All Types" else raw_type.lower().replace(" ", "_")
            search_query = self.search_bar.text().strip()

            iocs = db.get_filtered_iocs(ioc_type=type_filter, search=search_query, limit=300)
            self.populate_ioc_table(iocs, db)

            # High risk count estimation (from loaded items or sample)
            high_risk_count = sum(1 for ioc in getattr(self, "_scored_iocs_cache", []) if ioc["score"] >= 50)

            if "total_emails" in self.kpi_cards:
                self.kpi_cards["total_emails"].setText(f"{email_count:,}")
            if "unique_iocs" in self.kpi_cards:
                self.kpi_cards["unique_iocs"].setText(f"{ioc_count:,}")
            if "high_risk" in self.kpi_cards:
                self.kpi_cards["high_risk"].setText(f"{high_risk_count:,}")
            if "active_cases" in self.kpi_cards:
                self.kpi_cards["active_cases"].setText(str(case_stats.get("open", 0)))

        finally:
            db.close()

    def populate_ioc_table(self, iocs: list[dict[str, Any]], db: Database) -> None:
        """Populate the IOC table and score each indicator."""
        self.ioc_table.setRowCount(len(iocs))
        self._scored_iocs_cache = []

        for row_idx, ioc in enumerate(iocs):
            ioc_id = ioc["id"]
            ioc_type = ioc["type"]
            ioc_val = ioc["value"]
            freq = ioc.get("frequency", 1)
            last_seen = str(ioc.get("last_seen", ""))[:19]

            # Fetch cached enrichment results for accurate scoring
            enrichments = db.get_enrichments_for_ioc(ioc_id)
            score_res = self.scorer.score_ioc(
                ioc_type=ioc_type,
                ioc_value=ioc_val,
                enrichment_results=enrichments,
                frequency=freq,
            )
            severity = severity_from_score(score_res.score)

            cached_item = {
                "id": ioc_id,
                "type": ioc_type,
                "value": ioc_val,
                "frequency": freq,
                "last_seen": last_seen,
                "score": score_res.score,
                "breakdown": score_res.breakdown,
                "behaviour_tags": score_res.behaviour_tags,
                "enrichments": enrichments,
            }
            self._scored_iocs_cache.append(cached_item)

            # Col 0: Indicator Value (Monospace)
            val_item = QTableWidgetItem(ioc_val)
            val_item.setFont(QFont("Consolas", 10))
            val_item.setData(Qt.ItemDataRole.UserRole, cached_item)
            self.ioc_table.setItem(row_idx, 0, val_item)

            # Col 1: Type
            type_item = QTableWidgetItem(ioc_type)
            type_item.setFont(QFont("Segoe UI", 9))
            type_item.setForeground(QColor("#94a3b8"))
            self.ioc_table.setItem(row_idx, 1, type_item)

            # Col 2: Severity Badge
            badge_widget = QWidget()
            bw_layout = QHBoxLayout(badge_widget)
            bw_layout.setContentsMargins(4, 2, 4, 2)
            bw_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            bw_layout.addWidget(RiskBadge(severity))
            self.ioc_table.setCellWidget(row_idx, 2, badge_widget)

            # Col 3: Score
            score_item = QTableWidgetItem(f"{score_res.score:.0f}/100")
            score_item.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
            score_color = "#ef4444" if score_res.score >= 50 else ("#eab308" if score_res.score >= 25 else "#10b981")
            score_item.setForeground(QColor(score_color))
            self.ioc_table.setItem(row_idx, 3, score_item)

            # Col 4: Frequency
            freq_item = QTableWidgetItem(f"{freq}×")
            freq_item.setFont(QFont("Consolas", 9))
            freq_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ioc_table.setItem(row_idx, 4, freq_item)

            # Col 5: Last Seen
            seen_item = QTableWidgetItem(last_seen.replace("T", " "))
            seen_item.setFont(QFont("Segoe UI", 9))
            seen_item.setForeground(QColor("#64748b"))
            self.ioc_table.setItem(row_idx, 5, seen_item)

            self.ioc_table.setRowHeight(row_idx, 38)

        total_in_db = db.get_ioc_count()
        self.record_count_label.setText(f"Showing {len(iocs):,} of {total_in_db:,} IOCs")

    def on_ioc_filter_changed(self) -> None:
        """Trigger reload of the IOC table on filter or search edit."""
        self.load_dash_data()

    def on_ioc_table_selection_changed(self) -> None:
        """Update the details drawer when an IOC row is selected."""
        selected_rows = self.ioc_table.selectedItems()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        item = self.ioc_table.item(row, 0)
        if not item:
            return

        ioc_data = item.data(Qt.ItemDataRole.UserRole)
        if ioc_data:
            self.populate_ioc_drawer(ioc_data)

    def populate_ioc_drawer(self, ioc: dict[str, Any]) -> None:
        """Fill the right-side drawer with complete explainability breakdown and intel."""
        # Clear previous drawer contents
        while self.drawer_content_layout.count():
            child = self.drawer_content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        ioc_id = ioc["id"]
        ioc_val = ioc["value"]
        ioc_type = ioc["type"]
        freq = ioc["frequency"]
        score = ioc["score"]
        breakdown = ioc["breakdown"]
        enrichments = ioc["enrichments"]
        defanged_val = defang(ioc_val, ioc_type)

        # 1. Header Box
        header_card = QFrame()
        header_card.setObjectName("metricCard")
        hc_layout = QVBoxLayout(header_card)
        hc_layout.setContentsMargins(12, 10, 12, 10)
        hc_layout.setSpacing(6)

        val_title = QLabel(ioc_val)
        val_title.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        val_title.setStyleSheet("color: #00f0ff;")
        val_title.setWordWrap(True)
        hc_layout.addWidget(val_title)

        meta_label = QLabel(f"Defanged: {defanged_val}\nType: {ioc_type.upper()}  •  Seen: {freq} times in corpus")
        meta_label.setStyleSheet("color: #94a3b8; font-size: 11px; font-family: 'Consolas';")
        hc_layout.addWidget(meta_label)

        # Quick Actions Row
        action_row = QHBoxLayout()
        action_row.setSpacing(8)

        copy_btn = QPushButton("📋 Copy Defanged")
        copy_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        copy_btn.setStyleSheet("""
            QPushButton {
                background: #1e2432; color: #38bdf8; border: 1px solid #2d3748;
                border-radius: 5px; padding: 4px 8px; font-size: 11px; font-weight: 600;
            }
            QPushButton:hover { background: #283144; color: #ffffff; }
        """)
        copy_btn.clicked.connect(lambda: self.copy_defanged_ioc(ioc_val, ioc_type))
        action_row.addWidget(copy_btn)

        reenrich_btn = QPushButton("🔄 Re-enrich")
        reenrich_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        reenrich_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid #00f0ff;
                border-radius: 5px; padding: 4px 8px; font-size: 11px; font-weight: 700;
            }
            QPushButton:hover { background: #00f0ff; color: #0a0e17; }
        """)
        reenrich_btn.clicked.connect(lambda: self.re_enrich_ioc(ioc_id, ioc_type, ioc_val, freq))
        action_row.addWidget(reenrich_btn)

        hc_layout.addLayout(action_row)
        self.drawer_content_layout.addWidget(header_card)

        # 2. Risk Score & Explainability Breakdown Card
        score_card = QFrame()
        score_card.setObjectName("metricCard")
        sc_layout = QVBoxLayout(score_card)
        sc_layout.setContentsMargins(12, 12, 12, 12)
        sc_layout.setSpacing(8)

        sc_top = QHBoxLayout()
        sc_lbl = QLabel(f"RISK SCORE: {score:.0f}/100")
        sc_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        sc_color = "#ef4444" if score >= 50 else ("#eab308" if score >= 25 else "#10b981")
        sc_lbl.setStyleSheet(f"color: {sc_color};")
        sc_top.addWidget(sc_lbl)
        sc_top.addStretch()
        sc_top.addWidget(RiskBadge(severity_from_score(score)))
        sc_layout.addLayout(sc_top)

        # Breakdown List
        factors_title = QLabel("SCORE BREAKDOWN (EXPLAINABILITY)")
        factors_title.setObjectName("metricSubTitle")
        sc_layout.addWidget(factors_title)

        if breakdown:
            for factor in breakdown:
                fb_box = QFrame()
                fb_box.setStyleSheet("background-color: #12141c; border-radius: 5px; padding: 6px;")
                fb_lay = QVBoxLayout(fb_box)
                fb_lay.setContentsMargins(8, 6, 8, 6)
                fb_lay.setSpacing(2)

                row = QHBoxLayout()
                fname = QLabel(factor.factor.upper().replace("_", " "))
                fname.setStyleSheet("color: #f1f5f9; font-weight: 700; font-size: 11px;")
                fpts = QLabel(f"+{factor.points:.1f} pts")
                fpts.setStyleSheet(f"color: {sc_color}; font-weight: 800; font-size: 11px;")
                row.addWidget(fname)
                row.addStretch()
                row.addWidget(fpts)
                fb_lay.addLayout(row)

                freason = QLabel(factor.reason)
                freason.setStyleSheet("color: #94a3b8; font-size: 11px;")
                freason.setWordWrap(True)
                fb_lay.addWidget(freason)

                sc_layout.addWidget(fb_box)
        else:
            no_factor = QLabel("No threat penalties applied. Clean indicator.")
            no_factor.setStyleSheet("color: #10b981; font-size: 11px;")
            sc_layout.addWidget(no_factor)

        self.drawer_content_layout.addWidget(score_card)

        # 3. Enrichment Results Card
        enrich_card = QFrame()
        enrich_card.setObjectName("metricCard")
        ec_layout = QVBoxLayout(enrich_card)
        ec_layout.setContentsMargins(12, 12, 12, 12)
        ec_layout.setSpacing(8)

        ec_title = QLabel("THREAT INTEL FEEDS (CACHED / LIVE)")
        ec_title.setObjectName("metricSubTitle")
        ec_layout.addWidget(ec_title)

        if enrichments:
            for enr in enrichments:
                provider = enr.get("provider", "unknown").upper()
                verdict = enr.get("verdict", "unknown")
                enr_score = enr.get("score")
                fetched = str(enr.get("fetched_at", ""))[:19]

                eb_box = QFrame()
                eb_box.setStyleSheet("background-color: #12141c; border-radius: 5px; padding: 6px;")
                eb_lay = QVBoxLayout(eb_box)
                eb_lay.setContentsMargins(8, 6, 8, 6)
                eb_lay.setSpacing(4)

                top_row = QHBoxLayout()
                p_lbl = QLabel(provider)
                p_lbl.setStyleSheet("font-weight: 700; font-size: 11px; color: #38bdf8;")
                v_lbl = QLabel(verdict.upper())
                v_col = "#ef4444" if verdict == "malicious" else ("#eab308" if verdict == "suspicious" else "#10b981")
                v_lbl.setStyleSheet(f"font-weight: 800; font-size: 10px; color: {v_col};")
                top_row.addWidget(p_lbl)
                top_row.addStretch()
                top_row.addWidget(v_lbl)
                eb_lay.addLayout(top_row)

                details = f"Score: {enr_score if enr_score is not None else 'N/A'}  •  Fetched: {fetched}"
                d_lbl = QLabel(details)
                d_lbl.setStyleSheet("color: #64748b; font-size: 10px;")
                eb_lay.addWidget(d_lbl)

                ec_layout.addWidget(eb_box)
        else:
            no_enr = QLabel("No threat intelligence cached in DB for this indicator.")
            no_enr.setStyleSheet("color: #64748b; font-size: 11px;")
            ec_layout.addWidget(no_enr)

            enr_now_btn = QPushButton("⚡ Run Live Enrichment")
            enr_now_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            enr_now_btn.setStyleSheet("""
                QPushButton {
                    background: #1e2432; color: #00f0ff; border: 1px solid #00f0ff;
                    border-radius: 5px; padding: 5px; font-weight: 700; font-size: 11px;
                }
                QPushButton:hover { background: #00f0ff; color: #0a0e17; }
            """)
            enr_now_btn.clicked.connect(lambda: self.re_enrich_ioc(ioc_id, ioc_type, ioc_val, freq))
            ec_layout.addWidget(enr_now_btn)

        self.drawer_content_layout.addWidget(enrich_card)

        # 4. Associated Emails Card
        email_card = QFrame()
        email_card.setObjectName("metricCard")
        emc_layout = QVBoxLayout(email_card)
        emc_layout.setContentsMargins(12, 12, 12, 12)
        emc_layout.setSpacing(6)

        emc_title = QLabel("ASSOCIATED EVIDENCE EMAILS")
        emc_title.setObjectName("metricSubTitle")
        emc_layout.addWidget(emc_title)

        db = self.get_db()
        try:
            linked_emails = db.get_emails_for_ioc(ioc_id, limit=5)
            if linked_emails:
                for em in linked_emails:
                    fn = em.get("filename", "")
                    ctx = em.get("context", "")
                    lbl = QLabel(f"• {fn} ({ctx})")
                    lbl.setStyleSheet("color: #cbd5e1; font-size: 11px; font-family: 'Consolas';")
                    lbl.setWordWrap(True)
                    emc_layout.addWidget(lbl)
            else:
                lbl = QLabel("No linked email files recorded.")
                lbl.setStyleSheet("color: #64748b; font-size: 11px;")
                emc_layout.addWidget(lbl)
        finally:
            db.close()

        self.drawer_content_layout.addWidget(email_card)
        self.drawer_content_layout.addStretch()

    # =========================================================================
    # CONTEXT MENU & DEFANG / RE-ENRICH ACTIONS
    # =========================================================================
    def on_ioc_context_menu(self, pos: QPoint) -> None:
        """Right-click menu on the IOC table."""
        item = self.ioc_table.itemAt(pos)
        if not item:
            return

        row = item.row()
        item_data = self.ioc_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not item_data:
            return

        ioc_id = item_data["id"]
        ioc_val = item_data["value"]
        ioc_type = item_data["type"]
        freq = item_data["frequency"]
        defanged_val = defang(ioc_val, ioc_type)

        menu = QMenu(self)

        copy_defanged_act = menu.addAction(f"🛡️ Copy Defanged ({defanged_val})")
        copy_raw_act = menu.addAction(f"📋 Copy Raw ({ioc_val})")
        menu.addSeparator()
        reenrich_act = menu.addAction("🔄 Re-enrich Indicator")
        menu.addSeparator()
        link_case_act = menu.addAction("📁 Add to Investigation Case...")

        action = menu.exec(self.ioc_table.viewport().mapToGlobal(pos))
        if action == copy_defanged_act:
            self.copy_defanged_ioc(ioc_val, ioc_type)
        elif action == copy_raw_act:
            self.copy_raw_ioc(ioc_val)
        elif action == reenrich_act:
            self.re_enrich_ioc(ioc_id, ioc_type, ioc_val, freq)
        elif action == link_case_act:
            self.add_ioc_to_case_prompt(ioc_id, ioc_val)

    def copy_defanged_ioc(self, val: str, ioc_type: str) -> None:
        """Copy defanged IOC representation to the system clipboard."""
        defanged = defang(val, ioc_type)
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(defanged)
        self.statusBar().showMessage(f"Copied defanged IOC to clipboard: {defanged}", 4000)

    def copy_raw_ioc(self, val: str) -> None:
        """Copy raw IOC string to clipboard."""
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(val)
        self.statusBar().showMessage(f"Copied raw IOC to clipboard: {val}", 4000)

    def re_enrich_ioc(self, ioc_id: int, ioc_type: str, val: str, freq: int) -> None:
        """Launch background thread to re-enrich the indicator."""
        self.statusBar().showMessage(f"⏳ Querying live intelligence for {val}...", 5000)

        worker = EnrichWorker(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            ioc_value=val,
            frequency=freq,
            db_path=self.db_path,
            force_refresh=True,
            parent=self,
        )

        def on_finished(result: dict) -> None:
            self.statusBar().showMessage(
                f"✓ Re-enrichment complete for {val} — new score: {result['score']:.0f}/100", 6000
            )
            # Reload dash table and drawer
            self.load_dash_data()
            self.populate_ioc_drawer(result)
            if worker in self._enrich_workers:
                self._enrich_workers.remove(worker)

        def on_error(err: str) -> None:
            self.statusBar().showMessage(f"✕ Enrichment failed: {err}", 6000)
            if worker in self._enrich_workers:
                self._enrich_workers.remove(worker)

        worker.finished.connect(on_finished)
        worker.error.connect(on_error)
        self._enrich_workers.append(worker)
        worker.start()

    def add_ioc_to_case_prompt(self, ioc_id: int, ioc_val: str) -> None:
        """Prompt user to add this IOC to an existing or new case."""
        from PyQt6.QtWidgets import QInputDialog
        db = self.get_db()
        try:
            cases = db.get_all_cases()
            if not cases:
                reply = QMessageBox.question(
                    self,
                    "No Cases Found",
                    "No investigation cases exist yet.\n\nWould you like to create a new case now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    db.close()
                    self.handle_create_case()
                return

            case_titles = [f"#{c['id']}: {c['title']} ({c['status']})" for c in cases]
            chosen, ok = QInputDialog.getItem(
                self, "Add IOC to Case",
                f"Select a case for indicator  '{ioc_val}':",
                case_titles, 0, False,
            )
            if ok and chosen:
                case_id = int(chosen.split(":")[0].replace("#", ""))
                case = db.get_case(case_id)
                if case:
                    existing = case.get("notes", "")
                    updated = f"{existing}\n• [IOC] {ioc_val}".strip()
                    db.update_case_notes(case_id, updated)
                    self.statusBar().showMessage(
                        f"✓ Added IOC '{ioc_val}' to Case #{case_id}", 4000
                    )
        finally:
            db.close()

    def handle_add_scan_to_case(self) -> None:
        """Link all emails currently in the DB to a chosen case (called from Dash page)."""
        from PyQt6.QtWidgets import QInputDialog
        db = self.get_db()
        try:
            cases = db.get_all_cases()
            if not cases:
                reply = QMessageBox.question(
                    self,
                    "No Cases Found",
                    "No investigation cases exist yet.\n\nWould you like to create a new case now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    db.close()
                    self.handle_create_case()
                return

            case_titles = [f"#{c['id']}: {c['title']} ({c['status']})" for c in cases]
            chosen, ok = QInputDialog.getItem(
                self, "Add Scan Results to Case",
                "Link all scanned emails to which case?",
                case_titles, 0, False,
            )
            if ok and chosen:
                case_id = int(chosen.split(":")[0].replace("#", ""))
                emails = db.get_all_emails()
                linked = 0
                for email in emails:
                    db.add_email_to_case(case_id, email["id"])
                    linked += 1
                db.batch_commit()
                self.statusBar().showMessage(
                    f"✓ Linked {linked} email(s) to Case #{case_id}", 5000
                )
        finally:
            db.close()

    def handle_add_all_db_emails_to_case(self) -> None:
        """Add all emails in the DB to the currently selected case."""
        if not hasattr(self, "_active_case") or not self._active_case:
            return
        cid = self._active_case["id"]
        db = self.get_db()
        try:
            emails = db.get_all_emails()
            if not emails:
                QMessageBox.information(
                    self, "No Emails",
                    "No emails in the database yet.\nPlease scan an .eml folder first."
                )
                return
            confirm = QMessageBox.question(
                self,
                "Confirm",
                f"Add all {len(emails)} email(s) from the database to Case #{cid}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if confirm != QMessageBox.StandardButton.Yes:
                return
            for email in emails:
                db.add_email_to_case(cid, email["id"])
            db.batch_commit()
            count = db.get_email_count_for_case(cid)
            self.case_email_count_label.setText(f"📧 {count} email(s) linked")
            linked_emails = db.get_emails_for_case(cid)
            lines = [
                f"{e.get('subject', '(no subject)')[:55]}  [{e.get('sender_email', '')}]"
                for e in linked_emails[:10]
            ]
            if count > 10:
                lines.append(f"... and {count - 10} more")
            self.case_emails_list.setPlainText("\n".join(lines))
            self.statusBar().showMessage(
                f"✓ Added {len(emails)} email(s) to Case #{cid}", 5000
            )
        finally:
            db.close()

    # =========================================================================
    # PAGE 1: CASES PAGE
    # =========================================================================
    def create_cases_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("contentContainer")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(16)

        # Header Row
        top_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        h = QLabel("Forensic Incident Cases")
        h.setObjectName("headerTitle")
        sub = QLabel("Analyst incident management, mailbox evidence dossiers, and notes")
        sub.setObjectName("headerSubtitle")
        title_box.addWidget(h)
        title_box.addWidget(sub)
        top_row.addLayout(title_box)

        top_row.addStretch()

        new_case_btn = QPushButton("➕ New Investigation Case")
        new_case_btn.setFixedHeight(38)
        new_case_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        new_case_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00f0ff, stop:1 #0284c7);
                color: #0a0e17; font-weight: 800; font-size: 12px;
                border-radius: 6px; padding: 0px 16px; border: 1px solid #00f0ff;
            }
            QPushButton:hover { background: #38bdf8; }
        """)
        new_case_btn.clicked.connect(self.handle_create_case)
        top_row.addWidget(new_case_btn)

        export_btn = QPushButton("📦 Export Case (STIX / MISP / Report)")
        export_btn.setFixedHeight(38)
        export_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #202530; color: #00f0ff;
                border: 1px solid rgba(0, 240, 255, 0.4); border-radius: 6px;
                font-weight: 700; font-size: 12px; padding: 0px 16px;
            }
            QPushButton:hover { background-color: rgba(0, 240, 255, 0.15); color: #ffffff; }
        """)
        export_btn.clicked.connect(self.handle_export_dialog)
        top_row.addWidget(export_btn)

        layout.addLayout(top_row)

        # Metric Cards Row
        metrics_box = QHBoxLayout()
        metrics_box.setSpacing(14)
        self.case_metric_labels: dict[str, QLabel] = {}

        for key, title, col in [
            ("open", "OPEN INVESTIGATIONS", "#00f0ff"),
            ("high_priority", "HIGH PRIORITY", "#f97316"),
            ("closed", "RESOLVED CASES", "#10b981"),
            ("total", "TOTAL DOSSIERS", "#38bdf8"),
        ]:
            card = QFrame()
            card.setObjectName("metricCard")
            card.setStyleSheet(f"""
                QFrame#metricCard {{
                    background-color: #202530; border: 1px solid #2a3242;
                    border-top: 3px solid {col}; border-radius: 8px;
                }}
            """)
            cl = QVBoxLayout(card)
            cl.setContentsMargins(14, 10, 14, 10)
            t = QLabel(title)
            t.setObjectName("metricSubTitle")
            v = QLabel("0")
            v.setStyleSheet(f"font-size: 24px; font-weight: 800; color: {col}; font-family: 'Consolas';")
            cl.addWidget(t)
            cl.addWidget(v)
            metrics_box.addWidget(card)
            self.case_metric_labels[key] = v

        layout.addLayout(metrics_box)

        # Cases Splitter (Table Left, Dossier/Notes Right)
        cases_splitter = QSplitter(Qt.Orientation.Horizontal)
        cases_splitter.setChildrenCollapsible(False)

        # Table Container
        table_card = QFrame()
        table_card.setObjectName("tableContainer")
        tc_lay = QVBoxLayout(table_card)
        tc_lay.setContentsMargins(14, 12, 14, 12)
        tc_lay.setSpacing(8)

        t_lbl = QLabel("Active Case Dossiers")
        t_lbl.setObjectName("sectionTitle")
        tc_lay.addWidget(t_lbl)

        self.cases_table = QTableWidget()
        self.cases_table.setObjectName("iocTable")
        self.cases_table.setColumnCount(5)
        self.cases_table.setHorizontalHeaderLabels([
            "Case ID", "Title", "Priority", "Status", "Created At"
        ])
        self.cases_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.cases_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.cases_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.cases_table.setShowGrid(False)
        self.cases_table.verticalHeader().setVisible(False)
        self.cases_table.itemSelectionChanged.connect(self.on_case_table_selection_changed)

        chdr = self.cases_table.horizontalHeader()
        chdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        chdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        chdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        chdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        chdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        tc_lay.addWidget(self.cases_table)
        cases_splitter.addWidget(table_card)

        # Case Dossier Details & Notes Editor
        self.case_details_card = QFrame()
        self.case_details_card.setObjectName("rightSidebar")
        self.case_details_card.setMinimumWidth(380)
        cd_layout = QVBoxLayout(self.case_details_card)
        cd_layout.setContentsMargins(16, 14, 16, 14)
        cd_layout.setSpacing(10)

        cd_title = QLabel("CASE DOSSIER & ANALYST NOTES")
        cd_title.setObjectName("rightSidebarTitle")
        cd_layout.addWidget(cd_title)

        self.case_selected_title = QLabel("Select a case to view or edit notes")
        self.case_selected_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #00f0ff;")
        self.case_selected_title.setWordWrap(True)
        cd_layout.addWidget(self.case_selected_title)

        self.case_status_btn = QPushButton("Toggle Case Status")
        self.case_status_btn.setEnabled(False)
        self.case_status_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.case_status_btn.clicked.connect(self.handle_toggle_case_status)
        cd_layout.addWidget(self.case_status_btn)

        self.case_desc_label = QLabel("")
        self.case_desc_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        self.case_desc_label.setWordWrap(True)
        cd_layout.addWidget(self.case_desc_label)

        # --- Evidence counter + Add emails button ---
        evidence_row = QHBoxLayout()
        self.case_email_count_label = QLabel("📧 0 emails linked")
        self.case_email_count_label.setStyleSheet(
            "color: #38bdf8; font-size: 11px; font-weight: 700;"
        )
        evidence_row.addWidget(self.case_email_count_label)
        evidence_row.addStretch()

        self.add_db_emails_btn = QPushButton("+ Add All DB Emails")
        self.add_db_emails_btn.setEnabled(False)
        self.add_db_emails_btn.setFixedHeight(28)
        self.add_db_emails_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.add_db_emails_btn.setStyleSheet("""
            QPushButton {
                background: rgba(16, 185, 129, 0.15); color: #10b981;
                border: 1px solid #10b981; border-radius: 5px;
                font-size: 11px; font-weight: 700; padding: 0 10px;
            }
            QPushButton:hover { background: #10b981; color: #0a0e17; }
            QPushButton:disabled { color: #4a5568; border-color: #2d3748; background: transparent; }
        """)
        self.add_db_emails_btn.clicked.connect(self.handle_add_all_db_emails_to_case)
        evidence_row.addWidget(self.add_db_emails_btn)
        cd_layout.addLayout(evidence_row)

        # Linked emails mini-list
        self.case_emails_list = QPlainTextEdit()
        self.case_emails_list.setReadOnly(True)
        self.case_emails_list.setMaximumHeight(90)
        self.case_emails_list.setPlaceholderText("No emails linked to this case yet.")
        self.case_emails_list.setStyleSheet(
            "background: #161920; color: #64748b; font-size: 10px; "
            "border: 1px solid #2a3242; border-radius: 5px; padding: 4px;"
        )
        cd_layout.addWidget(self.case_emails_list)

        notes_header = QLabel("Analyst Investigation Notes:")
        notes_header.setObjectName("metricSubTitle")
        cd_layout.addWidget(notes_header)

        self.case_notes_editor = QTextEdit()
        self.case_notes_editor.setPlaceholderText("Write investigation findings, IOC links, timeline...")
        cd_layout.addWidget(self.case_notes_editor, 1)

        notes_btn_row = QHBoxLayout()
        self.save_notes_btn = QPushButton("💾 Save Notes")
        self.save_notes_btn.setEnabled(False)
        self.save_notes_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.save_notes_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid #00f0ff;
                border-radius: 6px; padding: 6px 14px; font-weight: 700;
            }
            QPushButton:hover { background: #00f0ff; color: #0a0e17; }
        """)
        self.save_notes_btn.clicked.connect(self.handle_save_case_notes)
        notes_btn_row.addWidget(self.save_notes_btn)

        self.delete_case_btn = QPushButton("🗑 Delete Case")
        self.delete_case_btn.setEnabled(False)
        self.delete_case_btn.setStyleSheet("""
            QPushButton {
                background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444;
                border-radius: 6px; padding: 6px 14px; font-weight: 700;
            }
            QPushButton:hover { background: #ef4444; color: #ffffff; }
        """)
        self.delete_case_btn.clicked.connect(self.handle_delete_case)
        notes_btn_row.addWidget(self.delete_case_btn)

        cd_layout.addLayout(notes_btn_row)

        cases_splitter.addWidget(self.case_details_card)
        cases_splitter.setStretchFactor(0, 3)
        cases_splitter.setStretchFactor(1, 2)
        layout.addWidget(cases_splitter, 1)

        return page

    def load_cases_data(self) -> None:
        """Load cases and statistics from SQLite."""
        db = self.get_db()
        try:
            stats = db.get_case_stats()
            for k in ["open", "high_priority", "closed", "total"]:
                if k in self.case_metric_labels:
                    self.case_metric_labels[k].setText(str(stats.get(k, 0)))

            cases = db.get_all_cases()
            self.cases_table.setRowCount(len(cases))

            for row_idx, c in enumerate(cases):
                cid = c["id"]
                title = c["title"]
                priority = c.get("priority", "medium")
                status = c.get("status", "open")
                created = str(c.get("created_at", ""))[:19]

                id_item = QTableWidgetItem(f"#{cid}")
                id_item.setData(Qt.ItemDataRole.UserRole, c)
                id_item.setFont(QFont("Consolas", 10))
                self.cases_table.setItem(row_idx, 0, id_item)

                title_item = QTableWidgetItem(title)
                title_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
                title_item.setForeground(QColor("#f1f5f9"))
                self.cases_table.setItem(row_idx, 1, title_item)

                p_item = QTableWidgetItem(priority.upper())
                p_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                p_col = "#ef4444" if priority in ("high", "critical") else "#eab308"
                p_item.setForeground(QColor(p_col))
                self.cases_table.setItem(row_idx, 2, p_item)

                s_item = QTableWidgetItem(status.upper())
                s_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                s_col = "#00f0ff" if status == "open" else "#10b981"
                s_item.setForeground(QColor(s_col))
                self.cases_table.setItem(row_idx, 3, s_item)

                dt_item = QTableWidgetItem(created.replace("T", " "))
                dt_item.setFont(QFont("Segoe UI", 9))
                dt_item.setForeground(QColor("#64748b"))
                self.cases_table.setItem(row_idx, 4, dt_item)

                self.cases_table.setRowHeight(row_idx, 38)

        finally:
            db.close()

    def on_case_table_selection_changed(self) -> None:
        selected = self.cases_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        case_data = self.cases_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not case_data:
            return

        self._active_case = case_data
        cid = case_data["id"]
        status = case_data.get("status", "open")

        self.case_selected_title.setText(f"Case #{cid}: {case_data['title']}")
        self.case_desc_label.setText(case_data.get("description", "No description provided."))
        self.case_notes_editor.setPlainText(case_data.get("notes", ""))
        self.save_notes_btn.setEnabled(True)
        self.delete_case_btn.setEnabled(True)
        self.add_db_emails_btn.setEnabled(True)

        self.case_status_btn.setEnabled(True)
        if status == "open":
            self.case_status_btn.setText("🔒 Close Case")
            self.case_status_btn.setStyleSheet("background: #1e2432; color: #10b981; border: 1px solid #10b981;")
        else:
            self.case_status_btn.setText("🔓 Reopen Case")
            self.case_status_btn.setStyleSheet("background: #1e2432; color: #00f0ff; border: 1px solid #00f0ff;")

        # Show linked email count and list
        db = self.get_db()
        try:
            count = db.get_email_count_for_case(cid)
            self.case_email_count_label.setText(f"📧 {count} email(s) linked")
            linked_emails = db.get_emails_for_case(cid)
            if linked_emails:
                lines = [
                    f"{e.get('subject', '(no subject)')[:55]}  [{e.get('sender_email', '')}]"
                    for e in linked_emails[:10]
                ]
                if count > 10:
                    lines.append(f"... and {count - 10} more")
                self.case_emails_list.setPlainText("\n".join(lines))
            else:
                self.case_emails_list.clear()
        finally:
            db.close()

    def handle_create_case(self) -> None:
        dlg = CreateCaseDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            db = self.get_db()
            try:
                cid = db.create_case(
                    title=data["title"],
                    description=data["description"],
                    notes=data["notes"],
                    priority=data["priority"],
                )
                self.statusBar().showMessage(f"✓ Case #{cid} created successfully.", 4000)
                self.load_cases_data()
            finally:
                db.close()

    def handle_save_case_notes(self) -> None:
        if not hasattr(self, "_active_case") or not self._active_case:
            return

        cid = self._active_case["id"]
        notes = self.case_notes_editor.toPlainText()
        db = self.get_db()
        try:
            db.update_case_notes(cid, notes)
            self._active_case["notes"] = notes
            self.statusBar().showMessage(f"✓ Saved notes for Case #{cid}.", 3000)
        finally:
            db.close()

    def handle_toggle_case_status(self) -> None:
        if not hasattr(self, "_active_case") or not self._active_case:
            return

        cid = self._active_case["id"]
        cur_status = self._active_case.get("status", "open")
        new_status = "closed" if cur_status == "open" else "open"

        db = self.get_db()
        try:
            db.update_case_status(cid, new_status)
            self._active_case["status"] = new_status
            self.load_cases_data()
            self.statusBar().showMessage(f"✓ Case #{cid} is now {new_status.upper()}.", 4000)
        finally:
            db.close()

    def handle_delete_case(self) -> None:
        if not hasattr(self, "_active_case") or not self._active_case:
            return

        cid = self._active_case["id"]
        confirm = QMessageBox.question(
            self, "Confirm Delete", f"Are you sure you want to delete Case #{cid}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            db = self.get_db()
            try:
                db.delete_case(cid)
                self.statusBar().showMessage(f"Deleted Case #{cid}.", 4000)
                self._active_case = None
                self.case_selected_title.setText("Select a case to view or edit notes")
                self.case_notes_editor.clear()
                self.save_notes_btn.setEnabled(False)
                self.delete_case_btn.setEnabled(False)
                self.case_status_btn.setEnabled(False)
                self.load_cases_data()
            finally:
                db.close()

    def handle_export_dialog(self) -> None:
        """Export case or full corpus to STIX 2.1, MISP, HTML, or PDF report."""
        db = self.get_db()
        try:
            if hasattr(self, "_active_case") and self._active_case:
                cid = self._active_case["id"]
                emails = db.get_emails_for_case(cid)
                title = f"Case #{cid} - {self._active_case.get('title', 'Investigation')}"
                case_info = self._active_case
            else:
                emails = db.get_recent_emails(limit=100)
                title = "MailIntel Incident Investigation"
                case_info = None

            eids = [e["id"] for e in emails]
            iocs_map = db.get_iocs_for_emails(eids)
            iocs = []
            seen = set()
            for ilist in iocs_map.values():
                for i in ilist:
                    k = f"{i['type']}:{i['value']}"
                    if k not in seen:
                        seen.add(k)
                        iocs.append(i)

            if not iocs and not emails:
                QMessageBox.information(self, "No Artifacts", "No emails or IOCs found to export.")
                return

            dest_folder = QFileDialog.getExistingDirectory(
                self, "Select Directory to Export Intelligence Packages", ""
            )
            if not dest_folder:
                return

            out_dir = Path(dest_folder)
            # 1. STIX 2.1
            stix_exp = StixExporter()
            stix_exp.export_to_file(out_dir / "mailintel_stix2.1_bundle.json", iocs=iocs, emails=emails)

            # 2. MISP Event
            misp_exp = MispExporter()
            misp_exp.export_to_file(out_dir / "mailintel_misp_event.json", iocs=iocs, emails=emails, event_info=title)

            # 3. HTML Incident Report
            rep_exp = ReportExporter()
            rep_exp.export_html(
                out_dir / "incident_report.html",
                incident_title=title,
                emails=emails,
                iocs=iocs,
                case_details=case_info,
            )

            # 4. PDF Incident Report
            rep_exp.export_pdf(
                out_dir / "incident_report.pdf",
                incident_title=title,
                emails=emails,
                iocs=iocs,
                case_details=case_info,
            )

            QMessageBox.information(
                self,
                "Export Complete",
                f"Successfully generated STIX 2.1 bundle, MISP JSON, HTML report, and PDF report in:\n{out_dir}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Failed generating export packages: {exc}")
        finally:
            db.close()

    # =========================================================================
    # PAGE 2: GRAPH PAGE (PYVIS IN QWEBENGINEVIEW WITH INTERACTIVE CORRELATION)
    # =========================================================================
    def create_graph_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("contentContainer")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 20, 28, 20)
        layout.setSpacing(14)

        # 1. Header with dynamic counts and refresh action
        header_layout = QHBoxLayout()
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(4)

        header = QLabel("Threat Entity Relationship Graph")
        header.setObjectName("headerTitle")
        header_vbox.addWidget(header)

        # Real node/cluster counts in the header instead of hardcoded text
        self.graph_stats_label = QLabel("Initializing threat correlation engine...")
        self.graph_stats_label.setObjectName("headerSubtitle")
        self.graph_stats_label.setStyleSheet("color: #94a3b8; font-size: 13px; font-weight: 500;")
        header_vbox.addWidget(self.graph_stats_label)
        header_layout.addLayout(header_vbox, 1)

        self.graph_refresh_btn = QPushButton("↻ Refresh Correlation")
        self.graph_refresh_btn.setFixedHeight(36)
        self.graph_refresh_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.graph_refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 240, 255, 0.12);
                color: #00f0ff;
                border: 1px solid #00f0ff;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 700;
                padding: 6px 16px;
            }
            QPushButton:hover {
                background-color: #00f0ff;
                color: #0d1117;
            }
        """)
        self.graph_refresh_btn.clicked.connect(self.load_graph_data)
        header_layout.addWidget(self.graph_refresh_btn)

        self.graph_fullscreen_btn = QPushButton("⛶ Full Page Mode")
        self.graph_fullscreen_btn.setFixedHeight(36)
        self.graph_fullscreen_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.graph_fullscreen_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(59, 130, 246, 0.12);
                color: #60a5fa;
                border: 1px solid #3b82f6;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 700;
                padding: 6px 16px;
            }
            QPushButton:hover {
                background-color: #3b82f6;
                color: #ffffff;
            }
        """)
        self.graph_fullscreen_btn.clicked.connect(self.toggle_graph_full_page)
        header_layout.addWidget(self.graph_fullscreen_btn)
        layout.addLayout(header_layout)

        # 2. Filter & Legend Bar
        filter_bar = QFrame()
        filter_bar.setObjectName("tableContainer")
        filter_bar.setFixedHeight(50)
        fb_layout = QHBoxLayout(filter_bar)
        fb_layout.setContentsMargins(16, 8, 16, 8)
        fb_layout.setSpacing(14)

        camp_lbl = QLabel("Campaign:")
        camp_lbl.setStyleSheet("color: #cbd5e1; font-weight: 600; font-size: 12px;")
        fb_layout.addWidget(camp_lbl)

        self.graph_campaign_combo = QComboBox()
        self.graph_campaign_combo.addItem("All Campaigns (Corpus Wide)", "all")
        self.graph_campaign_combo.setFixedHeight(30)
        self.graph_campaign_combo.setMinimumWidth(220)
        self.graph_campaign_combo.currentIndexChanged.connect(self.on_graph_filter_changed)
        fb_layout.addWidget(self.graph_campaign_combo)

        limit_lbl = QLabel("Limit:")
        limit_lbl.setStyleSheet("color: #cbd5e1; font-weight: 600; font-size: 12px;")
        fb_layout.addWidget(limit_lbl)

        self.graph_limit_combo = QComboBox()
        self.graph_limit_combo.addItem("Top 50 Entities", 50)
        self.graph_limit_combo.addItem("Top 100 Entities", 100)
        self.graph_limit_combo.addItem("Top 150 Entities", 150)
        self.graph_limit_combo.addItem("Top 250 Entities", 250)
        self.graph_limit_combo.addItem("Top 500 Entities", 500)
        self.graph_limit_combo.setCurrentIndex(2)
        self.graph_limit_combo.setFixedHeight(30)
        self.graph_limit_combo.currentIndexChanged.connect(self.on_graph_filter_changed)
        fb_layout.addWidget(self.graph_limit_combo)

        fb_layout.addSpacing(16)
        legend_lbl = QLabel("Legend:")
        legend_lbl.setStyleSheet("color: #64748b; font-size: 11px; font-weight: 700;")
        fb_layout.addWidget(legend_lbl)

        legends = [
            ("Email", ENTITY_COLORS["email"]),
            ("Sender", ENTITY_COLORS["sender"]),
            ("Domain", ENTITY_COLORS["domain"]),
            ("IP", ENTITY_COLORS["ip"]),
            ("Hash", ENTITY_COLORS["hash"]),
            ("URL", ENTITY_COLORS["url"]),
        ]
        for name, col in legends:
            dot = QLabel(f"● {name}")
            dot.setStyleSheet(f"color: {col}; font-size: 11px; font-weight: 700; margin-right: 4px;")
            fb_layout.addWidget(dot)

        fb_layout.addStretch()
        layout.addWidget(filter_bar)

        # 3. Main Splitter: Pyvis Graph (Left) & Node Details Drawer (Right)
        self.graph_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.graph_splitter.setObjectName("graphSplitter")
        self.graph_splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Left Container: QWebEngineView hosting the Pyvis interactive network
        self.graph_web_container = QFrame()
        self.graph_web_container.setObjectName("tableContainer")
        self.graph_web_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.graph_web_layout = QVBoxLayout(self.graph_web_container)
        self.graph_web_layout.setContentsMargins(0, 0, 0, 0)

        self.graph_web_view: QWebEngineView | None = None
        self.graph_splitter.addWidget(self.graph_web_container)

        # Right Container: Details Drawer
        self.graph_drawer = QFrame()
        self.graph_drawer.setObjectName("rightSidebar")
        self.graph_drawer.setMinimumWidth(360)
        self.graph_drawer.setMaximumWidth(460)

        gd_layout = QVBoxLayout(self.graph_drawer)
        gd_layout.setContentsMargins(18, 16, 18, 16)
        gd_layout.setSpacing(12)

        drawer_hdr_layout = QHBoxLayout()
        drawer_hdr = QLabel("ENTITY DETAILS & CORRELATION")
        drawer_hdr.setObjectName("rightSidebarTitle")
        drawer_hdr_layout.addWidget(drawer_hdr, 1)

        self.graph_drawer_close_btn = QPushButton("✕")
        self.graph_drawer_close_btn.setFixedSize(26, 26)
        self.graph_drawer_close_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.graph_drawer_close_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.06);
                color: #94a3b8;
                border: 1px solid #334155;
                border-radius: 4px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(244, 63, 94, 0.2);
                color: #f43f5e;
                border-color: #f43f5e;
            }
        """)
        self.graph_drawer_close_btn.clicked.connect(lambda: self.set_graph_drawer_visible(False))
        drawer_hdr_layout.addWidget(self.graph_drawer_close_btn)
        gd_layout.addLayout(drawer_hdr_layout)

        self.graph_drawer_scroll = QScrollArea()
        self.graph_drawer_scroll.setWidgetResizable(True)
        self.graph_drawer_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.graph_drawer_scroll.setStyleSheet("background: transparent;")

        self.graph_drawer_content = QWidget()
        self.graph_drawer_vbox = QVBoxLayout(self.graph_drawer_content)
        self.graph_drawer_vbox.setContentsMargins(0, 0, 0, 0)
        self.graph_drawer_vbox.setSpacing(12)

        self.graph_drawer_empty = QLabel(
            "Click any node in the graph (email, sender, IP, domain, hash, or URL) "
            "to inspect risk scoring breakdown, multi-signal correlations, and linked infrastructure."
        )
        self.graph_drawer_empty.setStyleSheet("color: #64748b; font-size: 13px; line-height: 1.5;")
        self.graph_drawer_empty.setWordWrap(True)
        self.graph_drawer_vbox.addWidget(self.graph_drawer_empty)
        self.graph_drawer_vbox.addStretch()

        self.graph_drawer_scroll.setWidget(self.graph_drawer_content)
        gd_layout.addWidget(self.graph_drawer_scroll)

        self.graph_splitter.addWidget(self.graph_drawer)
        self.graph_splitter.setStretchFactor(0, 1)
        self.graph_splitter.setStretchFactor(1, 0)
        self.graph_splitter.setCollapsible(0, False)
        self.graph_splitter.setCollapsible(1, True)

        layout.addWidget(self.graph_splitter, 1)
        return page

    def toggle_graph_full_page(self) -> None:
        """Toggle graph drawer visibility to allow full-width / full-page graph inspection."""
        is_visible = self.graph_drawer.isVisible()
        self.set_graph_drawer_visible(not is_visible)

    def set_graph_drawer_visible(self, visible: bool) -> None:
        """Show or hide the side drawer and update the toggle button state."""
        self.graph_drawer.setVisible(visible)
        if visible:
            self.graph_fullscreen_btn.setText("⛶ Full Page Mode")
            self.graph_fullscreen_btn.setToolTip("Expand graph to occupy full width")
        else:
            self.graph_fullscreen_btn.setText("◧ Show Details Panel")
            self.graph_fullscreen_btn.setToolTip("Show node details and correlation drawer")

        if self.graph_web_view is not None and os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            self.graph_web_view.page().runJavaScript(
                "if (typeof network !== 'undefined' && network) { network.redraw(); network.fit(); }"
            )

    def _ensure_graph_web_view(self) -> None:
        """Lazily initialize QWebEngineView on first demand."""
        if self.graph_web_view is None:
            self.graph_web_view = QWebEngineView(self.graph_web_container)
            self.graph_web_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            self.graph_web_view.setStyleSheet("background-color: #15181e;")
            self.graph_web_view.urlChanged.connect(self._on_web_url_changed)
            self.graph_web_layout.addWidget(self.graph_web_view)

    def _on_web_url_changed(self, qurl) -> None:
        """Handle URL navigation events emitted from Pyvis vis.js interactions."""
        url_str = qurl.toString()
        if "mailintel://node/" in url_str:
            raw_id = url_str.split("mailintel://node/")[-1]
            from urllib.parse import unquote
            node_id = unquote(raw_id)
            self.on_graph_node_clicked(node_id)
        elif "mailintel://deselect" in url_str:
            self.on_graph_node_deselected()

    def load_graph_data(self) -> None:
        """Fetch ingested email and IOC data from SQLite, cluster into campaigns, and render graph."""
        db = self.get_db()
        try:
            emails = db.get_recent_emails(limit=200)
            if not emails:
                self.graph_stats_label.setText("No emails ingested in database yet.")
                return

            email_ids = [e["id"] for e in emails]
            email_iocs_map = db.get_iocs_for_emails(email_ids)

            # Cluster emails into campaigns via shared IOCs, sender infrastructure, and TF-IDF
            self._current_campaigns = self.clusterer.cluster_emails(emails, email_iocs_map)

            # Populate campaign combo box
            self.graph_campaign_combo.blockSignals(True)
            self.graph_campaign_combo.clear()
            self.graph_campaign_combo.addItem("All Campaigns (Corpus Wide)", "all")
            for c in self._current_campaigns:
                self.graph_campaign_combo.addItem(
                    f"{c.campaign_id}: {c.name} ({len(c.email_ids)} emails)", c.campaign_id
                )
            self.graph_campaign_combo.blockSignals(False)

            self._cached_emails = emails
            self._cached_iocs_map = email_iocs_map

            self._render_active_graph()
        finally:
            db.close()

    def _render_active_graph(self) -> None:
        """Construct the NetworkX graph and render HTML inside QWebEngineView."""
        if not hasattr(self, "_cached_emails"):
            return

        camp_filter = self.graph_campaign_combo.currentData() or "all"
        max_nodes = int(self.graph_limit_combo.currentData() or 150)

        if camp_filter != "all":
            selected_camp = next((c for c in self._current_campaigns if c.campaign_id == camp_filter), None)
            if selected_camp:
                filter_eids = set(selected_camp.email_ids)
                active_emails = [e for e in self._cached_emails if e["id"] in filter_eids]
            else:
                active_emails = self._cached_emails
        else:
            active_emails = self._cached_emails

        # Build NetworkX graph
        g = self.graph_builder.build_graph(
            emails=active_emails,
            email_iocs_map=self._cached_iocs_map,
            campaigns=self._current_campaigns,
            max_nodes=max_nodes,
        )

        total_nodes = g.number_of_nodes()
        total_edges = g.number_of_edges()
        total_camps = len(self._current_campaigns)

        type_counts: dict[str, int] = defaultdict(int)
        for _, data in g.nodes(data=True):
            type_counts[data.get("entity_type", "other")] += 1

        # Real node/cluster counts in the header instead of hardcoded text
        self.graph_stats_label.setText(
            f"Active Graph: {total_nodes} Nodes • {total_edges} Edges • {total_camps} Campaigns Clustered "
            f"({type_counts['email']} Emails, {type_counts['sender']} Senders, "
            f"{type_counts['ip']} IPs, {type_counts['domain']} Domains, "
            f"{type_counts['hash']} Hashes, {type_counts['url']} URLs)"
        )

        # Generate Pyvis HTML and render in QWebEngineView
        html = self.graph_builder.generate_html()
        self._ensure_graph_web_view()
        if self.graph_web_view is not None and os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            self.graph_web_view.setHtml(html)

        self.on_graph_node_deselected()

    def on_graph_node_clicked(self, node_id: str) -> None:
        """Populate the details drawer when a user clicks any node in the pyvis graph."""
        details = self.graph_builder.get_node_details(node_id)
        if not details:
            return

        if not self.graph_drawer.isVisible():
            self.set_graph_drawer_visible(True)

        while self.graph_drawer_vbox.count():
            item = self.graph_drawer_vbox.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        # 1. Type Badge & Risk Severity Badge
        top_row = QHBoxLayout()
        type_badge = QLabel(f" {details.entity_type.upper()} ")
        col = ENTITY_COLORS.get(details.entity_type, "#94a3b8")
        type_badge.setStyleSheet(f"""
            background-color: rgba(255, 255, 255, 0.08);
            color: {col};
            border: 1px solid {col};
            border-radius: 5px;
            font-size: 11px;
            font-weight: 800;
            padding: 3px 8px;
        """)
        top_row.addWidget(type_badge)
        top_row.addStretch()
        top_row.addWidget(RiskBadge(details.severity))
        self.graph_drawer_vbox.addLayout(top_row)

        # 2. Entity Value / Identifier with Copy Buttons
        val_box = QFrame()
        val_box.setStyleSheet("background-color: #1a1d24; border: 1px solid #2a3242; border-radius: 8px; padding: 10px;")
        vb_layout = QVBoxLayout(val_box)
        vb_layout.setContentsMargins(10, 8, 10, 8)
        vb_layout.setSpacing(6)

        val_title = QLabel(details.label)
        val_title.setStyleSheet("color: #f1f5f9; font-size: 14px; font-weight: 800;")
        val_title.setWordWrap(True)
        vb_layout.addWidget(val_title)

        if details.value and details.value != details.label:
            val_sub = QLabel(details.value)
            val_sub.setStyleSheet("color: #94a3b8; font-size: 11px; font-family: monospace;")
            val_sub.setWordWrap(True)
            vb_layout.addWidget(val_sub)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        copy_btn = QPushButton("📋 Copy Value")
        copy_btn.setFixedHeight(28)
        copy_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #202530; color: #94a3b8;
                border: 1px solid #2a3242; border-radius: 5px; font-size: 11px; font-weight: 600;
            }
            QPushButton:hover { background-color: #2a3242; color: #ffffff; }
        """)
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(details.value))
        btn_row.addWidget(copy_btn)

        if details.entity_type in ("ip", "domain", "url", "hash"):
            defang_btn = QPushButton("🛡️ Copy Defanged")
            defang_btn.setFixedHeight(28)
            defang_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            defang_btn.setStyleSheet("""
                QPushButton {
                    background-color: #202530; color: #00f0ff;
                    border: 1px solid rgba(0, 240, 255, 0.4); border-radius: 5px; font-size: 11px; font-weight: 600;
                }
                QPushButton:hover { background-color: rgba(0, 240, 255, 0.15); color: #ffffff; }
            """)
            defang_btn.clicked.connect(lambda: QApplication.clipboard().setText(defang(details.value)))
            btn_row.addWidget(defang_btn)

        vb_layout.addLayout(btn_row)
        self.graph_drawer_vbox.addWidget(val_box)

        # 3. Risk Assessment Section
        risk_frame = QFrame()
        risk_frame.setStyleSheet("background-color: #1a1d24; border: 1px solid #2a3242; border-radius: 8px; padding: 10px;")
        rf_layout = QVBoxLayout(risk_frame)
        rf_layout.setContentsMargins(10, 8, 10, 8)
        rf_layout.setSpacing(6)

        rf_hdr = QLabel(f"Risk Score: {details.risk_score:.1f} / 100")
        rf_hdr.setStyleSheet("color: #e2e8f0; font-size: 12px; font-weight: 700;")
        rf_layout.addWidget(rf_hdr)

        pbar = QProgressBar()
        pbar.setRange(0, 100)
        pbar.setValue(int(details.risk_score))
        pbar.setFixedHeight(8)
        pbar.setTextVisible(False)
        bar_col = "#ef4444" if details.risk_score >= 75 else "#f97316" if details.risk_score >= 50 else "#eab308" if details.risk_score >= 25 else "#10b981"
        pbar.setStyleSheet(f"""
            QProgressBar {{ background-color: #222836; border-radius: 4px; border: none; }}
            QProgressBar::chunk {{ background-color: {bar_col}; border-radius: 4px; }}
        """)
        rf_layout.addWidget(pbar)
        self.graph_drawer_vbox.addWidget(risk_frame)

        # 4. Associated Campaigns
        if details.campaign_ids:
            camp_frame = QFrame()
            camp_frame.setStyleSheet("background-color: #1a1d24; border: 1px solid #2a3242; border-radius: 8px; padding: 10px;")
            cf_layout = QVBoxLayout(camp_frame)
            cf_layout.setContentsMargins(10, 8, 10, 8)
            cf_layout.setSpacing(6)

            cf_hdr = QLabel("Associated Campaign(s)")
            cf_hdr.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 700; text-transform: uppercase;")
            cf_layout.addWidget(cf_hdr)

            tags_layout = QHBoxLayout()
            tags_layout.setSpacing(6)
            for cid in details.campaign_ids:
                tag = QLabel(cid)
                tag.setStyleSheet("""
                    background-color: rgba(0, 240, 255, 0.15);
                    color: #00f0ff;
                    border: 1px solid rgba(0, 240, 255, 0.4);
                    border-radius: 4px;
                    font-size: 11px;
                    font-weight: 700;
                    padding: 2px 6px;
                """)
                tags_layout.addWidget(tag)
            tags_layout.addStretch()
            cf_layout.addLayout(tags_layout)
            self.graph_drawer_vbox.addWidget(camp_frame)

        # 5. Metadata Context
        if details.metadata:
            meta_frame = QFrame()
            meta_frame.setStyleSheet("background-color: #1a1d24; border: 1px solid #2a3242; border-radius: 8px; padding: 10px;")
            mf_layout = QVBoxLayout(meta_frame)
            mf_layout.setContentsMargins(10, 8, 10, 8)
            mf_layout.setSpacing(6)

            mf_hdr = QLabel("Entity Context")
            mf_hdr.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 700; text-transform: uppercase;")
            mf_layout.addWidget(mf_hdr)

            for k, v in details.metadata.items():
                if v and not isinstance(v, (dict, list)):
                    row = QHBoxLayout()
                    lbl_k = QLabel(k.replace('_', ' ').capitalize() + ":")
                    lbl_k.setStyleSheet("color: #64748b; font-size: 11px;")
                    lbl_v = QLabel(str(v))
                    lbl_v.setStyleSheet("color: #cbd5e1; font-size: 11px; font-weight: 600;")
                    lbl_v.setWordWrap(True)
                    row.addWidget(lbl_k)
                    row.addWidget(lbl_v, 1)
                    mf_layout.addLayout(row)
            self.graph_drawer_vbox.addWidget(meta_frame)

        # 6. Connected Entities List
        conn_frame = QFrame()
        conn_frame.setStyleSheet("background-color: #1a1d24; border: 1px solid #2a3242; border-radius: 8px; padding: 10px;")
        con_layout = QVBoxLayout(conn_frame)
        con_layout.setContentsMargins(10, 8, 10, 8)
        con_layout.setSpacing(8)

        con_hdr = QLabel(f"Connected Entities ({details.degree})")
        con_hdr.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 700; text-transform: uppercase;")
        con_layout.addWidget(con_hdr)

        for conn in details.connected_nodes[:15]:
            c_row = QHBoxLayout()
            c_row.setSpacing(6)
            c_type = conn["type"]
            c_col = ENTITY_COLORS.get(c_type, "#94a3b8")

            rel_lbl = QLabel(conn["relationship"])
            rel_lbl.setStyleSheet("color: #64748b; font-size: 10px; font-weight: 700;")
            c_row.addWidget(rel_lbl)

            lbl_node = QLabel(conn["label"])
            lbl_node.setStyleSheet(f"color: {c_col}; font-size: 11px; font-weight: 600;")
            lbl_node.setWordWrap(True)
            c_row.addWidget(lbl_node, 1)

            c_row.addWidget(RiskBadge(conn["severity"]))
            con_layout.addLayout(c_row)

        if len(details.connected_nodes) > 15:
            more_lbl = QLabel(f"+ {len(details.connected_nodes) - 15} additional connections")
            more_lbl.setStyleSheet("color: #64748b; font-size: 10px; font-style: italic;")
            con_layout.addWidget(more_lbl)

        self.graph_drawer_vbox.addWidget(conn_frame)
        self.graph_drawer_vbox.addStretch()

    def on_graph_node_deselected(self) -> None:
        """Reset drawer when no node is selected or on background click."""
        while self.graph_drawer_vbox.count():
            item = self.graph_drawer_vbox.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        self.graph_drawer_empty = QLabel(
            "Click any node in the graph (email, sender, IP, domain, hash, or URL) "
            "to inspect risk scoring breakdown, multi-signal correlations, and linked infrastructure."
        )
        self.graph_drawer_empty.setStyleSheet("color: #64748b; font-size: 13px; line-height: 1.5;")
        self.graph_drawer_empty.setWordWrap(True)
        self.graph_drawer_vbox.addWidget(self.graph_drawer_empty)
        self.graph_drawer_vbox.addStretch()

    def on_graph_filter_changed(self) -> None:
        """Re-render graph when campaign or entity limit filter changes."""
        self._render_active_graph()

    # =========================================================================
    # PAGE 3: INTEL PAGE (REAL ENRICHMENT STATUS & MITRE ATT&CK)
    # =========================================================================
    def create_intel_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("contentContainer")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(16)

        h = QLabel("Threat Intelligence Feeds & Tactics")
        h.setObjectName("headerTitle")
        sub = QLabel("Live reputation providers status and MITRE ATT&CK Enterprise Matrix behaviours")
        sub.setObjectName("headerSubtitle")
        layout.addWidget(h)
        layout.addWidget(sub)

        # 1. Real Provider Cards Grid
        feeds_title = QLabel("EXTERNAL INTEL PROVIDERS STATUS")
        feeds_title.setObjectName("metricSubTitle")
        layout.addWidget(feeds_title)

        self.feed_cards_grid = QGridLayout()
        self.feed_cards_grid.setSpacing(12)
        self.feed_status_widgets: dict[str, tuple[QLabel, QLabel]] = {}

        feed_specs = [
            ("virustotal", "VirusTotal v3", "Requires API Key"),
            ("abuseipdb",  "AbuseIPDB",    "Requires API Key"),
            ("otx",        "AlienVault OTX", "Requires API Key"),
            ("abusech",    "URLhaus / ThreatFox", "Public API (No Key)"),
            ("rdap",       "RDAP / WHOIS", "Public Protocol (No Key)"),
        ]

        for idx, (slug, name, key_req) in enumerate(feed_specs):
            card = QFrame()
            card.setObjectName("metricCard")
            card.setStyleSheet("""
                QFrame#metricCard {
                    background-color: #202530; border: 1px solid #2a3242;
                    border-radius: 8px; padding: 10px;
                }
            """)
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12, 10, 12, 10)
            cl.setSpacing(4)

            t = QLabel(name)
            t.setStyleSheet("font-size: 14px; font-weight: 700; color: #f1f5f9;")
            cl.addWidget(t)

            status_lbl = QLabel("Checking...")
            status_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #94a3b8;")
            cl.addWidget(status_lbl)

            cache_lbl = QLabel("0 cached queries in DB")
            cache_lbl.setStyleSheet("font-size: 11px; color: #64748b;")
            cl.addWidget(cache_lbl)

            test_btn = QPushButton("⚡ Test Connectivity")
            test_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            test_btn.setStyleSheet("""
                QPushButton {
                    background: #1e2432; color: #00f0ff; border: 1px solid #2d3748;
                    border-radius: 5px; font-size: 11px; font-weight: 600; padding: 4px;
                }
                QPushButton:hover { background: #283144; }
            """)
            test_btn.clicked.connect(lambda _, p=slug: self.handle_test_feed_connectivity(p))
            cl.addWidget(test_btn)

            self.feed_cards_grid.addWidget(card, idx // 3, idx % 3)
            self.feed_status_widgets[slug] = (status_lbl, cache_lbl)

        layout.addLayout(self.feed_cards_grid)

        # 2. Real MITRE ATT&CK Techniques Seen Table
        mitre_title = QLabel("OBSERVED MITRE ATT&CK TECHNIQUES")
        mitre_title.setObjectName("metricSubTitle")
        layout.addWidget(mitre_title)

        mitre_card = QFrame()
        mitre_card.setObjectName("tableContainer")
        mc_layout = QVBoxLayout(mitre_card)
        mc_layout.setContentsMargins(14, 12, 14, 12)
        mc_layout.setSpacing(8)

        self.mitre_table = QTableWidget()
        self.mitre_table.setObjectName("iocTable")
        self.mitre_table.setColumnCount(5)
        self.mitre_table.setHorizontalHeaderLabels([
            "Technique ID", "Technique Name", "Tactic", "Observed Trigger", "Corpus Status"
        ])
        self.mitre_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.mitre_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.mitre_table.setShowGrid(False)
        self.mitre_table.verticalHeader().setVisible(False)

        mhdr = self.mitre_table.horizontalHeader()
        mhdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        mhdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        mhdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        mhdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        mhdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        mc_layout.addWidget(self.mitre_table)
        layout.addWidget(mitre_card, 1)

        return page

    def load_intel_data(self) -> None:
        """Refresh real API status, DB cached counts, and observed ATT&CK techniques."""
        db = self.get_db()
        try:
            stats = db.get_enrichment_stats()

            for slug, (status_lbl, cache_lbl) in self.feed_status_widgets.items():
                p_stats = stats.get(slug, {})
                cached_cnt = p_stats.get("total", 0)
                mal_cnt = p_stats.get("malicious", 0)

                key = get_api_key(slug)
                if slug in ("abusech", "rdap"):
                    status_lbl.setText("● Active (Public Feed)")
                    status_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #10b981;")
                elif key:
                    status_lbl.setText("● Configured (Key in OS Keyring)")
                    status_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #10b981;")
                else:
                    status_lbl.setText("○ Not Configured (API Key Missing)")
                    status_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #f59e0b;")

                cache_lbl.setText(f"{cached_cnt:,} cached lookups ({mal_cnt:,} flagged malicious)")

            # Query real ATT&CK evidence in corpus
            all_techs = self.mitre_mapper.all_techniques()
            self.mitre_table.setRowCount(len(all_techs))

            email_with_urls = db._conn.execute("SELECT COUNT(*) FROM emails WHERE url_count > 0").fetchone()[0]
            email_with_att = db._conn.execute("SELECT COUNT(*) FROM emails WHERE attach_count > 0").fetchone()[0]

            for row_idx, tech in enumerate(all_techs):
                tid_item = QTableWidgetItem(tech.technique_id)
                tid_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
                tid_item.setForeground(QColor("#00f0ff"))
                self.mitre_table.setItem(row_idx, 0, tid_item)

                name_item = QTableWidgetItem(tech.name)
                name_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                self.mitre_table.setItem(row_idx, 1, name_item)

                tactic_item = QTableWidgetItem(tech.tactic)
                tactic_item.setFont(QFont("Segoe UI", 9))
                tactic_item.setForeground(QColor("#a78bfa"))
                self.mitre_table.setItem(row_idx, 2, tactic_item)

                tag_item = QTableWidgetItem(tech.behaviour_tag)
                tag_item.setFont(QFont("Consolas", 9))
                tag_item.setForeground(QColor("#94a3b8"))
                self.mitre_table.setItem(row_idx, 3, tag_item)

                # Real observation verdict
                is_observed = False
                obs_detail = "0 detections"
                if "link" in tech.behaviour_tag and email_with_urls > 0:
                    is_observed = True
                    obs_detail = f"Observed ({email_with_urls:,} emails)"
                elif "attachment" in tech.behaviour_tag and email_with_att > 0:
                    is_observed = True
                    obs_detail = f"Observed ({email_with_att:,} emails)"

                st_item = QTableWidgetItem(obs_detail)
                st_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                st_item.setForeground(QColor("#10b981" if is_observed else "#64748b"))
                self.mitre_table.setItem(row_idx, 4, st_item)

                self.mitre_table.setRowHeight(row_idx, 34)

        finally:
            db.close()

    def handle_test_feed_connectivity(self, provider_slug: str) -> None:
        """Run connectivity check against the provider API."""
        self.statusBar().showMessage(f"Testing {provider_slug} connectivity...", 4000)
        ok = False
        msg = ""

        try:
            if provider_slug == "virustotal":
                key = get_api_key("virustotal")
                p = VirusTotalProvider(key)
                ok, msg = p.test_connectivity()
            elif provider_slug == "abuseipdb":
                key = get_api_key("abuseipdb")
                p = AbuseIPDBProvider(key)
                ok, msg = p.test_connectivity()
            elif provider_slug == "otx":
                key = get_api_key("otx")
                p = OTXProvider(key)
                ok, msg = p.test_connectivity()
            elif provider_slug == "abusech":
                p = AbuseCHProvider()
                ok, msg = p.test_connectivity()
            elif provider_slug == "rdap":
                p = RDAPProvider()
                ok, msg = p.test_connectivity()
        except Exception as exc:  # noqa: BLE001
            ok, msg = False, str(exc)

        icon = "✓" if ok else "✕"
        QMessageBox.information(
            self, f"{provider_slug.upper()} Connectivity", f"{icon} {provider_slug.upper()}: {msg}"
        )
        self.load_intel_data()

    # =========================================================================
    # PAGE 4: CONFIG PAGE (API KEYS, WHITELIST, SCORE WEIGHTS)
    # =========================================================================
    def create_config_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("contentContainer")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(14)

        h = QLabel("System Configuration & Heuristics")
        h.setObjectName("headerTitle")
        sub = QLabel("API keys via OS keyring, context-aware whitelist editor, and scoring model weights")
        sub.setObjectName("headerSubtitle")
        layout.addWidget(h)
        layout.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        container = QWidget()
        c_layout = QVBoxLayout(container)
        c_layout.setContentsMargins(0, 0, 0, 0)
        c_layout.setSpacing(16)

        # 1. API Keys Management Card
        api_card = QFrame()
        api_card.setObjectName("tableContainer")
        ac_layout = QVBoxLayout(api_card)
        ac_layout.setContentsMargins(18, 14, 18, 14)
        ac_layout.setSpacing(12)

        ac_title = QLabel("THREAT INTELLIGENCE API KEYS (SECURE OS KEYRING)")
        ac_title.setObjectName("sectionTitle")
        ac_layout.addWidget(ac_title)

        self.key_inputs: dict[str, QLineEdit] = {}
        self.key_status_labels: dict[str, QLabel] = {}

        for slug, label in [
            ("virustotal", "VirusTotal v3 API Key"),
            ("abuseipdb", "AbuseIPDB API Key"),
            ("otx", "AlienVault OTX API Key"),
        ]:
            row = QVBoxLayout()
            row.setSpacing(4)
            lbl = QLabel(label)
            lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #cbd5e1;")
            row.addWidget(lbl)

            input_row = QHBoxLayout()
            inp = QLineEdit()
            inp.setObjectName("searchBar")
            inp.setEchoMode(QLineEdit.EchoMode.Password)
            inp.setPlaceholderText(f"Paste your {label} here...")
            inp.setFixedHeight(36)
            input_row.addWidget(inp, 1)

            save_btn = QPushButton("Save Key")
            save_btn.setFixedHeight(36)
            save_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            save_btn.setStyleSheet("""
                QPushButton {
                    background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid #00f0ff;
                    border-radius: 6px; font-weight: 700; font-size: 11px; padding: 0px 14px;
                }
                QPushButton:hover { background: #00f0ff; color: #0a0e17; }
            """)
            save_btn.clicked.connect(lambda _, p=slug: self.handle_save_api_key(p))
            input_row.addWidget(save_btn)

            test_btn = QPushButton("Test")
            test_btn.setFixedHeight(36)
            test_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            test_btn.setStyleSheet("""
                QPushButton {
                    background: #1e2432; color: #94a3b8; border: 1px solid #2d3748;
                    border-radius: 6px; font-weight: 600; font-size: 11px; padding: 0px 12px;
                }
                QPushButton:hover { background: #283144; color: #f1f5f9; }
            """)
            test_btn.clicked.connect(lambda _, p=slug: self.handle_test_feed_connectivity(p))
            input_row.addWidget(test_btn)

            row.addLayout(input_row)

            st_lbl = QLabel("Status: Checking...")
            st_lbl.setStyleSheet("color: #64748b; font-size: 11px;")
            row.addWidget(st_lbl)

            ac_layout.addLayout(row)
            self.key_inputs[slug] = inp
            self.key_status_labels[slug] = st_lbl

        c_layout.addWidget(api_card)

        # 2. Whitelist YAML Editor Card
        wl_card = QFrame()
        wl_card.setObjectName("tableContainer")
        wc_layout = QVBoxLayout(wl_card)
        wc_layout.setContentsMargins(18, 14, 18, 14)
        wc_layout.setSpacing(10)

        wc_title = QLabel("CONTEXT-AWARE WHITELIST (data/whitelist.yaml)")
        wc_title.setObjectName("sectionTitle")
        wc_layout.addWidget(wc_title)

        wc_sub = QLabel("Edit allowed relay domains, body URL benign domains, and false-positive filter rules.")
        wc_sub.setStyleSheet("color: #94a3b8; font-size: 11px;")
        wc_layout.addWidget(wc_sub)

        self.whitelist_editor = QPlainTextEdit()
        self.whitelist_editor.setFixedHeight(220)
        wc_layout.addWidget(self.whitelist_editor)

        wl_btn_row = QHBoxLayout()
        save_wl_btn = QPushButton("💾 Save Whitelist YAML")
        save_wl_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        save_wl_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid #00f0ff;
                border-radius: 6px; font-weight: 700; font-size: 11px; padding: 6px 14px;
            }
            QPushButton:hover { background: #00f0ff; color: #0a0e17; }
        """)
        save_wl_btn.clicked.connect(self.handle_save_whitelist)
        wl_btn_row.addWidget(save_wl_btn)

        reload_wl_btn = QPushButton("🔄 Reload Whitelist")
        reload_wl_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        reload_wl_btn.clicked.connect(self.handle_reload_whitelist)
        wl_btn_row.addWidget(reload_wl_btn)
        wl_btn_row.addStretch()

        wc_layout.addLayout(wl_btn_row)
        c_layout.addWidget(wl_card)

        # 3. Score Weights YAML Editor Card
        weights_card = QFrame()
        weights_card.setObjectName("tableContainer")
        wec_layout = QVBoxLayout(weights_card)
        wec_layout.setContentsMargins(18, 14, 18, 14)
        wec_layout.setSpacing(10)

        wec_title = QLabel("RISK SCORING WEIGHTS (data/scoring_weights.yaml)")
        wec_title.setObjectName("sectionTitle")
        wec_layout.addWidget(wec_title)

        wec_sub = QLabel("Retune point caps, thresholds, and penalty contributions without editing code.")
        wec_sub.setStyleSheet("color: #94a3b8; font-size: 11px;")
        wec_layout.addWidget(wec_sub)

        self.weights_editor = QPlainTextEdit()
        self.weights_editor.setFixedHeight(220)
        wec_layout.addWidget(self.weights_editor)

        w_btn_row = QHBoxLayout()
        save_w_btn = QPushButton("💾 Save Scoring Weights")
        save_w_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        save_w_btn.setStyleSheet("""
            QPushButton {
                background: rgba(0, 240, 255, 0.15); color: #00f0ff; border: 1px solid #00f0ff;
                border-radius: 6px; font-weight: 700; font-size: 11px; padding: 6px 14px;
            }
            QPushButton:hover { background: #00f0ff; color: #0a0e17; }
        """)
        save_w_btn.clicked.connect(self.handle_save_weights)
        w_btn_row.addWidget(save_w_btn)

        reload_w_btn = QPushButton("🔄 Reload Weights")
        reload_w_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        reload_w_btn.clicked.connect(self.handle_reload_weights)
        w_btn_row.addWidget(reload_w_btn)
        w_btn_row.addStretch()

        wec_layout.addLayout(w_btn_row)
        c_layout.addWidget(weights_card)

        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

        return page

    def load_config_data(self) -> None:
        """Load API keys status and YAML files into editors."""
        for slug, st_lbl in self.key_status_labels.items():
            key = get_api_key(slug)
            if key:
                masked = key[:4] + "••••" + key[-4:] if len(key) > 8 else "••••••••"
                st_lbl.setText(f"✓ Configured in OS Keyring ({masked})")
                st_lbl.setStyleSheet("color: #10b981; font-size: 11px; font-weight: 600;")
            else:
                st_lbl.setText("✕ Not configured")
                st_lbl.setStyleSheet("color: #f59e0b; font-size: 11px;")

        self.handle_reload_whitelist()
        self.handle_reload_weights()

    def handle_save_api_key(self, slug: str) -> None:
        inp = self.key_inputs.get(slug)
        if not inp:
            return

        key = inp.text().strip()
        if not key:
            QMessageBox.warning(self, "Invalid Key", f"Please enter a valid key for {slug}.")
            return

        ok = set_api_key(slug, key)
        if ok:
            inp.clear()
            self.statusBar().showMessage(f"✓ Saved {slug} API key to OS Keyring.", 4000)
            self.load_config_data()
        else:
            QMessageBox.critical(self, "Keyring Error", f"Failed to store {slug} key in OS Keyring.")

    def handle_save_whitelist(self) -> None:
        text = self.whitelist_editor.toPlainText()
        try:
            yaml.safe_load(text)
            with open(_WHITELIST_PATH, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.statusBar().showMessage("✓ Saved data/whitelist.yaml successfully.", 4000)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "YAML Syntax Error", f"Cannot save invalid YAML:\n{exc}")

    def handle_reload_whitelist(self) -> None:
        if _WHITELIST_PATH.is_file():
            with open(_WHITELIST_PATH, encoding="utf-8") as fh:
                self.whitelist_editor.setPlainText(fh.read())

    def handle_save_weights(self) -> None:
        text = self.weights_editor.toPlainText()
        try:
            yaml.safe_load(text)
            with open(_WEIGHTS_PATH, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.scorer = RiskScorer(weights_path=_WEIGHTS_PATH)
            self.statusBar().showMessage("✓ Saved scoring weights and re-initialized RiskScorer.", 4000)
            self.load_dash_data()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "YAML Syntax Error", f"Cannot save invalid YAML:\n{exc}")

    def handle_reload_weights(self) -> None:
        if _WEIGHTS_PATH.is_file():
            with open(_WEIGHTS_PATH, encoding="utf-8") as fh:
                self.weights_editor.setPlainText(fh.read())

    # =========================================================================
    # GLOBAL REFRESH & PROGRESS HELPERS
    # =========================================================================
    def refresh_all_data(self, db: Database | None = None) -> None:
        """Global refresh called after a scan completes."""
        self.load_dash_data()
        self.load_cases_data()
        self.load_intel_data()
        if hasattr(self, "stacked_widget") and self.stacked_widget.currentIndex() == 2:
            self.load_graph_data()

    def populate_table_from_db(self, db: Database) -> None:
        """Backward-compatibility hook for main.py."""
        self.load_dash_data()

    def update_kpi_from_db(self, db: Database) -> None:
        """Backward-compatibility hook for main.py."""
        self.refresh_all_data()

    def show_scan_progress(self) -> None:
        self.progress_bar.setValue(0)
        self.progress_label.setText("Starting scan...")
        self.progress_frame.setVisible(True)
        self.analyze_button.setEnabled(False)
        self.analyze_button.setText("⏳ Scanning...")

    def update_scan_progress(self, current: int, total: int, filename: str) -> None:
        if total > 0:
            self.progress_bar.setValue(int((current / total) * 100))
        self.progress_label.setText(f"({current}/{total})  {filename}")

    def hide_scan_progress(self, result: dict | None = None) -> None:
        self.progress_frame.setVisible(False)
        self.analyze_button.setEnabled(True)
        self.analyze_button.setText("Select .eml Folder & Analyze")

        if result:
            scanned = result.get("emails_scanned", 0)
            new = result.get("emails_new", 0)
            iocs = result.get("iocs_found", 0)
            cancelled = result.get("cancelled", False)
            status = "Cancelled" if cancelled else "Complete"
            self.statusBar().showMessage(
                f"Scan {status}: {scanned} scanned, {new} new emails, {iocs} IOCs.", 6000
            )
            self.refresh_all_data()
            # Show the "Add to Case" button after a successful scan
            if not cancelled and new > 0:
                self.add_to_case_btn.setVisible(True)
