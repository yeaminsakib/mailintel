"""tests/test_isolation.py - the test-suite must never touch the real database."""
from __future__ import annotations

from pathlib import Path

from app.dashboard import DashboardWindow
from core.storage.database import Database

REAL_DB = Path(__file__).resolve().parent.parent / "mailintel.db"


def test_default_database_is_redirected_away_from_project_root() -> None:
    db = Database()
    try:
        assert Path(db._path).resolve() != REAL_DB.resolve()
    finally:
        db.close()


def test_dashboard_default_path_is_redirected(qapp) -> None:
    window = DashboardWindow()
    assert Path(window.db_path).resolve() != REAL_DB.resolve()
