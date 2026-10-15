"""
tests/test_workers.py
Tests for app/workers.py (ScanWorker, ExportWorker, EnrichWorker) and app/theme.py.
"""
from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.theme import DARK_THEME_QSS
from app.workers import EnrichWorker, ExportWorker, ScanWorker
from core.parser.eml_parser import parse_eml_file
from core.storage.database import Database
from core.storage.ingest import ingest_parsed_email


def test_theme_qss_defined():
    """Verify DARK_THEME_QSS is non-empty and contains key styling tokens."""
    assert isinstance(DARK_THEME_QSS, str)
    assert len(DARK_THEME_QSS) > 100
    assert "#1a1d24" in DARK_THEME_QSS
    assert "#00f0ff" in DARK_THEME_QSS
    assert "QMainWindow" in DARK_THEME_QSS


def test_scan_worker_non_directory(tmp_path: Path):
    """ScanWorker emits error if folder does not exist."""
    not_dir = tmp_path / "does_not_exist"
    worker = ScanWorker(str(not_dir))

    errors = []
    worker.error.connect(errors.append)
    worker.run()

    assert len(errors) == 1
    assert "Not a directory" in errors[0]


def test_scan_worker_empty_folder(tmp_path: Path):
    """ScanWorker completes cleanly with 0 scanned when no .eml files exist."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    worker = ScanWorker(str(empty_dir))

    results = []
    worker.finished.connect(results.append)
    worker.run()

    assert len(results) == 1
    assert results[0]["emails_scanned"] == 0
    assert results[0]["cancelled"] is False


def test_scan_worker_successful_scan(tmp_path: Path):
    """ScanWorker processes .eml files, emits progress, and finishes."""
    scan_dir = tmp_path / "emails"
    scan_dir.mkdir()
    (scan_dir / "msg1.eml").write_text("From: a@b.com\nSubject: Test 1\n\nhttp://link1.com\n", encoding="utf-8")
    (scan_dir / "msg2.eml").write_text("From: c@d.com\nSubject: Test 2\n\nhttp://link2.com\n", encoding="utf-8")

    db_path = str(tmp_path / "scan_worker.db")
    worker = ScanWorker(str(scan_dir), db_path=db_path)

    progress_events = []
    results = []
    worker.progress.connect(lambda cur, tot, name: progress_events.append((cur, tot, name)))
    worker.finished.connect(results.append)

    worker.run()

    assert len(progress_events) == 2
    assert len(results) == 1
    assert results[0]["emails_scanned"] == 2
    assert results[0]["emails_new"] == 2
    assert results[0]["cancelled"] is False


def test_scan_worker_cancellation(tmp_path: Path):
    """ScanWorker respects cancel() call."""
    scan_dir = tmp_path / "cancel_emails"
    scan_dir.mkdir()
    for i in range(5):
        (scan_dir / f"msg{i}.eml").write_text(f"From: user{i}@test.com\nSubject: T\n\nHello\n", encoding="utf-8")

    db_path = str(tmp_path / "cancel_worker.db")
    worker = ScanWorker(str(scan_dir), db_path=db_path)

    # Cancel before run
    worker.cancel()
    results = []
    worker.finished.connect(results.append)
    worker.run()

    assert len(results) == 1
    assert results[0]["cancelled"] is True


def test_export_worker_success(tmp_path: Path):
    """ExportWorker exports cases and emits finished."""
    db_path = str(tmp_path / "export_worker.db")
    db = Database(db_path)
    eml = tmp_path / "sample.eml"
    eml.write_text("From: x@y.com\nSubject: Exp\n\nhttp://bad.com\n", encoding="utf-8")
    parsed = parse_eml_file(eml)
    ingest_parsed_email(parsed, db)
    db.close()

    out_dir = str(tmp_path / "exports")
    worker = ExportWorker(out_dir, db_path=db_path)

    results = []
    worker.finished.connect(results.append)
    worker.run()

    assert len(results) == 1
    assert results[0]["error"] is None
    assert len(results[0]["files_written"]) > 0


def test_export_worker_error():
    """ExportWorker handles unhandled exception during export."""
    worker = ExportWorker("/invalid/path/that/cannot/exist/??<>*|")
    results = []
    worker.finished.connect(results.append)
    worker.run()

    assert len(results) == 1
    assert results[0]["error"] is not None


def test_enrich_worker(tmp_path: Path):
    """EnrichWorker enriches IOC, rescores, and emits results."""
    db_path = str(tmp_path / "enrich_worker.db")
    db = Database(db_path)
    ioc_id = db.upsert_ioc("domain", "evil-phish.net")
    db.close()

    worker = EnrichWorker(
        ioc_id=ioc_id,
        ioc_type="domain",
        ioc_value="evil-phish.net",
        frequency=2,
        db_path=db_path,
        force_refresh=False,
    )

    with patch("core.enrichment.manager.EnrichmentManager.enrich_ioc") as mock_enrich:
        mock_enrich.return_value = []
        results = []
        worker.finished.connect(results.append)
        worker.run()

        assert len(results) == 1
        assert results[0]["ioc_id"] == ioc_id
        assert results[0]["ioc_type"] == "domain"
        assert "score" in results[0]
        assert "breakdown" in results[0]
