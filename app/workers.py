"""
app/workers.py
QThread-based background workers for MailIntel.

Rule: no business logic here — this module only wires Qt signals/slots
to functions in core/.  All DB writes happen in the worker thread; the
UI thread only receives signals.

Workers
-------
ScanWorker
    Scans a folder of .eml files, parses them, and writes results to the
    database.  Supports cancellation via :meth:`cancel`.

ExportWorker
    Exports all emails (and per-case CSVs) to a given directory.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from PyQt6.QtCore import QThread, pyqtSignal

from core.storage.database import Database
from core.storage.export import export_all_cases
from core.storage.scan import (
    MAX_EML_BYTES,
    FileProblem,
    ScanReport,
    discover_eml_files,
    scan_folder,
)


class ScanWorker(QThread):
    """Background thread for .eml folder scanning and DB ingestion.

    Uses batched DB commits (every 25 files) to reduce fsync overhead
    without losing data if the scan is cancelled.

    Signals
    -------
    progress(current: int, total: int, filename: str)
        Emitted after each file is processed.
    finished(result: dict)
        Emitted when the scan completes (normally or cancelled).
        Keys: ``emails_scanned`` (read, new + duplicate), ``emails_new``,
        ``emails_duplicate``, ``files_found``, ``files_skipped`` (empty / too
        large), ``files_failed``, ``problems`` (list of dicts, capped at 100),
        ``problems_total``, ``iocs_found``, ``cancelled``.
    error(message: str)
        Emitted if an unrecoverable exception occurs.
    """

    progress: pyqtSignal = pyqtSignal(int, int, str)   # current, total, filename
    finished: pyqtSignal = pyqtSignal(dict)             # result dict
    error:    pyqtSignal = pyqtSignal(str)              # error message

    _BATCH_SIZE: int = 25  # commit every N files

    def __init__(
        self,
        folder_path: str,
        db_path: str | None = None,
        parent: Any = None,
        *,
        recursive: bool = True,
        max_file_bytes: int = MAX_EML_BYTES,
    ) -> None:
        super().__init__(parent)
        self._folder_path = folder_path
        self._db_path = db_path
        self._recursive = recursive
        self._max_file_bytes = max_file_bytes
        self._cancelled = False

    def cancel(self) -> None:
        """Request cancellation.  The worker will stop after the current file."""
        self._cancelled = True

    def run(self) -> None:
        """Entry point — runs in the worker thread."""
        try:
            self._scan()
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))

    def _scan(self) -> None:
        """Discover the files, then parse + ingest them via the shared scanner."""
        folder = Path(self._folder_path)
        if not folder.is_dir():
            self.error.emit(f"Not a directory: {self._folder_path}")
            return

        problems: list[FileProblem] = []
        files = discover_eml_files(folder, recursive=self._recursive, problems=problems)

        if not files:
            self.finished.emit({
                **ScanReport(problems=problems).to_dict(),
                "iocs_found": 0,
            })
            return

        # The worker owns its own DB connection (WAL allows concurrent readers).
        # Batch commits cut fsync overhead; a cancelled scan keeps what it stored.
        db = Database(self._db_path, commit_interval=self._BATCH_SIZE)
        try:
            iocs_before = db.get_ioc_count()
            report = scan_folder(
                folder,
                db,
                files=files,
                max_file_bytes=self._max_file_bytes,
                progress=self.progress.emit,
                should_cancel=lambda: self._cancelled,
            )
            report.problems = problems + report.problems
            iocs_after = db.get_ioc_count()
        finally:
            db.close()

        self.finished.emit({**report.to_dict(), "iocs_found": iocs_after - iocs_before})


class ExportWorker(QThread):
    """Background thread for CSV export.

    Signals
    -------
    finished(result: dict)
        Emitted when the export completes.
        Keys: ``files_written`` (list[str]), ``error`` (str or None).
    """

    finished: pyqtSignal = pyqtSignal(dict)

    def __init__(
        self,
        output_dir: str,
        db_path: str | None = None,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self._output_dir = output_dir
        self._db_path = db_path

    def run(self) -> None:
        """Entry point — runs in the worker thread."""
        try:
            db = Database(self._db_path)
            paths = export_all_cases(db, self._output_dir)
            db.close()
            self.finished.emit({
                "files_written": [str(p) for p in paths],
                "error": None,
            })
        except Exception as exc:  # noqa: BLE001
            self.finished.emit({
                "files_written": [],
                "error": str(exc),
            })


class EnrichWorker(QThread):
    """Background thread for live IOC enrichment and risk re-scoring.

    Signals
    -------
    finished(data: dict)
        Emitted when enrichment and scoring finish.
    error(message: str)
        Emitted if an exception occurs.
    """

    finished: pyqtSignal = pyqtSignal(dict)
    error:    pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        ioc_id: int,
        ioc_type: str,
        ioc_value: str,
        frequency: int = 1,
        db_path: str | None = None,
        force_refresh: bool = True,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self._ioc_id = ioc_id
        self._ioc_type = ioc_type
        self._ioc_value = ioc_value
        self._frequency = frequency
        self._db_path = db_path
        self._force_refresh = force_refresh

    def run(self) -> None:
        try:
            from core.enrichment.manager import EnrichmentManager
            from core.scoring.risk_score import RiskScorer

            db = Database(self._db_path)
            manager = EnrichmentManager(db)
            manager.enrich_ioc(
                ioc_id=self._ioc_id,
                ioc_type=self._ioc_type,
                ioc_value=self._ioc_value,
                force_refresh=self._force_refresh,
            )

            stored_enrichments = db.get_enrichments_for_ioc(self._ioc_id)
            scorer = RiskScorer()
            score_obj = scorer.score_ioc(
                ioc_type=self._ioc_type,
                ioc_value=self._ioc_value,
                enrichment_results=stored_enrichments,
                frequency=self._frequency,
            )
            db.close()

            self.finished.emit({
                "ioc_id": self._ioc_id,
                "ioc_type": self._ioc_type,
                "ioc_value": self._ioc_value,
                "enrichments": stored_enrichments,
                "score": score_obj.score,
                "breakdown": [
                    {"factor": f.factor, "points": f.points, "reason": f.reason}
                    for f in score_obj.breakdown
                ],
                "behaviour_tags": score_obj.behaviour_tags,
            })
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
