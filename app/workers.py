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
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from PyQt6.QtCore import QThread, pyqtSignal

from core.parser.eml_parser import parse_eml_file
from core.storage.database import Database
from core.storage.ingest import ingest_parsed_email


class ScanWorker(QThread):
    """Background thread for .eml folder scanning and DB ingestion.

    Signals
    -------
    progress(current: int, total: int, filename: str)
        Emitted after each file is processed.
    finished(result: dict)
        Emitted when the scan completes (normally or cancelled).
        Keys: ``emails_scanned``, ``emails_new``, ``iocs_found``,
        ``cancelled``.
    error(message: str)
        Emitted if an unrecoverable exception occurs.
    """

    progress: pyqtSignal = pyqtSignal(int, int, str)   # current, total, filename
    finished: pyqtSignal = pyqtSignal(dict)             # result dict
    error:    pyqtSignal = pyqtSignal(str)              # error message

    def __init__(
        self,
        folder_path: str,
        db_path: str | None = None,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self._folder_path = folder_path
        self._db_path = db_path
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
        """Core scan loop."""
        folder = Path(self._folder_path)
        if not folder.is_dir():
            self.error.emit(f"Not a directory: {self._folder_path}")
            return

        eml_files = sorted(folder.glob("*.eml"))
        total = len(eml_files)

        if total == 0:
            self.finished.emit({
                "emails_scanned": 0,
                "emails_new": 0,
                "iocs_found": 0,
                "cancelled": False,
            })
            return

        # Each worker creates its own DB connection (WAL allows concurrent use)
        db = Database(self._db_path)
        email_count_before = db.get_email_count()
        ioc_count_before   = db.get_ioc_count()

        for idx, eml_path in enumerate(eml_files, start=1):
            if self._cancelled:
                break

            filename = eml_path.name
            self.progress.emit(idx, total, filename)

            try:
                parsed = parse_eml_file(eml_path)
                if parsed.file_sha256:
                    ingest_parsed_email(parsed, db)
            except Exception:  # noqa: BLE001
                # Single-file failures are non-fatal — skip and continue
                continue

        emails_now = db.get_email_count()
        iocs_now   = db.get_ioc_count()
        db.close()

        self.finished.emit({
            "emails_scanned": min(idx, total),   # type: ignore[possibly-undefined]
            "emails_new":     emails_now - email_count_before,
            "iocs_found":     iocs_now   - ioc_count_before,
            "cancelled":      self._cancelled,
        })
