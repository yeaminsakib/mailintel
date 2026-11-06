"""
core/storage/scan.py
Folder scanning shared by the GUI worker and the CLI.

* ``discover_eml_files`` - find ``.eml`` files (recursive, case-insensitive,
  symlinked folders are not followed, results are sorted).
* ``scan_folder``        - parse + ingest each file and return a
  :class:`ScanReport` that says exactly what happened to every file: new,
  duplicate, skipped (empty / too large) or failed.  Nothing is dropped
  silently.

Safety limits: files larger than ``MAX_EML_BYTES`` are skipped *before* they
are read, so a single huge file cannot exhaust memory.  Pure business logic:
no Qt imports, safe to call from any thread.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.ioc.whitelist import WhitelistPolicy
from core.parser.eml_parser import parse_eml_file

from .database import Database
from .ingest import ingest_parsed_email

logger = logging.getLogger(__name__)

#: Largest ``.eml`` file that will be read (bytes).  Mail with big attachments is
#: usually below this; anything bigger is reported and skipped.
MAX_EML_BYTES: int = 25 * 1024 * 1024

#: ``progress(current, total, filename)``
ProgressCallback = Callable[[int, int, str], None]

# Problem kinds
EMPTY = "empty"
TOO_LARGE = "too_large"
UNREADABLE = "unreadable"
ERROR = "error"


@dataclass
class FileProblem:
    """A file (or folder) that was not ingested, and why."""

    path: str
    kind: str       # EMPTY, TOO_LARGE, UNREADABLE or ERROR
    reason: str

    @property
    def name(self) -> str:
        return Path(self.path).name or self.path

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "name": self.name, "kind": self.kind, "reason": self.reason}


@dataclass
class ScanReport:
    """Outcome of one scan."""

    files_found: int = 0
    new_emails: int = 0
    duplicates: int = 0
    skipped: int = 0          # empty or too large
    failed: int = 0           # unreadable or an error while parsing/ingesting
    cancelled: bool = False
    email_ids: list[int] = field(default_factory=list)   # new + duplicate emails
    problems: list[FileProblem] = field(default_factory=list)

    @property
    def emails_read(self) -> int:
        """Emails that were actually read (new or already stored)."""
        return self.new_emails + self.duplicates

    @property
    def files_processed(self) -> int:
        return self.emails_read + self.skipped + self.failed

    def to_dict(self, max_problems: int = 100) -> dict[str, Any]:
        """Plain-dict form for Qt signals / JSON."""
        return {
            "files_found": self.files_found,
            "files_processed": self.files_processed,
            "emails_scanned": self.emails_read,
            "emails_new": self.new_emails,
            "emails_duplicate": self.duplicates,
            "files_skipped": self.skipped,
            "files_failed": self.failed,
            "cancelled": self.cancelled,
            "problems": [p.to_dict() for p in self.problems[:max_problems]],
            "problems_total": len(self.problems),
        }


def discover_eml_files(
    folder: str | Path,
    *,
    recursive: bool = True,
    limit: int = 0,
    problems: list[FileProblem] | None = None,
) -> list[Path]:
    """Return the ``.eml`` files below *folder*, sorted by path.

    * the extension match is case-insensitive (``.EML`` works on Linux too);
    * symlinks (files and folders) are not followed, so link loops are harmless;
    * folders that cannot be read are appended to *problems* when given;
    * ``limit > 0`` keeps only the first *limit* files.
    """
    root = Path(folder)

    def on_error(exc: OSError) -> None:
        if problems is not None:
            problems.append(FileProblem(str(getattr(exc, "filename", root)), UNREADABLE, f"cannot read folder: {exc.strerror or exc}"))

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error, followlinks=False):
        if not recursive:
            dirnames[:] = []
        for name in filenames:
            if name.lower().endswith(".eml"):
                full = Path(dirpath) / name
                if not full.is_symlink():
                    found.append(full)
    found.sort(key=lambda p: str(p).lower())
    return found[:limit] if limit > 0 else found


def scan_folder(
    folder: str | Path,
    db: Database,
    *,
    files: list[Path] | None = None,
    recursive: bool = True,
    limit: int = 0,
    max_file_bytes: int = MAX_EML_BYTES,
    progress: ProgressCallback | None = None,
    should_cancel: Callable[[], bool] | None = None,
    whitelist: WhitelistPolicy | None = None,
) -> ScanReport:
    """Parse and ingest every ``.eml`` below *folder* into *db*.

    Pass *files* (from :func:`discover_eml_files`) to avoid walking twice.
    Re-scanning is safe: an already stored email counts as a duplicate and
    leaves IOC frequencies unchanged.
    """
    report = ScanReport()
    if files is None:
        files = discover_eml_files(folder, recursive=recursive, limit=limit, problems=report.problems)
    report.files_found = len(files)
    total = len(files)

    for index, path in enumerate(files, start=1):
        if should_cancel is not None and should_cancel():
            report.cancelled = True
            break
        if progress is not None:
            progress(index, total, path.name)

        problem = _check_file(path, max_file_bytes)
        if problem is not None:
            _record(report, problem)
            continue

        try:
            parsed = parse_eml_file(path)
            if not parsed.file_sha256:  # parse_eml_file returns this when the file cannot be read
                _record(report, FileProblem(str(path), UNREADABLE, "file could not be read"))
                continue
            already_stored = db.email_exists(parsed.file_sha256)
            email_id = ingest_parsed_email(parsed, db, whitelist)
        except Exception as exc:  # one bad file must never stop the scan
            logger.debug("Failed to ingest %s: %s", path, exc, exc_info=True)
            _record(report, FileProblem(str(path), ERROR, f"{type(exc).__name__}: {exc}"))
            continue

        report.email_ids.append(email_id)
        if already_stored:
            report.duplicates += 1
        else:
            report.new_emails += 1

    db.batch_commit()
    return report


def _check_file(path: Path, max_file_bytes: int) -> FileProblem | None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return FileProblem(str(path), UNREADABLE, f"cannot stat file: {exc.strerror or exc}")
    if size == 0:
        return FileProblem(str(path), EMPTY, "file is empty (0 bytes)")
    if size > max_file_bytes:
        return FileProblem(
            str(path), TOO_LARGE,
            f"file is {size / 1_048_576:.1f} MB, limit is {max_file_bytes / 1_048_576:.0f} MB",
        )
    return None


def _record(report: ScanReport, problem: FileProblem) -> None:
    report.problems.append(problem)
    if problem.kind in (EMPTY, TOO_LARGE):
        report.skipped += 1
    else:
        report.failed += 1
