"""
core/storage/export.py
CSV export utilities for MailIntel.

Functions
---------
export_csv_all(db, output_path)
    Write every stored email to a single cumulative CSV.

export_csv_case(db, case_id, output_path)
    Write all emails in a given case to a CSV.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .database import Database


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _row_to_csv_record(row: dict[str, Any]) -> dict[str, str]:
    """Flatten a database email row into a CSV-friendly flat dict.

    JSON blobs are unpacked to their most useful sub-fields.
    """
    headers: dict = json.loads(row.get("headers_json", "{}"))
    auth: dict    = json.loads(row.get("auth_json",    "{}"))

    return {
        "id":           str(row.get("id", "")),
        "file_sha256":  row.get("file_sha256", ""),
        "filename":     row.get("filename", ""),
        "filepath":     row.get("filepath", ""),
        "from":         headers.get("from_addr", ""),
        "reply_to":     headers.get("reply_to", ""),
        "return_path":  headers.get("return_path", ""),
        "subject":      headers.get("subject", ""),
        "date":         headers.get("date", ""),
        "message_id":   headers.get("message_id", ""),
        "spf":          auth.get("spf", "none"),
        "dkim":         auth.get("dkim", "none"),
        "dmarc":        auth.get("dmarc", "none"),
        "first_hop_ip": row.get("first_hop_ip", ""),
        "url_count":    str(row.get("url_count", 0)),
        "attach_count": str(row.get("attach_count", 0)),
        "first_seen":   row.get("first_seen", ""),
        "last_seen":    row.get("last_seen", ""),
    }


_CSV_FIELDNAMES: list[str] = [
    "id", "file_sha256", "filename", "filepath",
    "from", "reply_to", "return_path", "subject", "date", "message_id",
    "spf", "dkim", "dmarc",
    "first_hop_ip", "url_count", "attach_count",
    "first_seen", "last_seen",
]


def _write_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    """Write a list of email rows to *output_path* as CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(_row_to_csv_record(row))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_csv_all(db: Database, output_path: str | Path) -> Path:
    """Write all stored emails to a single cumulative CSV.

    Parameters
    ----------
    db : Database
        Open database instance.
    output_path : str or Path
        Destination file path.  Parent directories are created as needed.

    Returns
    -------
    Path
        Absolute path of the written file.
    """
    output_path = Path(output_path).resolve()
    rows = db.get_all_emails()
    _write_csv(rows, output_path)
    return output_path


def export_csv_case(db: Database, case_id: int, output_path: str | Path) -> Path:
    """Write all emails in *case_id* to a per-case CSV.

    Parameters
    ----------
    db : Database
        Open database instance.
    case_id : int
        Database row id of the case.
    output_path : str or Path
        Destination file path.  Parent directories are created as needed.

    Returns
    -------
    Path
        Absolute path of the written file.
    """
    output_path = Path(output_path).resolve()
    rows = db.get_emails_for_case(case_id)
    _write_csv(rows, output_path)
    return output_path
