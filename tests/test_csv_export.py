"""
tests/test_csv_export.py
CSV export: the new flag / attachment columns and spreadsheet-formula protection.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from core.parser.models import AttachmentInfo, AuthResults, FileHashes, HeaderInfo, ParsedEmail
from core.storage.database import Database
from core.storage.export import _CSV_FIELDNAMES, _cell, export_csv_all, export_csv_case
from core.storage.ingest import ingest_parsed_email


def _mail(sha: str, subject: str, from_addr: str, *, filename: str = "m.eml", **kw) -> ParsedEmail:
    attachments = kw.pop("attachments", [])
    return ParsedEmail(
        filepath=f"/mail/{filename}",
        file_sha256=sha * 32,
        headers=HeaderInfo(from_addr=from_addr, subject=subject, date="Mon, 02 Nov 2026 10:00:00 +0000",
                           message_id=f"<{sha}@x>", **kw),
        auth_results=AuthResults(spf="fail", dkim="pass", dmarc="fail"),
        body_plain="x",
        urls=["http://evil-pay.org/p"],
        attachments=attachments,
    )


def _read(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.fixture
def db() -> Database:
    database = Database(":memory:")
    att = AttachmentInfo("invoice.pdf.exe", "application/octet-stream", 10,
                         FileHashes("a" * 32, "a" * 40, "a" * 64))
    att2 = AttachmentInfo("notes.txt", "text/plain", 5, FileHashes("b" * 32, "b" * 40, "b" * 64))
    ingest_parsed_email(_mail("aa", "Urgent invoice overdue", "Bill <bill@evil-pay.org>", filename="bad.eml",
                              reply_to="x@other.net", attachments=[att, att2]), database)
    ingest_parsed_email(_mail("bb", '=HYPERLINK("http://evil.example","click")', "+cmd@evil.org",
                              filename="@sum.eml"), database)
    yield database
    database.close()


def test_new_columns_are_in_the_header_and_filled(db: Database, tmp_path: Path) -> None:
    out = export_csv_all(db, tmp_path / "all.csv")
    rows = {r["filename"]: r for r in _read(out)}
    bad = rows["bad.eml"]
    assert set(_CSV_FIELDNAMES) <= set(bad)
    assert bad["attachment_names"] == "invoice.pdf.exe; notes.txt"
    assert bad["attach_count"] == "2"
    assert bad["reply_to_mismatch"] == "yes"
    assert bad["return_path_mismatch"] == "no"
    assert bad["auth_failures"] == "spf, dmarc"
    assert "urgency" in bad["subject_patterns"] and "payment_invoice" in bad["subject_patterns"]
    assert "evil-pay.org" in bad["ioc_domains"]


def test_case_export_has_the_same_columns(db: Database, tmp_path: Path) -> None:
    case_id = db.create_case(title="T", description="", notes="", priority="low")
    db.add_email_to_case(case_id, db.get_all_emails()[0]["id"])
    out = export_csv_case(db, case_id, tmp_path / "case.csv")
    rows = _read(out)
    assert len(rows) == 1 and "attachment_names" in rows[0] and "auth_failures" in rows[0]


def test_formula_like_cells_are_neutralised(db: Database, tmp_path: Path) -> None:
    rows = {r["filename"].lstrip("'"): r for r in _read(export_csv_all(db, tmp_path / "all.csv"))}
    evil = rows["@sum.eml"]
    assert evil["subject"] == "'=HYPERLINK(\"http://evil.example\",\"click\")"
    assert evil["from"].startswith("'+cmd")
    assert evil["filename"] == "'@sum.eml"
    for row in rows.values():
        for column, value in row.items():
            assert not value.startswith(("=", "+", "@", "\t", "\r")), (column, value)


def test_normal_values_are_left_alone(db: Database, tmp_path: Path) -> None:
    bad = next(r for r in _read(export_csv_all(db, tmp_path / "all.csv")) if r["filename"] == "bad.eml")
    assert bad["subject"] == "Urgent invoice overdue"
    assert bad["file_sha256"] == "aa" * 32


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("=1+1", "'=1+1"), ("+49 123", "'+49 123"), ("-2+3", "'-2+3"), ("@SUM(A1)", "'@SUM(A1)"),
        ("\tTAB", "'\tTAB"), ("\rCR", "'\rCR"),
        ("plain", "plain"), ("", ""), (None, ""), (42, "42"), ("a=b", "a=b"),
    ],
)
def test_cell(raw, expected) -> None:
    assert _cell(raw) == expected
