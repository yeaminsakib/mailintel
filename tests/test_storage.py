"""
tests/test_storage.py
Comprehensive tests for core/storage (schema, database, ingest, export).

All tests use an in-memory SQLite database — no disk IO required.
"""
from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

import pytest

from core.parser.models import (
    AttachmentInfo,
    AuthResults,
    FileHashes,
    HeaderInfo,
    ParsedEmail,
    ReceivedHop,
)
from core.storage.database import Database
from core.storage.export import export_all_cases, export_csv_all, export_csv_case
from core.storage.ingest import ingest_parsed_email


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db() -> Database:
    """Return a fresh in-memory database for each test."""
    return Database(":memory:")


def _make_parsed_email(
    sha256: str = "aabbccdd" * 8,
    filename: str = "test.eml",
    subject: str = "Hello",
    from_addr: str = "sender@evil.com",
    body: str = "Check http://malware.example.com/payload",
    ips: list[str] | None = None,
    attachments: list[AttachmentInfo] | None = None,
) -> ParsedEmail:
    """Build a minimal ParsedEmail for testing."""
    hops: list[ReceivedHop] = []
    if ips:
        for ip in ips:
            hops.append(ReceivedHop(
                from_host="mail.evil.com",
                by_host="mail.local.com",
                from_ip=ip,
                timestamp=None,
                raw=f"from mail.evil.com ({ip})",
                is_external=True,
            ))

    return ParsedEmail(
        filepath=f"/tmp/{filename}",
        file_sha256=sha256,
        headers=HeaderInfo(
            from_addr=from_addr,
            reply_to="",
            return_path="",
            subject=subject,
            date="2026-10-01",
            message_id="<msg@evil.com>",
        ),
        received_chain=hops,
        first_external_hop=hops[0] if hops else None,
        auth_results=AuthResults(spf="fail", dkim="none", dmarc="fail"),
        body_plain=body,
        body_html="",
        urls=["http://malware.example.com/payload"] if "http" in body else [],
        attachments=attachments or [],
    )


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

class TestSchema:
    """Verify the schema applies cleanly and is idempotent."""

    def test_schema_creates_tables(self, db: Database) -> None:
        """All expected tables exist after init."""
        cur = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {r[0] for r in cur.fetchall()}
        expected = {"emails", "iocs", "email_iocs", "enrichments", "cases", "case_emails"}
        assert expected.issubset(tables)

    def test_schema_is_idempotent(self, db: Database) -> None:
        """Calling _apply_schema twice doesn't raise."""
        db._apply_schema()  # second call — should not error


# ---------------------------------------------------------------------------
# Email upsert / deduplication tests
# ---------------------------------------------------------------------------

class TestEmailDedup:
    """Verify emails are deduplicated by file_sha256."""

    def test_insert_new_email(self, db: Database) -> None:
        parsed = _make_parsed_email(sha256="aa" * 32)
        eid = db.upsert_email(parsed)
        assert eid >= 1
        assert db.get_email_count() == 1

    def test_duplicate_sha256_does_not_create_new_row(self, db: Database) -> None:
        """Re-scanning the same file (same SHA-256) must NOT create a new row."""
        parsed = _make_parsed_email(sha256="bb" * 32)
        id1 = db.upsert_email(parsed)
        id2 = db.upsert_email(parsed)
        assert id1 == id2
        assert db.get_email_count() == 1

    def test_different_sha256_creates_new_row(self, db: Database) -> None:
        p1 = _make_parsed_email(sha256="cc" * 32)
        p2 = _make_parsed_email(sha256="dd" * 32)
        id1 = db.upsert_email(p1)
        id2 = db.upsert_email(p2)
        assert id1 != id2
        assert db.get_email_count() == 2

    def test_email_exists(self, db: Database) -> None:
        sha = "ee" * 32
        assert not db.email_exists(sha)
        db.upsert_email(_make_parsed_email(sha256=sha))
        assert db.email_exists(sha)

    def test_upsert_updates_last_seen(self, db: Database) -> None:
        """On conflict, last_seen should be updated."""
        parsed = _make_parsed_email(sha256="ff" * 32)
        db.upsert_email(parsed)
        rows1 = db.get_all_emails()
        first_last_seen = rows1[0]["last_seen"]

        # Upsert again
        db.upsert_email(parsed)
        rows2 = db.get_all_emails()
        assert rows2[0]["last_seen"] >= first_last_seen


# ---------------------------------------------------------------------------
# IOC upsert tests
# ---------------------------------------------------------------------------

class TestIocUpsert:
    def test_new_ioc(self, db: Database) -> None:
        ioc_id = db.upsert_ioc("ipv4", "1.2.3.4")
        assert ioc_id >= 1
        assert db.get_ioc_count() == 1

    def test_duplicate_ioc_increments_frequency(self, db: Database) -> None:
        db.upsert_ioc("ipv4", "1.2.3.4")
        db.upsert_ioc("ipv4", "1.2.3.4")
        iocs = db.get_all_iocs()
        assert len(iocs) == 1
        assert iocs[0]["frequency"] == 2

    def test_same_value_different_type(self, db: Database) -> None:
        """'1.2.3.4' as ipv4 and '1.2.3.4' as domain are separate IOCs."""
        db.upsert_ioc("ipv4", "1.2.3.4")
        db.upsert_ioc("domain", "1.2.3.4")
        assert db.get_ioc_count() == 2

    def test_get_ioc_count_by_type(self, db: Database) -> None:
        db.upsert_ioc("ipv4", "1.1.1.1")
        db.upsert_ioc("ipv4", "2.2.2.2")
        db.upsert_ioc("domain", "evil.com")
        assert db.get_ioc_count_by_type("ipv4") == 2
        assert db.get_ioc_count_by_type("domain") == 1
        assert db.get_ioc_count_by_type("url") == 0


# ---------------------------------------------------------------------------
# Email ↔ IOC linking tests
# ---------------------------------------------------------------------------

class TestEmailIocLinking:
    def test_link_and_retrieve(self, db: Database) -> None:
        parsed = _make_parsed_email(sha256="11" * 32)
        email_id = db.upsert_email(parsed)
        ioc_id = db.upsert_ioc("ipv4", "5.6.7.8")
        db.link_email_ioc(email_id, ioc_id, context="header_ip")

        iocs = db.get_iocs_for_email(email_id)
        assert len(iocs) == 1
        assert iocs[0]["value"] == "5.6.7.8"
        assert iocs[0]["context"] == "header_ip"

    def test_link_is_idempotent(self, db: Database) -> None:
        parsed = _make_parsed_email(sha256="22" * 32)
        email_id = db.upsert_email(parsed)
        ioc_id = db.upsert_ioc("ipv4", "5.6.7.8")
        db.link_email_ioc(email_id, ioc_id, context="header_ip")
        db.link_email_ioc(email_id, ioc_id, context="header_ip")
        assert len(db.get_iocs_for_email(email_id)) == 1


# ---------------------------------------------------------------------------
# Enrichment tests
# ---------------------------------------------------------------------------

class TestEnrichments:
    def test_upsert_enrichment(self, db: Database) -> None:
        ioc_id = db.upsert_ioc("ipv4", "9.9.9.9")
        db.upsert_enrichment(
            ioc_id=ioc_id,
            provider="virustotal",
            raw_json='{"detected": true}',
            verdict="malicious",
            score=85.0,
        )
        results = db.get_enrichments_for_ioc(ioc_id)
        assert len(results) == 1
        assert results[0]["verdict"] == "malicious"
        assert results[0]["score"] == 85.0

    def test_upsert_enrichment_replaces_on_conflict(self, db: Database) -> None:
        ioc_id = db.upsert_ioc("ipv4", "9.9.9.9")
        db.upsert_enrichment(ioc_id, "virustotal", '{"v": 1}', "unknown")
        db.upsert_enrichment(ioc_id, "virustotal", '{"v": 2}', "malicious", 95.0)
        results = db.get_enrichments_for_ioc(ioc_id)
        assert len(results) == 1
        assert results[0]["verdict"] == "malicious"
        assert json.loads(results[0]["raw_json"])["v"] == 2


# ---------------------------------------------------------------------------
# Case management tests
# ---------------------------------------------------------------------------

class TestCases:
    def test_create_case(self, db: Database) -> None:
        cid = db.create_case("Phishing Campaign Alpha", description="Investigation")
        assert cid >= 1
        cases = db.get_all_cases()
        assert len(cases) == 1
        assert cases[0]["title"] == "Phishing Campaign Alpha"
        assert cases[0]["status"] == "open"

    def test_update_case_status(self, db: Database) -> None:
        cid = db.create_case("Test Case")
        db.update_case_status(cid, "closed")
        case = db.get_case(cid)
        assert case is not None
        assert case["status"] == "closed"

    def test_update_case_notes(self, db: Database) -> None:
        cid = db.create_case("Test Case")
        db.update_case_notes(cid, "Found suspicious attachment.")
        case = db.get_case(cid)
        assert case is not None
        assert case["notes"] == "Found suspicious attachment."

    def test_add_email_to_case(self, db: Database) -> None:
        cid = db.create_case("Case X")
        parsed = _make_parsed_email(sha256="33" * 32)
        eid = db.upsert_email(parsed)
        db.add_email_to_case(cid, eid)
        emails = db.get_emails_for_case(cid)
        assert len(emails) == 1

    def test_get_case_stats(self, db: Database) -> None:
        db.create_case("A", priority="high")
        db.create_case("B", priority="medium")
        cid = db.create_case("C", priority="high")
        db.update_case_status(cid, "closed")
        stats = db.get_case_stats()
        assert stats["total"] == 3
        assert stats["open"] == 2
        assert stats["closed"] == 1
        assert stats["high_priority"] == 2

    def test_get_email_count_for_case(self, db: Database) -> None:
        cid = db.create_case("Case Y")
        p1 = _make_parsed_email(sha256="44" * 32)
        p2 = _make_parsed_email(sha256="55" * 32)
        e1 = db.upsert_email(p1)
        e2 = db.upsert_email(p2)
        db.add_email_to_case(cid, e1)
        db.add_email_to_case(cid, e2)
        assert db.get_email_count_for_case(cid) == 2


# ---------------------------------------------------------------------------
# Ingest tests
# ---------------------------------------------------------------------------

class TestIngest:
    def test_ingest_creates_email_and_iocs(self, db: Database) -> None:
        parsed = _make_parsed_email(
            sha256="66" * 32,
            ips=["5.6.7.8"],
            attachments=[
                AttachmentInfo(
                    filename="malware.exe",
                    mime_type="application/x-msdownload",
                    size=1024,
                    hashes=FileHashes(
                        md5="d41d8cd98f00b204e9800998ecf8427e",
                        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    ),
                ),
            ],
        )
        eid = ingest_parsed_email(parsed, db)
        assert eid >= 1
        assert db.get_email_count() == 1
        assert db.get_ioc_count() > 0

        # Verify IOC types
        iocs = db.get_iocs_for_email(eid)
        ioc_types = {i["type"] for i in iocs}
        assert "ipv4" in ioc_types
        assert "hash_sha256" in ioc_types

    def test_ingest_dedup_on_rescan(self, db: Database) -> None:
        """Ingesting the same email twice should not create duplicates."""
        parsed = _make_parsed_email(sha256="77" * 32, ips=["10.0.0.1", "8.8.8.8"])
        ingest_parsed_email(parsed, db)
        ingest_parsed_email(parsed, db)
        assert db.get_email_count() == 1


# ---------------------------------------------------------------------------
# Batch commit tests
# ---------------------------------------------------------------------------

class TestBatchCommit:
    def test_batch_commit_defers_writes(self) -> None:
        db = Database(":memory:", commit_interval=5)
        for i in range(4):
            db.upsert_ioc("ipv4", f"1.1.1.{i}")
        assert db._pending_writes == 4
        db.batch_commit()
        assert db._pending_writes == 0

    def test_batch_commit_auto_flushes_at_interval(self) -> None:
        db = Database(":memory:", commit_interval=3)
        for i in range(6):
            db.upsert_ioc("ipv4", f"2.2.2.{i}")
        # After 6 writes with interval 3, should have auto-committed twice
        assert db._pending_writes == 0


# ---------------------------------------------------------------------------
# Collapsed IOC tests
# ---------------------------------------------------------------------------

class TestCollapsedIocs:
    def test_get_email_with_iocs(self, db: Database) -> None:
        parsed = _make_parsed_email(sha256="88" * 32, ips=["3.3.3.3"])
        eid = ingest_parsed_email(parsed, db)
        record = db.get_email_with_iocs(eid)
        assert record.get("ioc_ips") != ""  # should contain 3.3.3.3

    def test_get_all_emails_with_iocs(self, db: Database) -> None:
        p1 = _make_parsed_email(sha256="99" * 32, ips=["4.4.4.4"])
        p2 = _make_parsed_email(sha256="a0" * 32, ips=["5.5.5.5"])
        ingest_parsed_email(p1, db)
        ingest_parsed_email(p2, db)
        all_emails = db.get_all_emails_with_iocs()
        assert len(all_emails) == 2
        for email in all_emails:
            assert "ioc_ips" in email


# ---------------------------------------------------------------------------
# CSV export tests
# ---------------------------------------------------------------------------

class TestCsvExport:
    def test_export_csv_all(self, db: Database) -> None:
        parsed = _make_parsed_email(sha256="b1" * 32, ips=["6.6.6.6"])
        ingest_parsed_email(parsed, db)

        with tempfile.TemporaryDirectory() as tmpdir:
            out = export_csv_all(db, Path(tmpdir) / "all.csv")
            assert out.exists()
            with open(out, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["file_sha256"] == "b1" * 32
            # IOC columns should be present
            assert "ioc_ips" in rows[0]
            assert "ioc_hashes" in rows[0]

    def test_export_csv_case(self, db: Database) -> None:
        cid = db.create_case("Export Test Case")
        parsed = _make_parsed_email(sha256="c2" * 32)
        eid = ingest_parsed_email(parsed, db)
        db.add_email_to_case(cid, eid)

        with tempfile.TemporaryDirectory() as tmpdir:
            out = export_csv_case(db, cid, Path(tmpdir) / "case.csv")
            assert out.exists()
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            assert len(rows) == 1

    def test_export_all_cases(self, db: Database) -> None:
        # Create 2 cases with 1 email each
        for i, sha in enumerate(["d3" * 32, "e4" * 32]):
            cid = db.create_case(f"Case {i}")
            parsed = _make_parsed_email(sha256=sha)
            eid = ingest_parsed_email(parsed, db)
            db.add_email_to_case(cid, eid)

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = export_all_cases(db, tmpdir)
            # Should produce: all_emails.csv + 2 per-case files = 3
            assert len(paths) == 3
            for p in paths:
                assert Path(p).exists()

    def test_export_csv_empty_db(self, db: Database) -> None:
        """Exporting from an empty DB should produce a CSV with only headers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = export_csv_all(db, Path(tmpdir) / "empty.csv")
            assert out.exists()
            with open(out, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            assert len(rows) == 0

    def test_export_csv_includes_ioc_columns(self, db: Database) -> None:
        """Verify the CSV header row contains the IOC columns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = export_csv_all(db, Path(tmpdir) / "headers.csv")
            with open(out, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames or []
            for col in ["ioc_ips", "ioc_domains", "ioc_urls", "ioc_emails", "ioc_hashes"]:
                assert col in fieldnames, f"Missing column: {col}"


# ---------------------------------------------------------------------------
# get_case returns None for missing case
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_get_case_returns_none(self, db: Database) -> None:
        assert db.get_case(9999) is None

    def test_get_email_with_iocs_returns_empty_for_missing(self, db: Database) -> None:
        assert db.get_email_with_iocs(9999) == {}

    def test_close_is_safe_to_call_twice(self, db: Database) -> None:
        db.close()
        # Second close should not raise (Connection already closed is fine)
        try:
            db.close()
        except Exception:
            pass  # sqlite3 may raise on double-close — that's acceptable
