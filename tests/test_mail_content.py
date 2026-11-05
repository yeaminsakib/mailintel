"""
tests/test_mail_content.py
Week-1 features: stored mail content, attachment metadata, mismatch flags,
domain IOCs, URL normalisation and the schema v1 -> v2 migration.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.ioc.whitelist import WhitelistPolicy
from core.parser.eml_parser import parse_eml_bytes
from core.parser.models import (
    AttachmentInfo,
    AuthResults,
    FileHashes,
    HeaderInfo,
    ParsedEmail,
    ReceivedHop,
)
from core.parser.text import MAX_BODY_CHARS, body_text_for_storage, html_to_text
from core.storage.database import Database
from core.storage.ingest import ingest_parsed_email
from core.storage.schema import SCHEMA_VERSION

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def db() -> Database:
    database = Database(":memory:")
    yield database
    database.close()


def _hop(host: str, ip: str, external: bool = True) -> ReceivedHop:
    return ReceivedHop(from_host=host, by_host="mx.corp.com", from_ip=ip, timestamp=None, raw="", is_external=external)


def _mail(
    sha: str = "11" * 32,
    *,
    subject: str = "Urgent invoice",
    from_addr: str = "Billing <billing@evil.org>",
    reply_to: str = "",
    return_path: str = "",
    body_plain: str = "Pay now: http://Pay.Evil.org:80/Login#top",
    body_html: str = "",
    urls: list[str] | None = None,
    hops: list[ReceivedHop] | None = None,
    attachments: list[AttachmentInfo] | None = None,
) -> ParsedEmail:
    return ParsedEmail(
        filepath=f"/mail/{sha[:4]}.eml",
        file_sha256=sha,
        headers=HeaderInfo(
            from_addr=from_addr, reply_to=reply_to, return_path=return_path,
            subject=subject, date="2026-10-01", message_id="<m@evil.org>",
        ),
        received_chain=hops or [],
        first_external_hop=(hops or [None])[0],
        auth_results=AuthResults(spf="fail", dkim="pass", dmarc="none"),
        body_plain=body_plain,
        body_html=body_html,
        urls=urls if urls is not None else ["http://Pay.Evil.org:80/Login#top"],
        attachments=attachments or [],
    )


def _att(name: str = "invoice.pdf.exe", tag: str = "a") -> AttachmentInfo:
    return AttachmentInfo(
        filename=name, mime_type="application/octet-stream", size=1234,
        hashes=FileHashes(md5=tag * 32, sha1=tag * 40, sha256=tag * 64),
    )


def _iocs(db: Database, itype: str) -> dict[str, dict]:
    return {i["value"]: i for i in db.get_all_iocs() if i["type"] == itype}


# ---------------------------------------------------------------------------
# HTML -> text
# ---------------------------------------------------------------------------

class TestBodyText:
    def test_html_is_reduced_to_visible_text(self) -> None:
        html = (
            "<html><head><title>T</title><style>p{color:red}</style></head><body>"
            "<script>alert(1)</script><p>Hello&nbsp;<b>world</b> &amp; co</p>"
            "<a href='http://x.example/a'>click</a><!-- hidden --></body></html>"
        )
        text = html_to_text(html)
        assert "Hello" in text and "world & co" in text and "click" in text
        for forbidden in ("alert", "color:red", "<", "hidden", "http://x.example"):
            assert forbidden not in text

    def test_malformed_html_does_not_raise(self) -> None:
        assert isinstance(html_to_text("<p><b>unclosed <i>tags &bogus; <"), str)
        assert html_to_text("") == ""

    def test_plain_body_is_preferred_over_html(self) -> None:
        assert body_text_for_storage("plain text", "<p>html text</p>") == "plain text"

    def test_html_used_when_plain_missing_or_blank(self) -> None:
        assert body_text_for_storage("", "<p>only html</p>") == "only html"
        assert body_text_for_storage("   \n ", "<p>only html</p>") == "only html"

    def test_body_is_capped(self) -> None:
        assert len(body_text_for_storage("x" * (MAX_BODY_CHARS + 5000), "")) == MAX_BODY_CHARS


# ---------------------------------------------------------------------------
# Stored mail content
# ---------------------------------------------------------------------------

class TestStoredContent:
    def test_content_columns_are_filled(self, db: Database) -> None:
        eid = ingest_parsed_email(_mail(reply_to="x@other.net", return_path="<b@third.io>"), db)
        row = db.get_email_with_iocs(eid)
        assert row["subject"] == "Urgent invoice"
        assert row["from_addr"] == "Billing <billing@evil.org>"
        assert "Pay now" in row["body_text"]
        assert row["reply_to_mismatch"] == 1
        assert row["return_path_mismatch"] == 1
        flags = json.loads(row["flags_json"])
        assert flags["auth_failures"] == ["spf"]
        assert {"urgency", "payment_invoice"} <= set(flags["subject_patterns"])

    def test_recent_emails_expose_list_columns(self, db: Database) -> None:
        ingest_parsed_email(_mail(), db)
        row = db.get_recent_emails(5)[0]
        assert row["subject"] == "Urgent invoice"
        assert row["from_addr"].endswith("<billing@evil.org>")
        assert row["reply_to_mismatch"] == 0

    def test_html_only_mail_stores_text_not_markup(self, db: Database) -> None:
        eid = ingest_parsed_email(
            _mail(sha="22" * 32, body_plain="", body_html="<script>x()</script><p>Click <b>here</b></p>"), db
        )
        body = db.get_email_with_iocs(eid)["body_text"]
        assert body == "Click here"

    def test_real_fixture_end_to_end(self, db: Database) -> None:
        parsed = parse_eml_bytes((FIXTURES / "07_reply_to_mismatch.eml").read_bytes())
        parsed.file_sha256 = "33" * 32
        row = db.get_email_with_iocs(ingest_parsed_email(parsed, db))
        assert row["reply_to_mismatch"] == 1
        assert row["subject"]


class TestAttachments:
    def test_attachment_metadata_is_stored(self, db: Database) -> None:
        eid = ingest_parsed_email(_mail(attachments=[_att("invoice.pdf.exe"), _att("notes.txt", "b")]), db)
        rows = db.get_attachments_for_email(eid)
        assert [r["filename"] for r in rows] == ["invoice.pdf.exe", "notes.txt"]
        assert rows[0]["size"] == 1234
        assert rows[0]["sha256"] == "a" * 64
        assert rows[0]["mime_type"] == "application/octet-stream"

    def test_reingest_does_not_duplicate_attachments(self, db: Database) -> None:
        mail = _mail(attachments=[_att()])
        ingest_parsed_email(mail, db)
        eid = ingest_parsed_email(mail, db)
        assert len(db.get_attachments_for_email(eid)) == 1

    def test_attachments_are_removed_with_their_email(self, db: Database) -> None:
        eid = ingest_parsed_email(_mail(attachments=[_att()]), db)
        db._conn.execute("DELETE FROM emails WHERE id = ?", (eid,))
        assert db.get_attachments_for_email(eid) == []


# ---------------------------------------------------------------------------
# Domain IOCs and URL normalisation
# ---------------------------------------------------------------------------

class TestDomainIocs:
    def test_domains_come_from_url_and_sender(self, db: Database) -> None:
        ingest_parsed_email(_mail(reply_to="r@replyhost.net"), db)
        domains = _iocs(db, "domain")
        assert {"pay.evil.org", "evil.org", "replyhost.net"} <= set(domains)

    def test_domain_contexts_are_recorded(self, db: Database) -> None:
        eid = ingest_parsed_email(_mail(), db)
        contexts = {(i["value"], i["context"]) for i in db.get_iocs_for_email(eid) if i["type"] == "domain"}
        assert ("pay.evil.org", "url_domain") in contexts
        assert ("evil.org", "sender_domain") in contexts

    def test_external_received_host_becomes_domain(self, db: Database) -> None:
        ingest_parsed_email(_mail(hops=[_hop("relay.bulk-sender.net", "198.51.100.7")]), db)
        assert "relay.bulk-sender.net" in _iocs(db, "domain")

    def test_internal_hosts_and_non_public_names_are_skipped(self, db: Database) -> None:
        hops = [_hop("fw.corp.local", "198.51.100.8"), _hop("mail.google.com", "198.51.100.9")]
        ingest_parsed_email(_mail(hops=hops), db)
        domains = _iocs(db, "domain")
        assert "fw.corp.local" not in domains
        assert "mail.google.com" not in domains  # whitelisted infrastructure

    def test_non_external_hop_host_is_skipped(self, db: Database) -> None:
        ingest_parsed_email(_mail(hops=[_hop("inner.relay-example.net", "10.0.0.5", external=False)]), db)
        assert "inner.relay-example.net" not in _iocs(db, "domain")

    def test_whitelisted_sender_domain_is_skipped(self, db: Database) -> None:
        ingest_parsed_email(_mail(from_addr="someone@gmail.com", urls=[], body_plain=""), db)
        assert "gmail.com" not in _iocs(db, "domain")
        assert "someone@gmail.com" not in _iocs(db, "email")

    def test_whitelisted_url_domain_skips_url_and_domain(self, db: Database) -> None:
        mail = _mail(urls=["https://www.w3.org/TR/html/"], body_plain="")
        ingest_parsed_email(mail, db, whitelist=WhitelistPolicy.load())
        assert "www.w3.org" not in _iocs(db, "domain")
        assert not _iocs(db, "url")

    def test_ip_hosts_do_not_create_domains(self, db: Database) -> None:
        ingest_parsed_email(_mail(urls=["http://203.0.113.50/login"], body_plain=""), db)
        assert "203.0.113.50" not in _iocs(db, "domain")
        assert "http://203.0.113.50/login" in _iocs(db, "url")

    def test_domain_counted_once_per_email_even_if_seen_twice(self, db: Database) -> None:
        # evil.org is both the sender domain and the host of a URL in the same mail
        ingest_parsed_email(_mail(urls=["http://evil.org/a", "http://evil.org/b"]), db)
        assert _iocs(db, "domain")["evil.org"]["frequency"] == 1

    def test_domain_frequency_counts_distinct_emails(self, db: Database) -> None:
        ingest_parsed_email(_mail(sha="aa" * 32), db)
        ingest_parsed_email(_mail(sha="bb" * 32), db)
        ingest_parsed_email(_mail(sha="aa" * 32), db)  # rescan: must not count
        assert _iocs(db, "domain")["evil.org"]["frequency"] == 2


class TestUrlNormalisationOnIngest:
    def test_url_is_stored_in_canonical_form(self, db: Database) -> None:
        ingest_parsed_email(_mail(), db)
        assert "http://pay.evil.org/Login" in _iocs(db, "url")

    def test_url_variants_are_one_ioc(self, db: Database) -> None:
        urls = ["http://Evil.org", "http://evil.org:80/", "HTTP://EVIL.ORG/#x"]
        ingest_parsed_email(_mail(urls=urls, body_plain=""), db)
        found = [u for u in _iocs(db, "url") if "evil.org" in u]
        assert found == ["http://evil.org/"]
        assert _iocs(db, "url")["http://evil.org/"]["frequency"] == 1


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------

_V1_EMAILS = """
CREATE TABLE emails (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_sha256   TEXT    NOT NULL UNIQUE,
    filename      TEXT    NOT NULL,
    filepath      TEXT    NOT NULL DEFAULT '',
    headers_json  TEXT    NOT NULL DEFAULT '{}',
    auth_json     TEXT    NOT NULL DEFAULT '{}',
    received_json TEXT    NOT NULL DEFAULT '[]',
    first_hop_ip  TEXT    NOT NULL DEFAULT '',
    url_count     INTEGER NOT NULL DEFAULT 0,
    attach_count  INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL
);
"""


@pytest.fixture
def v1_db_path(tmp_path: Path) -> Path:
    """A database file exactly as the previous version created it."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(_V1_EMAILS)
    conn.execute(
        "INSERT INTO emails (file_sha256, filename, first_seen, last_seen) VALUES (?, 'old.eml', 't', 't')",
        ("44" * 32,),
    )
    conn.commit()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    conn.close()
    return path


class TestMigration:
    def test_new_database_has_current_version(self, db: Database) -> None:
        assert db.schema_version() == SCHEMA_VERSION == 2

    def test_old_database_is_upgraded_in_place(self, v1_db_path: Path) -> None:
        database = Database(v1_db_path)
        try:
            assert database.schema_version() == SCHEMA_VERSION
            columns = {r["name"] for r in database._conn.execute("PRAGMA table_info(emails)")}
            assert {"subject", "from_addr", "body_text", "reply_to_mismatch",
                    "return_path_mismatch", "flags_json"} <= columns
            tables = {r["name"] for r in database._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            assert "attachments" in tables
            old = database.get_all_emails()
            assert [e["filename"] for e in old] == ["old.eml"]   # data kept
            assert old[0]["subject"] == "" and old[0]["flags_json"] == "{}"
        finally:
            database.close()

    def test_reopening_is_idempotent(self, v1_db_path: Path) -> None:
        Database(v1_db_path).close()
        database = Database(v1_db_path)  # second open must not try to re-add columns
        assert database.schema_version() == SCHEMA_VERSION
        database.close()

    def test_interrupted_upgrade_can_be_resumed(self, v1_db_path: Path) -> None:
        conn = sqlite3.connect(v1_db_path)
        conn.execute("ALTER TABLE emails ADD COLUMN subject TEXT NOT NULL DEFAULT ''")  # half-done
        conn.commit()
        conn.close()
        database = Database(v1_db_path)
        assert database.schema_version() == SCHEMA_VERSION
        database.close()

    def test_rescan_backfills_content_of_old_rows(self, v1_db_path: Path) -> None:
        database = Database(v1_db_path)
        try:
            ingest_parsed_email(_mail(sha="44" * 32, attachments=[_att()]), database)
            assert database.get_email_count() == 1
            row = database.get_all_emails()[0]
            assert row["subject"] == "Urgent invoice"
            assert "Pay now" in row["body_text"]
            assert len(database.get_attachments_for_email(row["id"])) == 1
        finally:
            database.close()
