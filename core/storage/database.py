"""
core/storage/database.py
Database access layer for MailIntel.

All reads and writes go through the :class:`Database` class.  It owns a
single ``sqlite3.Connection`` and exposes intent-revealing methods rather
than raw SQL.

Thread safety
-------------
SQLite connections are **not** thread-safe by default.  The worker thread
creates its own ``Database`` instance pointing at the same file; SQLite's
WAL mode allows concurrent readers alongside the single writer.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.parser.models import ParsedEmail
from .schema import SCHEMA_SQL


# Default DB path — resolved relative to the project root so tests can
# override it trivially by passing a tmp_path / :memory: connection.
_DEFAULT_DB_PATH: Path = (
    Path(__file__).resolve().parent.parent.parent / "mailintel.db"
)


def _now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Thin wrapper around ``sqlite3.Connection`` for MailIntel storage.

    Parameters
    ----------
    db_path : str or Path or ``None``
        Path to the SQLite file.  Pass ``':memory:'`` for an in-memory DB
        (useful in tests).  Defaults to ``mailintel.db`` in the project root.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            db_path = _DEFAULT_DB_PATH
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._apply_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _apply_schema(self) -> None:
        """Run all CREATE TABLE … IF NOT EXISTS statements."""
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    # ------------------------------------------------------------------
    # emails
    # ------------------------------------------------------------------

    def upsert_email(self, parsed: ParsedEmail) -> int:
        """Insert or update an email record; return its row id.

        The dedup key is ``file_sha256``.  If the email already exists,
        only ``last_seen`` and aggregate counts are updated.

        Parameters
        ----------
        parsed : ParsedEmail
            Fully parsed email from :mod:`core.parser`.

        Returns
        -------
        int
            The ``id`` of the (possibly pre-existing) emails row.
        """
        now = _now()
        headers_json = json.dumps(asdict(parsed.headers))
        auth_json    = json.dumps(asdict(parsed.auth_results))
        received_json = json.dumps([asdict(h) for h in parsed.received_chain])
        first_hop_ip = (
            parsed.first_external_hop.from_ip
            if parsed.first_external_hop and parsed.first_external_hop.from_ip
            else ""
        )

        cur = self._conn.execute(
            """
            INSERT INTO emails
                (file_sha256, filename, filepath, headers_json, auth_json,
                 received_json, first_hop_ip, url_count, attach_count,
                 first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (file_sha256) DO UPDATE SET
                last_seen    = excluded.last_seen,
                url_count    = excluded.url_count,
                attach_count = excluded.attach_count
            RETURNING id
            """,
            (
                parsed.file_sha256,
                Path(parsed.filepath).name if parsed.filepath else "",
                parsed.filepath,
                headers_json,
                auth_json,
                received_json,
                first_hop_ip,
                len(parsed.urls),
                len(parsed.attachments),
                now,
                now,
            ),
        )
        row = cur.fetchone()
        self._conn.commit()
        return row[0]

    def get_all_emails(self) -> list[dict[str, Any]]:
        """Return all email rows as plain dicts."""
        cur = self._conn.execute("SELECT * FROM emails ORDER BY first_seen DESC")
        return [dict(r) for r in cur.fetchall()]

    def get_email_count(self) -> int:
        """Return total number of unique emails stored."""
        cur = self._conn.execute("SELECT COUNT(*) FROM emails")
        return cur.fetchone()[0]

    # ------------------------------------------------------------------
    # iocs
    # ------------------------------------------------------------------

    def upsert_ioc(self, ioc_type: str, value: str) -> int:
        """Insert a new IOC or update its ``last_seen``/``frequency``.

        Parameters
        ----------
        ioc_type : str
            One of ``'ipv4'``, ``'ipv6'``, ``'domain'``, ``'url'``,
            ``'email'``, ``'hash_md5'``, ``'hash_sha1'``, ``'hash_sha256'``.
        value : str
            The IOC value (normalised by the caller).

        Returns
        -------
        int
            Row id of the (possibly pre-existing) iocs row.
        """
        now = _now()
        cur = self._conn.execute(
            """
            INSERT INTO iocs (type, value, frequency, first_seen, last_seen)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT (type, value) DO UPDATE SET
                frequency = frequency + 1,
                last_seen = excluded.last_seen
            RETURNING id
            """,
            (ioc_type, value, now, now),
        )
        row = cur.fetchone()
        self._conn.commit()
        return row[0]

    def get_all_iocs(self) -> list[dict[str, Any]]:
        """Return all IOC rows ordered by frequency descending."""
        cur = self._conn.execute(
            "SELECT * FROM iocs ORDER BY frequency DESC"
        )
        return [dict(r) for r in cur.fetchall()]

    def get_ioc_count(self) -> int:
        """Return total number of unique IOCs stored."""
        cur = self._conn.execute("SELECT COUNT(*) FROM iocs")
        return cur.fetchone()[0]

    def get_ioc_count_by_type(self, ioc_type: str) -> int:
        """Return count of IOCs of a given type."""
        cur = self._conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE type = ?", (ioc_type,)
        )
        return cur.fetchone()[0]

    # ------------------------------------------------------------------
    # email_iocs
    # ------------------------------------------------------------------

    def link_email_ioc(
        self, email_id: int, ioc_id: int, context: str = ""
    ) -> None:
        """Create an email↔IOC association (idempotent).

        Parameters
        ----------
        email_id : int
        ioc_id : int
        context : str
            Provenance label such as ``'body_url'``, ``'header_ip'``,
            ``'attachment_sha256'``.
        """
        self._conn.execute(
            """
            INSERT OR IGNORE INTO email_iocs (email_id, ioc_id, context)
            VALUES (?, ?, ?)
            """,
            (email_id, ioc_id, context),
        )
        self._conn.commit()

    def get_iocs_for_email(self, email_id: int) -> list[dict[str, Any]]:
        """Return all IOCs linked to a given email."""
        cur = self._conn.execute(
            """
            SELECT i.*, ei.context
            FROM iocs i
            JOIN email_iocs ei ON ei.ioc_id = i.id
            WHERE ei.email_id = ?
            ORDER BY i.frequency DESC
            """,
            (email_id,),
        )
        return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    # enrichments
    # ------------------------------------------------------------------

    def upsert_enrichment(
        self,
        ioc_id: int,
        provider: str,
        raw_json: str,
        verdict: str = "unknown",
        score: float | None = None,
    ) -> None:
        """Insert or replace an enrichment result for an IOC.

        Parameters
        ----------
        ioc_id : int
        provider : str
            Provider name, e.g. ``'virustotal'``.
        raw_json : str
            Full provider API response serialised as JSON.
        verdict : str
            Normalised verdict (``'malicious'``, ``'suspicious'``,
            ``'clean'``, ``'unknown'``).
        score : float or None
            Numeric score if the provider exposes one.
        """
        now = _now()
        self._conn.execute(
            """
            INSERT INTO enrichments
                (ioc_id, provider, raw_json, verdict, score, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (ioc_id, provider) DO UPDATE SET
                raw_json   = excluded.raw_json,
                verdict    = excluded.verdict,
                score      = excluded.score,
                fetched_at = excluded.fetched_at
            """,
            (ioc_id, provider, raw_json, verdict, score, now),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # cases
    # ------------------------------------------------------------------

    def create_case(
        self,
        title: str,
        description: str = "",
        priority: str = "medium",
    ) -> int:
        """Create a new investigation case and return its id."""
        now = _now()
        cur = self._conn.execute(
            """
            INSERT INTO cases (title, description, status, priority, created_at, updated_at)
            VALUES (?, ?, 'open', ?, ?, ?)
            RETURNING id
            """,
            (title, description, priority, now, now),
        )
        row = cur.fetchone()
        self._conn.commit()
        return row[0]

    def update_case_status(self, case_id: int, status: str) -> None:
        """Update a case's status (``'open'``, ``'closed'``, ``'archived'``)."""
        self._conn.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now(), case_id),
        )
        self._conn.commit()

    def get_all_cases(self) -> list[dict[str, Any]]:
        """Return all cases ordered by creation date descending."""
        cur = self._conn.execute("SELECT * FROM cases ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

    def add_email_to_case(self, case_id: int, email_id: int) -> None:
        """Associate an email with a case (idempotent)."""
        self._conn.execute(
            """
            INSERT OR IGNORE INTO case_emails (case_id, email_id, added_at)
            VALUES (?, ?, ?)
            """,
            (case_id, email_id, _now()),
        )
        self._conn.commit()

    def get_emails_for_case(self, case_id: int) -> list[dict[str, Any]]:
        """Return all emails linked to a specific case."""
        cur = self._conn.execute(
            """
            SELECT e.*
            FROM emails e
            JOIN case_emails ce ON ce.email_id = e.id
            WHERE ce.case_id = ?
            ORDER BY e.first_seen DESC
            """,
            (case_id,),
        )
        return [dict(r) for r in cur.fetchall()]
