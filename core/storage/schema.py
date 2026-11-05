"""
core/storage/schema.py
SQLite table definitions for MailIntel.

Tables
------
emails          – One row per unique .eml file (deduped by file_sha256).
attachments     – Name / type / size / hashes of each attachment of an email.
iocs            – One row per unique IOC (type, value) pair.
email_iocs      – Many-to-many join between emails and iocs.
enrichments     – Cached provider results keyed by (ioc_id, provider).
cases           – Analyst-managed investigation cases.
case_emails     – Many-to-many join between cases and emails.
"""
from __future__ import annotations

#: Current schema version, stored in ``PRAGMA user_version``.
#:   1 - original tables
#:   2 - mail content columns on ``emails`` + ``attachments`` table
SCHEMA_VERSION: int = 2

#: Columns added to ``emails`` in version 2: name -> column definition.
#: Used by :meth:`Database._migrate` to upgrade databases created by v1
#: (``CREATE TABLE IF NOT EXISTS`` does not alter an existing table).
EMAILS_V2_COLUMNS: dict[str, str] = {
    "subject":              "TEXT    NOT NULL DEFAULT ''",
    "from_addr":            "TEXT    NOT NULL DEFAULT ''",
    "body_text":            "TEXT    NOT NULL DEFAULT ''",   # plain text only, capped
    "reply_to_mismatch":    "INTEGER NOT NULL DEFAULT 0",
    "return_path_mismatch": "INTEGER NOT NULL DEFAULT 0",
    "flags_json":           "TEXT    NOT NULL DEFAULT '{}'",  # see core.ioc.flags.MailFlags
}

# All CREATE TABLE statements use IF NOT EXISTS — safe to call on every start.
SCHEMA_SQL: str = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- -------------------------------------------------------------------------
-- emails: one row per unique .eml file (deduped by file_sha256)
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS emails (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_sha256   TEXT    NOT NULL UNIQUE,   -- dedup key
    filename      TEXT    NOT NULL,
    filepath      TEXT    NOT NULL DEFAULT '',
    headers_json  TEXT    NOT NULL DEFAULT '{}',  -- JSON blob of HeaderInfo
    auth_json     TEXT    NOT NULL DEFAULT '{}',  -- JSON blob of AuthResults
    received_json TEXT    NOT NULL DEFAULT '[]',  -- JSON list of ReceivedHop dicts
    first_hop_ip  TEXT    NOT NULL DEFAULT '',    -- first_external_hop.from_ip
    url_count     INTEGER NOT NULL DEFAULT 0,
    attach_count  INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT    NOT NULL,               -- ISO-8601
    last_seen     TEXT    NOT NULL,               -- updated on re-scan
    -- schema v2 (kept in sync with EMAILS_V2_COLUMNS)
    subject              TEXT    NOT NULL DEFAULT '',
    from_addr            TEXT    NOT NULL DEFAULT '',
    body_text            TEXT    NOT NULL DEFAULT '',
    reply_to_mismatch    INTEGER NOT NULL DEFAULT 0,
    return_path_mismatch INTEGER NOT NULL DEFAULT 0,
    flags_json           TEXT    NOT NULL DEFAULT '{}'
);

-- -------------------------------------------------------------------------
-- attachments: metadata + hashes only; the bytes are never stored
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attachments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id   INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    filename   TEXT    NOT NULL,
    mime_type  TEXT    NOT NULL DEFAULT '',
    size       INTEGER NOT NULL DEFAULT 0,
    md5        TEXT    NOT NULL DEFAULT '',
    sha1       TEXT    NOT NULL DEFAULT '',
    sha256     TEXT    NOT NULL DEFAULT ''
);

-- -------------------------------------------------------------------------
-- iocs: one row per unique (type, value) pair
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL,    -- 'ipv4','ipv6','domain','url','email','hash_md5','hash_sha256'
    value      TEXT    NOT NULL,
    frequency  INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    UNIQUE (type, value)
);

-- -------------------------------------------------------------------------
-- email_iocs: many-to-many join
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS email_iocs (
    email_id   INTEGER NOT NULL REFERENCES emails(id)  ON DELETE CASCADE,
    ioc_id     INTEGER NOT NULL REFERENCES iocs(id)    ON DELETE CASCADE,
    context    TEXT    NOT NULL DEFAULT '',   -- e.g. 'body_url', 'header_ip', 'attachment_hash'
    PRIMARY KEY (email_id, ioc_id, context)
);

-- -------------------------------------------------------------------------
-- enrichments: one row per (ioc, provider) — TTL-based cache (Phase 2)
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS enrichments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id     INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    provider   TEXT    NOT NULL,   -- 'virustotal','abuseipdb','urlhaus',…
    raw_json   TEXT    NOT NULL DEFAULT '{}',
    verdict    TEXT    NOT NULL DEFAULT 'unknown',
    score      REAL,
    fetched_at TEXT    NOT NULL,   -- ISO-8601
    UNIQUE (ioc_id, provider)
);

-- -------------------------------------------------------------------------
-- cases: analyst-managed investigation cases
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    notes       TEXT    NOT NULL DEFAULT '',       -- analyst investigation notes
    status      TEXT    NOT NULL DEFAULT 'open',  -- 'open','closed','archived'
    priority    TEXT    NOT NULL DEFAULT 'medium',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

-- -------------------------------------------------------------------------
-- case_emails: many-to-many join between cases and emails
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_emails (
    case_id    INTEGER NOT NULL REFERENCES cases(id)  ON DELETE CASCADE,
    email_id   INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    added_at   TEXT    NOT NULL,
    PRIMARY KEY (case_id, email_id)
);
"""
