"""
core/storage/schema.py
SQLite table definitions for MailIntel.

Tables
------
emails          – One row per unique .eml file (deduped by file_sha256).
iocs            – One row per unique IOC (type, value) pair.
email_iocs      – Many-to-many join between emails and iocs.
enrichments     – Cached provider results keyed by (ioc_id, provider).
cases           – Analyst-managed investigation cases.
case_emails     – Many-to-many join between cases and emails.
"""
from __future__ import annotations

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
    last_seen     TEXT    NOT NULL                -- updated on re-scan
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
