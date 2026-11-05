"""
core/storage/ingest.py
Ingestion logic — parse a ParsedEmail and persist all its IOCs to the DB.

This is pure business logic (no Qt imports) so it can be unit-tested
independently and is safe to call from any thread.
"""
from __future__ import annotations

from core.ioc.extractors import (
    extract_email_addresses,
    extract_ipv4,
    extract_ipv6,
)
from core.ioc.whitelist import WhitelistPolicy
from core.parser.models import ParsedEmail

from .database import Database

# Module-level whitelist loaded once
_WHITELIST = WhitelistPolicy.load()


def ingest_parsed_email(
    parsed: ParsedEmail,
    db: Database,
    whitelist: WhitelistPolicy | None = None,
) -> int:
    """Persist a :class:`ParsedEmail` and all its IOCs to the database.

    Steps
    -----
    1. Upsert the email row (deduped by file_sha256).  If it was already
       stored, stop here so IOC frequencies are not inflated.
    2. Extract IPs from Received headers (infrastructure context).
    3. Extract URLs from body (body_url context).
    4. Extract email addresses from From/Reply-To/Return-Path.
    5. Extract attachment hashes.
    6. For each IOC: upsert into ``iocs``, link to ``email_iocs``.

    Parameters
    ----------
    parsed : ParsedEmail
    db : Database
    whitelist : WhitelistPolicy or None
        Falls back to the module-level singleton.

    Returns
    -------
    int
        The email row id.
    """
    if whitelist is None:
        whitelist = _WHITELIST

    # Re-ingesting a stored email (same file SHA-256) only refreshes its
    # last_seen.  IOC frequency means "number of distinct emails", so it
    # must not grow on rescans.
    already_stored = db.email_exists(parsed.file_sha256)
    email_id = db.upsert_email(parsed)
    if already_stored:
        return email_id

    # Each (type, value) is upserted once per email, even if it appears in
    # several places (e.g. header and body); every context is still linked.
    ioc_ids: dict[tuple[str, str], int] = {}

    def add(ioc_type: str, value: str, context: str) -> None:
        key = (ioc_type, value)
        ioc_id = ioc_ids.get(key)
        if ioc_id is None:
            ioc_id = db.upsert_ioc(ioc_type, value)
            ioc_ids[key] = ioc_id
        db.link_email_ioc(email_id, ioc_id, context=context)

    # ------------------------------------------------------------------
    # 1. IPs from Received chain (infrastructure context)
    # ------------------------------------------------------------------
    for hop in parsed.received_chain:
        if hop.from_ip and hop.is_external:
            add("ipv6" if ":" in hop.from_ip else "ipv4", hop.from_ip, "header_ip")

    # ------------------------------------------------------------------
    # 2. IPs from body plain text (body context)
    # ------------------------------------------------------------------
    for ip in extract_ipv4(parsed.body_plain):
        add("ipv4", ip, "body_ipv4")

    for ip in extract_ipv6(parsed.body_plain):
        add("ipv6", ip, "body_ipv6")

    # ------------------------------------------------------------------
    # 3. URLs (body_url context — strict whitelist)
    # ------------------------------------------------------------------
    for url in parsed.urls:
        domain = _domain_from_url(url)
        if domain and whitelist.is_whitelisted(domain, context="body_url"):
            continue
        add("url", url, "body_url")

    # ------------------------------------------------------------------
    # 4. Email addresses from key headers
    # ------------------------------------------------------------------
    header_text = " ".join([
        parsed.headers.from_addr,
        parsed.headers.reply_to,
        parsed.headers.return_path,
    ])
    for addr in extract_email_addresses(header_text):
        domain = addr.split("@", 1)[-1]
        if whitelist.is_whitelisted(domain, context="sender"):
            continue
        add("email", addr, "header_email")

    # ------------------------------------------------------------------
    # 5. Attachment hashes
    # ------------------------------------------------------------------
    for att in parsed.attachments:
        for hash_type, hash_val in [
            ("hash_md5",    att.hashes.md5),
            ("hash_sha1",   att.hashes.sha1),
            ("hash_sha256", att.hashes.sha256),
        ]:
            add(hash_type, hash_val, "attachment_hash")

    return email_id


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _domain_from_url(url: str) -> str:
    """Extract the domain/host from a URL string.

    Returns empty string on failure.
    """
    try:
        # Trim scheme
        rest = url.split("://", 1)[1]
        # Trim path / query / fragment
        domain = rest.split("/")[0].split("?")[0].split("#")[0]
        # Trim port
        domain = domain.split(":")[0]
        return domain.lower()
    except (IndexError, AttributeError):
        return ""
