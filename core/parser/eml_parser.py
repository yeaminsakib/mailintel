"""
core/parser/eml_parser.py
Main MIME parser — the single entry point for parsing ``.eml`` files.

Uses Python's ``email`` package with ``policy.default`` for proper MIME
handling, including charset decoding, Content-Transfer-Encoding, and
RFC-2047 header unfolding.

Public API
----------
parse_eml_file(filepath)   → ParsedEmail
parse_eml_bytes(raw_bytes)  → ParsedEmail
"""
from __future__ import annotations

import hashlib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from .attachments import extract_attachments
from .headers import (
    extract_headers,
    find_first_external_hop,
    parse_auth_results,
    parse_received_chain,
)
from .models import AuthResults, HeaderInfo, ParsedEmail
from .urls import extract_all_urls


def parse_eml_file(filepath: str | Path) -> ParsedEmail:
    """Parse a single ``.eml`` file into a structured :class:`ParsedEmail`.

    Parameters
    ----------
    filepath : str or Path
        Path to the ``.eml`` file on disk.

    Returns
    -------
    ParsedEmail
        Fully parsed email with headers, bodies, URLs, attachments, and
        hashes.  Malformed emails return a ``ParsedEmail`` with whatever
        could be extracted plus empty defaults for the rest — **never
        raises**.
    """
    filepath = Path(filepath)

    try:
        raw_bytes = filepath.read_bytes()
    except OSError:
        return ParsedEmail(filepath=str(filepath))

    file_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    parsed = parse_eml_bytes(raw_bytes)
    parsed.filepath = str(filepath)
    parsed.file_sha256 = file_sha256
    return parsed


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw RFC-5322 email bytes into a :class:`ParsedEmail`.

    Uses ``email.policy.default`` so that:

    * Headers are unfolded and decoded (RFC 2047).
    * Body charsets and Content-Transfer-Encoding (base64, QP) are
      decoded transparently.
    * MIME structure is walked correctly.

    Parameters
    ----------
    raw_bytes : bytes
        Raw email content.

    Returns
    -------
    ParsedEmail
        Malformed content fills in empty defaults — **never raises**.
    """
    try:
        msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        return ParsedEmail()

    # Every stage is isolated: a header or MIME part the stdlib chokes on must
    # cost only that stage, never the whole message.
    headers = _stage(extract_headers, msg, default=HeaderInfo())
    received_chain = _stage(parse_received_chain, msg, default=[])
    first_external_hop = find_first_external_hop(received_chain)
    auth_results = _stage(parse_auth_results, msg, default=AuthResults())
    body_plain = _stage(_extract_body, msg, "plain", default="")
    body_html = _stage(_extract_body, msg, "html", default="")
    urls = _stage(extract_all_urls, body_plain, body_html, default=[])
    attachments = _stage(extract_attachments, msg, default=[])

    return ParsedEmail(
        headers=headers,
        received_chain=received_chain,
        first_external_hop=first_external_hop,
        auth_results=auth_results,
        body_plain=body_plain,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
    )


def _stage(func, *args, default):
    """Run one parsing stage; return *default* if it raises."""
    try:
        return func(*args)
    except Exception:
        return default


def _extract_body(msg: EmailMessage, subtype: str) -> str:
    """Extract the first text body of a given subtype (``plain`` or ``html``).

    ``policy.default`` handles charset / CTE decoding automatically.
    """
    # Preferred: use the high-level API
    try:
        body = msg.get_body(preferencelist=(subtype,))
        if body is not None:
            content = body.get_content()
            if isinstance(content, str):
                return content
            if isinstance(content, bytes):
                return content.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Fallback: walk all parts manually
    try:
        for part in msg.walk():
            if part.get_content_type() == f"text/{subtype}":
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
    except Exception:
        pass

    return ""
