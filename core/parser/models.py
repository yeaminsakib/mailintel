"""
core/parser/models.py
Data models for parsed email components.

All models are plain dataclasses with no UI or IO dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FileHashes:
    """Cryptographic hashes of a file's decoded content."""

    md5: str
    sha1: str
    sha256: str


@dataclass
class AttachmentInfo:
    """Metadata and hashes for an email attachment.

    The raw attachment bytes are used **only** for hash computation and
    are never retained in memory, executed, or written to disk.
    """

    filename: str
    mime_type: str
    size: int  # decoded byte count
    hashes: FileHashes


@dataclass
class ReceivedHop:
    """One hop in the Received header chain."""

    from_host: str
    by_host: str
    from_ip: str | None
    timestamp: str | None
    raw: str
    is_external: bool = False


@dataclass
class AuthResults:
    """SPF / DKIM / DMARC verdicts from Authentication-Results headers."""

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    raw: str = ""


@dataclass
class HeaderInfo:
    """Key RFC-5322 and RFC-2822 email headers."""

    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    to: str = ""
    cc: str = ""


@dataclass
class ParsedEmail:
    """Complete parse result for a single .eml file.

    Produced by :func:`core.parser.eml_parser.parse_eml_file` or
    :func:`core.parser.eml_parser.parse_eml_bytes`.
    """

    filepath: str = ""
    file_sha256: str = ""
    headers: HeaderInfo = field(default_factory=HeaderInfo)
    received_chain: list[ReceivedHop] = field(default_factory=list)
    first_external_hop: ReceivedHop | None = None
    auth_results: AuthResults = field(default_factory=AuthResults)
    body_plain: str = ""
    body_html: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
