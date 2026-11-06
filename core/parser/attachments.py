"""
core/parser/attachments.py
Extract attachment metadata and compute cryptographic hashes.

Decoded attachment bytes are used **only** for hashing and are never
retained in memory, executed, or written to disk.
"""
from __future__ import annotations

import hashlib
from email.message import EmailMessage

from .models import AttachmentInfo, FileHashes


def compute_hashes(data: bytes) -> FileHashes:
    """Compute MD5, SHA-1, and SHA-256 of raw bytes.

    Parameters
    ----------
    data : bytes
        Decoded attachment content.

    Returns
    -------
    FileHashes
        Named tuple of hex-digest strings.
    """
    return FileHashes(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def extract_attachments(msg: EmailMessage) -> list[AttachmentInfo]:
    """Walk MIME parts and return metadata + hashes for every attachment.

    An attachment is any part with ``Content-Disposition: attachment`` or
    any non-``multipart`` part that carries a filename.  Inline images
    with filenames are also captured.

    Malformed parts are silently skipped.
    """
    attachments: list[AttachmentInfo] = []

    for part in msg.walk():
        try:
            info = _attachment_from_part(part)
        except Exception:
            # Malformed part (bad Content-Disposition, undecodable payload, ...):
            # skip it without losing the other attachments.
            continue
        if info is not None:
            attachments.append(info)

    return attachments


def _attachment_from_part(part: EmailMessage) -> AttachmentInfo | None:
    """Return metadata + hashes for one MIME part, or ``None`` if it is not an attachment."""
    # Skip multipart containers
    if part.get_content_maintype() == "multipart":
        return None

    content_disp = str(part.get("Content-Disposition", ""))
    is_attachment = "attachment" in content_disp.lower()
    filename = part.get_filename()

    # Must be an explicit attachment or carry a filename
    if not is_attachment and not filename:
        return None

    # Safe filename fallback
    if not filename:
        ext = part.get_content_subtype() or "bin"
        filename = f"unnamed_attachment.{ext}"

    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return None

    return AttachmentInfo(
        filename=filename,
        mime_type=part.get_content_type() or "application/octet-stream",
        size=len(payload),
        hashes=compute_hashes(payload),
    )
