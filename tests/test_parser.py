"""
tests/test_parser.py
Unit tests for the MIME email parser (core.parser).

All emails are built synthetically in-memory or in tmp directories —
no external samples required.
"""
from __future__ import annotations

import hashlib
import os
import textwrap
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import pytest

from core.parser import parse_eml_file, parse_eml_bytes, ParsedEmail


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_simple_eml() -> bytes:
    """A minimal text/plain email with known headers."""
    return textwrap.dedent("""\
        From: Alice Attacker <attacker@evil-domain.com>
        To: victim@company.com
        Reply-To: real-alice@spoofed-reply.net
        Return-Path: <bounce@evil-domain.com>
        Subject: Urgent: Verify your account
        Date: Mon, 30 Sep 2026 14:00:00 +0000
        Message-ID: <abc123@evil-domain.com>
        Received: from internal-gw.company.com (192.168.1.10) by mx.company.com; Mon, 30 Sep 2026 14:00:05 +0000
        Received: from relay.evil-domain.com (185.220.101.5) by internal-gw.company.com; Mon, 30 Sep 2026 14:00:03 +0000
        Received: from sender-box.evil-domain.com (45.33.32.156) by relay.evil-domain.com; Mon, 30 Sep 2026 14:00:01 +0000
        Authentication-Results: mx.company.com;
            spf=fail (sender IP not permitted);
            dkim=pass header.d=evil-domain.com;
            dmarc=fail (p=REJECT)

        Click here to verify your account: http://secure-login-portal.net/verify?id=12345
        Also check: https://evil-domain.com/payload.exe
        Contact: helpdesk@evil-domain.com
    """).encode("utf-8")


def _make_multipart_eml() -> bytes:
    """A multipart/alternative (plain + HTML) email."""
    msg = MIMEMultipart("alternative")
    msg["From"] = "sender@phish.example.com"
    msg["To"] = "target@company.com"
    msg["Subject"] = "Invoice #12345"
    msg["Date"] = "Tue, 01 Oct 2026 08:00:00 +0000"
    msg["Message-ID"] = "<inv-12345@phish.example.com>"

    plain = MIMEText(
        "Please review the invoice at http://phish.example.com/invoice",
        "plain",
    )
    html = MIMEText(
        '<html><body><a href="http://phish.example.com/invoice">Click</a>'
        '<img src="https://tracker.example.com/pixel.gif"></body></html>',
        "html",
    )
    msg.attach(plain)
    msg.attach(html)
    return msg.as_bytes()


def _make_attachment_eml() -> bytes:
    """An email with a binary attachment."""
    msg = MIMEMultipart()
    msg["From"] = "malware@bad-actor.com"
    msg["To"] = "victim@company.com"
    msg["Subject"] = "Your receipt"

    msg.attach(MIMEText("See attached receipt.", "plain"))

    # Fake malicious payload (we never execute it)
    payload_data = b"This is a fake malicious payload for testing purposes"
    part = MIMEBase("application", "octet-stream")
    part.set_payload(payload_data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename="receipt.exe")
    msg.attach(part)

    return msg.as_bytes(), payload_data  # type: ignore[return-value]


def _make_malformed_eml() -> bytes:
    """Something that looks like email but is badly broken."""
    return b"This is not\r\na valid email\r\nat all\r\n\x00\xff\xfe"


# ---------------------------------------------------------------------------
# Test: parse_eml_bytes — headers
# ---------------------------------------------------------------------------

class TestHeaderExtraction:
    """Verify header parsing from a well-formed email."""

    def test_from_and_reply_to(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert "attacker@evil-domain.com" in parsed.headers.from_addr
        assert "real-alice@spoofed-reply.net" in parsed.headers.reply_to

    def test_return_path(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert "bounce@evil-domain.com" in parsed.headers.return_path

    def test_subject_date_message_id(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert parsed.headers.subject == "Urgent: Verify your account"
        assert "30 Sep 2026" in parsed.headers.date
        assert "abc123@evil-domain.com" in parsed.headers.message_id

    def test_to(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert "victim@company.com" in parsed.headers.to


# ---------------------------------------------------------------------------
# Test: Received chain and first external hop
# ---------------------------------------------------------------------------

class TestReceivedChain:
    """Verify Received header parsing and external hop identification."""

    def test_received_chain_count(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert len(parsed.received_chain) == 3

    def test_first_external_hop_is_oldest(self) -> None:
        """The first external hop should be the oldest (sender's infrastructure)."""
        parsed = parse_eml_bytes(_make_simple_eml())
        hop = parsed.first_external_hop
        assert hop is not None
        assert hop.from_ip == "45.33.32.156"
        assert hop.is_external is True

    def test_internal_hops_marked_correctly(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        # The hop from 192.168.1.10 should NOT be external
        internal_hops = [h for h in parsed.received_chain if not h.is_external]
        internal_ips = [h.from_ip for h in internal_hops if h.from_ip]
        assert "192.168.1.10" in internal_ips

    def test_external_hops_have_public_ips(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        external_hops = [h for h in parsed.received_chain if h.is_external]
        assert len(external_hops) >= 2
        external_ips = {h.from_ip for h in external_hops}
        assert "185.220.101.5" in external_ips
        assert "45.33.32.156" in external_ips


# ---------------------------------------------------------------------------
# Test: Authentication-Results
# ---------------------------------------------------------------------------

class TestAuthResults:
    """Verify SPF/DKIM/DMARC extraction from Authentication-Results."""

    def test_spf_fail(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert parsed.auth_results.spf == "fail"

    def test_dkim_pass(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert parsed.auth_results.dkim == "pass"

    def test_dmarc_fail(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert parsed.auth_results.dmarc == "fail"

    def test_no_auth_results_returns_none(self) -> None:
        raw = b"From: x@y.com\r\nSubject: test\r\n\r\nbody\r\n"
        parsed = parse_eml_bytes(raw)
        assert parsed.auth_results.spf == "none"
        assert parsed.auth_results.dkim == "none"
        assert parsed.auth_results.dmarc == "none"


# ---------------------------------------------------------------------------
# Test: Body extraction
# ---------------------------------------------------------------------------

class TestBodyExtraction:
    """Verify plain-text and HTML body extraction."""

    def test_plain_body_from_simple(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert "verify your account" in parsed.body_plain.lower()

    def test_multipart_plain_body(self) -> None:
        parsed = parse_eml_bytes(_make_multipart_eml())
        assert "review the invoice" in parsed.body_plain.lower()

    def test_multipart_html_body(self) -> None:
        parsed = parse_eml_bytes(_make_multipart_eml())
        assert "<a href=" in parsed.body_html.lower()


# ---------------------------------------------------------------------------
# Test: URL extraction
# ---------------------------------------------------------------------------

class TestURLExtraction:
    """Verify URL extraction from text and HTML."""

    def test_urls_from_plain_text(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        url_set = set(parsed.urls)
        assert "http://secure-login-portal.net/verify?id=12345" in url_set
        assert "https://evil-domain.com/payload.exe" in url_set

    def test_urls_from_html_href(self) -> None:
        parsed = parse_eml_bytes(_make_multipart_eml())
        url_set = set(parsed.urls)
        assert "http://phish.example.com/invoice" in url_set

    def test_urls_from_html_src(self) -> None:
        parsed = parse_eml_bytes(_make_multipart_eml())
        url_set = set(parsed.urls)
        assert "https://tracker.example.com/pixel.gif" in url_set


# ---------------------------------------------------------------------------
# Test: Attachment extraction
# ---------------------------------------------------------------------------

class TestAttachmentExtraction:
    """Verify attachment metadata and hash computation."""

    def test_attachment_metadata(self) -> None:
        raw, payload_data = _make_attachment_eml()
        parsed = parse_eml_bytes(raw)
        assert len(parsed.attachments) == 1

        att = parsed.attachments[0]
        assert att.filename == "receipt.exe"
        assert att.mime_type == "application/octet-stream"
        assert att.size == len(payload_data)

    def test_attachment_hashes_correct(self) -> None:
        raw, payload_data = _make_attachment_eml()
        parsed = parse_eml_bytes(raw)
        att = parsed.attachments[0]

        assert att.hashes.md5 == hashlib.md5(payload_data).hexdigest()
        assert att.hashes.sha1 == hashlib.sha1(payload_data).hexdigest()
        assert att.hashes.sha256 == hashlib.sha256(payload_data).hexdigest()

    def test_no_attachments_returns_empty(self) -> None:
        parsed = parse_eml_bytes(_make_simple_eml())
        assert parsed.attachments == []


# ---------------------------------------------------------------------------
# Test: parse_eml_file (disk read + file SHA-256)
# ---------------------------------------------------------------------------

class TestParseEmlFile:
    """Verify file-based parsing including file-level SHA-256."""

    def test_file_sha256_computed(self, tmp_path: Any) -> None:
        raw = _make_simple_eml()
        eml_path = tmp_path / "test.eml"
        eml_path.write_bytes(raw)

        parsed = parse_eml_file(eml_path)
        expected = hashlib.sha256(raw).hexdigest()
        assert parsed.file_sha256 == expected
        assert str(eml_path) in parsed.filepath

    def test_missing_file_returns_empty(self, tmp_path: Any) -> None:
        parsed = parse_eml_file(tmp_path / "nonexistent.eml")
        assert parsed.headers.from_addr == ""
        assert parsed.attachments == []


# ---------------------------------------------------------------------------
# Test: Malformed email handling
# ---------------------------------------------------------------------------

class TestMalformedHandling:
    """Parser must never crash on garbage input."""

    def test_malformed_bytes(self) -> None:
        parsed = parse_eml_bytes(_make_malformed_eml())
        # Should return a ParsedEmail with empty/default fields, not raise
        assert isinstance(parsed, ParsedEmail)

    def test_empty_bytes(self) -> None:
        parsed = parse_eml_bytes(b"")
        assert isinstance(parsed, ParsedEmail)
        assert parsed.headers.subject == ""

    def test_binary_garbage(self) -> None:
        parsed = parse_eml_bytes(os.urandom(1024))
        assert isinstance(parsed, ParsedEmail)
