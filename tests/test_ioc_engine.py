"""
tests/test_ioc_engine.py
Unit tests for the IOC extraction engine (core.ioc.engine).
Uses synthetic .eml files in a temp directory – no external data needed.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict

import pytest

from core.ioc.engine import (
    _is_private_or_reserved,
    _is_whitelisted_domain,
    parse_eml_folder,
    analyze_folder,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_eml(tmp_dir: str, filename: str, body: str) -> str:
    """Write a synthetic .eml file and return its path."""
    path = os.path.join(tmp_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path


# ---------------------------------------------------------------------------
# _is_private_or_reserved
# ---------------------------------------------------------------------------

class TestIsPrivateOrReserved:
    """Verify private/reserved IP filtering."""

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",       # Loopback
        "10.0.0.1",        # Private A
        "172.16.5.1",      # Private B low
        "172.31.255.255",  # Private B high
        "192.168.1.1",     # Private C
        "169.254.0.1",     # Link-local
        "100.64.0.1",      # CGNAT
        "192.0.2.1",       # TEST-NET-1
        "198.51.100.1",    # TEST-NET-2
        "203.0.113.1",     # TEST-NET-3
        "224.0.0.1",       # Multicast
        "255.255.255.255", # Broadcast
        "0.0.0.0",         # This-network
    ])
    def test_private_ips_filtered(self, ip: str) -> None:
        assert _is_private_or_reserved(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "185.220.101.5",
        "139.59.164.251",
        "172.15.0.1",      # Just below Private B range
        "172.32.0.1",      # Just above Private B range
        "100.63.255.255",  # Just below CGNAT
        "100.128.0.1",     # Just above CGNAT
    ])
    def test_public_ips_kept(self, ip: str) -> None:
        assert _is_private_or_reserved(ip) is False

    def test_malformed_ip_treated_as_private(self) -> None:
        assert _is_private_or_reserved("not-an-ip") is True
        assert _is_private_or_reserved("") is True


# ---------------------------------------------------------------------------
# _is_whitelisted_domain
# ---------------------------------------------------------------------------

class TestIsWhitelistedDomain:
    """Verify domain whitelist matching including parent-zone walking."""

    @pytest.mark.parametrize("domain", [
        "google.com",
        "www.google.com",
        "sub.googleapis.com",
        "schemas.microsoft.com",
        "outlook.com",
    ])
    def test_whitelisted_domains(self, domain: str) -> None:
        assert _is_whitelisted_domain(domain) is True

    @pytest.mark.parametrize("domain", [
        "evil-update-auth.com",
        "secure-login-portal-office365.net",
        "cdn-cloud-storage-sync.biz",
        "phishing-google.com",   # Not a subdomain of google.com
    ])
    def test_non_whitelisted_domains(self, domain: str) -> None:
        assert _is_whitelisted_domain(domain) is False

    def test_case_insensitive(self) -> None:
        assert _is_whitelisted_domain("Google.COM") is True


# ---------------------------------------------------------------------------
# parse_eml_folder
# ---------------------------------------------------------------------------

class TestParseEmlFolder:
    """Integration tests for the full parsing pipeline."""

    def test_empty_folder(self, tmp_path: Any) -> None:
        """Empty directory → zero counts, empty lists."""
        result = parse_eml_folder(str(tmp_path))
        assert result["total_emails_scanned"] == 0
        assert result["top_ips"] == []
        assert result["top_domains"] == []
        assert result["hashes"] == []
        assert result["email_logs"] == []

    def test_invalid_path(self) -> None:
        """Non-existent path → zero counts, empty lists (no crash)."""
        result = parse_eml_folder("/nonexistent/path/foo")
        assert result["total_emails_scanned"] == 0

    def test_empty_string_path(self) -> None:
        """Empty string → zero counts, empty lists (no crash)."""
        result = parse_eml_folder("")
        assert result["total_emails_scanned"] == 0

    def test_extracts_public_ips(self, tmp_path: Any) -> None:
        """Public IPs are extracted; private ones are filtered."""
        _write_eml(str(tmp_path), "test.eml", (
            "From: x@example.com\n"
            "Received: from 185.220.101.5\n"
            "Received: from 192.168.1.1\n"  # private, should be filtered
            "\n"
            "Body with 8.8.8.8 mention\n"
        ))
        result = parse_eml_folder(str(tmp_path))
        assert result["total_emails_scanned"] == 1
        ip_values = {entry["ioc"] for entry in result["top_ips"]}
        assert "185.220.101.5" in ip_values
        assert "8.8.8.8" in ip_values
        assert "192.168.1.1" not in ip_values

    def test_extracts_domains_filters_whitelist(self, tmp_path: Any) -> None:
        """Non-whitelisted domains are kept; whitelisted ones are dropped."""
        _write_eml(str(tmp_path), "test.eml", (
            "From: x@evil-domain.com\n"
            "\n"
            "Visit http://evil-domain.com/login\n"
            "Trusted: https://www.google.com/search\n"
        ))
        result = parse_eml_folder(str(tmp_path))
        domain_values = {entry["ioc"] for entry in result["top_domains"]}
        assert "evil-domain.com" in domain_values
        assert "google.com" not in domain_values
        assert "www.google.com" not in domain_values

    def test_extracts_hashes(self, tmp_path: Any) -> None:
        """32-hex strings that aren't pure digits are captured as MD5 hashes."""
        _write_eml(str(tmp_path), "test.eml", (
            "From: x@example.com\n\n"
            "Hash: d41d8cd98f00b204e9800998ecf8427e\n"
            "Not a hash: 12345678901234567890123456789012\n"  # pure digits
        ))
        result = parse_eml_folder(str(tmp_path))
        hash_values = {entry["ioc"] for entry in result["hashes"]}
        assert "d41d8cd98f00b204e9800998ecf8427e" in hash_values
        # Pure-digit string should be excluded
        assert "12345678901234567890123456789012" not in hash_values

    def test_per_email_logs(self, tmp_path: Any) -> None:
        """Each .eml file gets its own entry in email_logs."""
        _write_eml(str(tmp_path), "a.eml", "From: x@a.com\nReceived: from 1.2.3.4\n\nbody\n")
        _write_eml(str(tmp_path), "b.eml", "From: y@b.com\n\nbody\n")
        result = parse_eml_folder(str(tmp_path))
        assert result["total_emails_scanned"] == 2
        assert len(result["email_logs"]) == 2
        filenames = {log["filename"] for log in result["email_logs"]}
        assert filenames == {"a.eml", "b.eml"}


# ---------------------------------------------------------------------------
# analyze_folder – no fake data
# ---------------------------------------------------------------------------

class TestAnalyzeFolder:
    """Verify that analyze_folder never returns fake DEFAULT_IOC_DATA."""

    def test_empty_folder_returns_empty_list(self, tmp_path: Any) -> None:
        result = analyze_folder(str(tmp_path))
        assert result == []

    def test_invalid_path_returns_empty_list(self) -> None:
        result = analyze_folder("/nonexistent/path")
        assert result == []

    def test_real_data_returned(self, tmp_path: Any) -> None:
        _write_eml(str(tmp_path), "test.eml", (
            "From: x@malicious.com\n"
            "Received: from 185.220.101.5\n\n"
            "body http://malicious.com/payload\n"
        ))
        result = analyze_folder(str(tmp_path))
        assert len(result) > 0
        # All results must have proper keys
        for entry in result:
            assert "ioc" in entry
            assert "type" in entry
            assert "severity" in entry
