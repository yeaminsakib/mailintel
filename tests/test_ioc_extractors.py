"""
tests/test_ioc_extractors.py
Unit tests for IOC extractors, defanging, and whitelist policy.
"""
from __future__ import annotations

import pytest

from core.ioc.extractors import (
    extract_email_addresses,
    extract_ipv4,
    extract_ipv6,
    extract_urls,
)
from core.ioc.defang import (
    defang,
    defang_email,
    defang_ip,
    defang_url,
    refang_email,
    refang_ip,
    refang_url,
)
from core.ioc.whitelist import WhitelistPolicy


# ===================================================================
# IPv4 Extraction
# ===================================================================

class TestExtractIPv4:
    """Verify public-only IPv4 extraction."""

    def test_public_ips_extracted(self) -> None:
        text = "Seen from 185.220.101.5 and also 8.8.8.8 in the logs"
        result = extract_ipv4(text)
        assert "185.220.101.5" in result
        assert "8.8.8.8" in result

    def test_private_ips_excluded(self) -> None:
        text = "Internal: 192.168.1.1 10.0.0.1 172.16.5.3 127.0.0.1"
        result = extract_ipv4(text)
        assert result == []

    def test_deduplication(self) -> None:
        text = "IP 1.2.3.4 repeated 1.2.3.4 three times 1.2.3.4"
        result = extract_ipv4(text)
        assert result == ["1.2.3.4"]

    def test_cgnat_excluded(self) -> None:
        text = "CGNAT: 100.64.0.1 100.127.255.255"
        result = extract_ipv4(text)
        assert result == []

    def test_empty_input(self) -> None:
        assert extract_ipv4("") == []
        assert extract_ipv4("no IPs here") == []


# ===================================================================
# IPv6 Extraction
# ===================================================================

class TestExtractIPv6:
    """Verify global-only IPv6 extraction."""

    def test_full_ipv6_extracted(self) -> None:
        # Use a real globally-routable IPv6 (2001:db8::/32 is documentation range)
        text = "Connected from 2607:f8b0:4004:0800:0000:0000:0000:200e"
        result = extract_ipv6(text)
        assert len(result) == 1
        assert "2607:f8b0:4004:800::200e" in result

    def test_loopback_excluded(self) -> None:
        text = "Loopback: ::1"
        result = extract_ipv6(text)
        assert result == []

    def test_link_local_excluded(self) -> None:
        text = "Link-local: fe80::1"
        result = extract_ipv6(text)
        assert result == []

    def test_empty_input(self) -> None:
        assert extract_ipv6("") == []


# ===================================================================
# URL Extraction
# ===================================================================

class TestExtractURLs:
    """Verify URL extraction from plain text."""

    def test_http_and_https(self) -> None:
        text = "Visit http://evil.com/page and https://also-evil.com/login"
        result = extract_urls(text)
        assert "http://evil.com/page" in result
        assert "https://also-evil.com/login" in result

    def test_trailing_punctuation_stripped(self) -> None:
        text = "See http://evil.com/page. Also http://evil.com/other,"
        result = extract_urls(text)
        assert "http://evil.com/page" in result
        assert "http://evil.com/other" in result

    def test_deduplication(self) -> None:
        text = "http://dup.com http://dup.com http://dup.com"
        result = extract_urls(text)
        assert len(result) == 1

    def test_query_params_preserved(self) -> None:
        text = "https://phish.com/login?user=admin&token=abc123"
        result = extract_urls(text)
        assert "https://phish.com/login?user=admin&token=abc123" in result


# ===================================================================
# Email Address Extraction
# ===================================================================

class TestExtractEmailAddresses:
    """Verify email address extraction."""

    def test_basic_extraction(self) -> None:
        text = "Contact admin@company.com or helpdesk@support.io"
        result = extract_email_addresses(text)
        assert "admin@company.com" in result
        assert "helpdesk@support.io" in result

    def test_case_normalized(self) -> None:
        text = "User@Example.COM"
        result = extract_email_addresses(text)
        assert result == ["user@example.com"]

    def test_deduplication(self) -> None:
        text = "user@a.com and user@a.com again"
        result = extract_email_addresses(text)
        assert len(result) == 1


# ===================================================================
# Defanging
# ===================================================================

class TestDefangIP:
    def test_ipv4(self) -> None:
        assert defang_ip("1.2.3.4") == "1[.]2[.]3[.]4"

    def test_round_trip(self) -> None:
        original = "185.220.101.5"
        assert refang_ip(defang_ip(original)) == original


class TestDefangURL:
    def test_http(self) -> None:
        result = defang_url("http://evil.com/path")
        assert "hXXp[://]" in result
        assert "evil[.]com" in result
        assert "/path" in result

    def test_https(self) -> None:
        result = defang_url("https://evil.com")
        assert "hXXps[://]" in result
        assert "evil[.]com" in result

    def test_round_trip(self) -> None:
        original = "https://evil.example.com/login?id=1"
        assert refang_url(defang_url(original)) == original


class TestDefangEmail:
    def test_basic(self) -> None:
        result = defang_email("user@evil.com")
        assert "[@]" in result
        assert "[.]" in result
        assert "@" not in result.replace("[@]", "")

    def test_round_trip(self) -> None:
        original = "user@evil.example.com"
        assert refang_email(defang_email(original)) == original


class TestDefangAuto:
    def test_auto_url(self) -> None:
        result = defang("http://evil.com", ioc_type="auto")
        assert "hXXp" in result

    def test_auto_email(self) -> None:
        result = defang("user@evil.com", ioc_type="auto")
        assert "[@]" in result

    def test_auto_ip(self) -> None:
        result = defang("1.2.3.4", ioc_type="auto")
        assert "[.]" in result


# ===================================================================
# Whitelist Policy
# ===================================================================

class TestWhitelistPolicy:
    """Verify context-aware whitelist behaviour."""

    @pytest.fixture
    def policy(self) -> WhitelistPolicy:
        return WhitelistPolicy.load()

    def test_infrastructure_whitelists_sendgrid(self, policy: WhitelistPolicy) -> None:
        assert policy.is_whitelisted("sendgrid.net", context="infrastructure") is True

    def test_body_url_does_not_whitelist_sendgrid(self, policy: WhitelistPolicy) -> None:
        """Attackers abuse sendgrid.net — it must NOT be trusted in body URLs."""
        assert policy.is_whitelisted("sendgrid.net", context="body_url") is False

    def test_body_url_whitelists_w3_org(self, policy: WhitelistPolicy) -> None:
        assert policy.is_whitelisted("w3.org", context="body_url") is True

    def test_parent_zone_walking(self, policy: WhitelistPolicy) -> None:
        assert policy.is_whitelisted("sub.google.com", context="infrastructure") is True

    def test_unknown_domain_not_whitelisted(self, policy: WhitelistPolicy) -> None:
        assert policy.is_whitelisted("evil-domain.com", context="infrastructure") is False
        assert policy.is_whitelisted("evil-domain.com", context="body_url") is False

    def test_sender_context(self, policy: WhitelistPolicy) -> None:
        assert policy.is_whitelisted("gmail.com", context="sender") is True
        assert policy.is_whitelisted("evil.com", context="sender") is False

    def test_artifact_patterns(self, policy: WhitelistPolicy) -> None:
        assert policy.is_whitelisted("utf-8", context="body_url") is True
        assert policy.is_whitelisted("charset", context="body_url") is True

    def test_case_insensitive(self, policy: WhitelistPolicy) -> None:
        assert policy.is_whitelisted("Google.COM", context="infrastructure") is True
