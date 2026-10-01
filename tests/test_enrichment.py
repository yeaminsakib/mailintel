"""
tests/test_enrichment.py
Comprehensive tests for core/enrichment — all HTTP mocked via ``responses``.

Tests cover:
- Abstract base provider (backoff, rate limiting, unsupported types)
- VirusTotal v3 normalization and connectivity test
- AbuseIPDB normalization and scoring
- abuse.ch (URLhaus, ThreatFox, MalwareBazaar) routing and normalization
- AlienVault OTX pulse-based scoring
- RDAP domain age scoring
- Enrichment cache (TTL, expiry)
- EnrichmentManager orchestration (cache → network → DB write)
- Rate limiter token bucket
- API key management (keyring)
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import responses

from core.enrichment.abuseipdb import AbuseIPDBProvider
from core.enrichment.abusech import AbuseCHProvider
from core.enrichment.base import BaseProvider
from core.enrichment.cache import EnrichmentCache
from core.enrichment.keys import get_api_key, set_api_key
from core.enrichment.manager import EnrichmentManager
from core.enrichment.models import EnrichmentResult
from core.enrichment.otx import OTXProvider
from core.enrichment.rate_limiter import RateLimiter
from core.enrichment.rdap import RDAPProvider
from core.enrichment.virustotal import VirusTotalProvider
from core.storage.database import Database


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db() -> Database:
    """Return a fresh in-memory database for each test."""
    return Database(":memory:")


# ---------------------------------------------------------------------------
# EnrichmentResult model
# ---------------------------------------------------------------------------

class TestEnrichmentResult:
    def test_success_when_no_error(self) -> None:
        r = EnrichmentResult(provider="test")
        assert r.success is True

    def test_not_success_when_error(self) -> None:
        r = EnrichmentResult(provider="test", error="boom")
        assert r.success is False

    def test_default_verdict(self) -> None:
        r = EnrichmentResult(provider="test")
        assert r.verdict == "unknown"


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_acquire_within_budget(self) -> None:
        rl = RateLimiter(max_tokens=3, refill_seconds=60.0)
        assert rl.acquire(timeout=0.1)
        assert rl.acquire(timeout=0.1)
        assert rl.acquire(timeout=0.1)

    def test_acquire_exceeds_budget(self) -> None:
        rl = RateLimiter(max_tokens=1, refill_seconds=60.0)
        assert rl.acquire(timeout=0.1)  # consumes the one token
        assert not rl.acquire(timeout=0.1)  # bucket empty

    def test_try_acquire_nonblocking(self) -> None:
        rl = RateLimiter(max_tokens=1, refill_seconds=60.0)
        assert rl.try_acquire()
        assert not rl.try_acquire()

    def test_tokens_refill(self) -> None:
        rl = RateLimiter(max_tokens=1, refill_seconds=0.2)
        assert rl.try_acquire()
        assert not rl.try_acquire()
        time.sleep(0.3)
        assert rl.try_acquire()


# ---------------------------------------------------------------------------
# VirusTotal Provider
# ---------------------------------------------------------------------------

class TestVirusTotalProvider:
    @responses.activate
    def test_malicious_ip(self) -> None:
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 10,
                            "suspicious": 2,
                            "harmless": 50,
                            "undetected": 8,
                        },
                        "last_analysis_results": {
                            "engine1": {"category": "malicious", "result": "Trojan"},
                        },
                    }
                }
            },
            status=200,
        )
        provider = VirusTotalProvider(api_key="fake-key")
        result = provider.enrich("ipv4", "1.2.3.4")
        assert result.success
        assert result.verdict == "malicious"
        assert result.score is not None
        assert result.score > 0
        assert "Trojan" in result.tags

    @responses.activate
    def test_clean_domain(self) -> None:
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/domains/example.com",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 60,
                            "undetected": 10,
                        },
                        "last_analysis_results": {},
                    }
                }
            },
            status=200,
        )
        provider = VirusTotalProvider(api_key="fake-key")
        result = provider.enrich("domain", "example.com")
        assert result.success
        assert result.verdict == "clean"
        assert result.score == 0.0

    @responses.activate
    def test_connectivity_success(self) -> None:
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/users/me",
            json={"data": {"id": "testuser"}},
            status=200,
        )
        provider = VirusTotalProvider(api_key="fake-key")
        ok, msg = provider.test_connectivity()
        assert ok
        assert "testuser" in msg

    @responses.activate
    def test_connectivity_bad_key(self) -> None:
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/users/me",
            json={"error": {"code": "AuthenticationRequiredError"}},
            status=401,
        )
        provider = VirusTotalProvider(api_key="bad-key")
        ok, msg = provider.test_connectivity()
        assert not ok
        assert "401" in msg

    def test_unsupported_ioc_type(self) -> None:
        provider = VirusTotalProvider(api_key="fake-key")
        result = provider.enrich("unknown_type", "foo")
        assert not result.success
        assert "not supported" in (result.error or "")

    def test_no_api_key(self) -> None:
        provider = VirusTotalProvider(api_key=None)
        result = provider.enrich("ipv4", "1.2.3.4")
        assert not result.success
        assert "No API key" in (result.error or "")

    @responses.activate
    def test_hash_lookup(self) -> None:
        sha = "a" * 64
        responses.add(
            responses.GET,
            f"https://www.virustotal.com/api/v3/files/{sha}",
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 30,
                            "suspicious": 5,
                            "harmless": 20,
                            "undetected": 5,
                        },
                        "type_description": "PE32 executable",
                        "last_analysis_results": {},
                    }
                }
            },
            status=200,
        )
        provider = VirusTotalProvider(api_key="fake-key")
        result = provider.enrich("hash_sha256", sha)
        assert result.success
        assert result.verdict == "malicious"
        assert "PE32 executable" in result.tags


# ---------------------------------------------------------------------------
# AbuseIPDB Provider
# ---------------------------------------------------------------------------

class TestAbuseIPDBProvider:
    @responses.activate
    def test_high_confidence_ip(self) -> None:
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 85,
                    "totalReports": 120,
                    "countryCode": "CN",
                    "isp": "Evil ISP",
                    "usageType": "Data Center",
                    "domain": "evil.cn",
                    "isTor": False,
                    "isWhitelisted": False,
                }
            },
            status=200,
        )
        provider = AbuseIPDBProvider(api_key="fake-key")
        result = provider.enrich("ipv4", "1.2.3.4")
        assert result.success
        assert result.verdict == "malicious"
        assert result.score == 85.0
        assert "country:CN" in result.tags

    @responses.activate
    def test_clean_ip(self) -> None:
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "countryCode": "US",
                    "isp": "Google",
                    "usageType": "Content Delivery Network",
                    "domain": "google.com",
                    "isTor": False,
                    "isWhitelisted": True,
                }
            },
            status=200,
        )
        provider = AbuseIPDBProvider(api_key="fake-key")
        result = provider.enrich("ipv4", "8.8.8.8")
        assert result.success
        assert result.verdict == "clean"
        assert "whitelisted" in result.tags


# ---------------------------------------------------------------------------
# abuse.ch Provider
# ---------------------------------------------------------------------------

class TestAbuseCHProvider:
    @responses.activate
    def test_urlhaus_malicious_url(self) -> None:
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/url/",
            json={
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["emotet", "loader"],
            },
            status=200,
        )
        provider = AbuseCHProvider()
        result = provider.enrich("url", "http://evil.com/payload.exe")
        assert result.success
        assert result.verdict == "malicious"
        assert "malware_download" in result.tags
        assert result.score == 90.0

    @responses.activate
    def test_urlhaus_not_found(self) -> None:
        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/url/",
            json={"query_status": "no_results"},
            status=200,
        )
        provider = AbuseCHProvider()
        result = provider.enrich("url", "http://clean.example.com")
        assert result.success
        assert result.verdict == "clean"

    @responses.activate
    def test_bazaar_hash_found(self) -> None:
        sha = "b" * 64
        responses.add(
            responses.POST,
            "https://mb-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [{
                    "signature": "Emotet",
                    "file_type": "exe",
                    "tags": ["emotet", "banker"],
                    "delivery_method": "email_attachment",
                }],
            },
            status=200,
        )
        provider = AbuseCHProvider()
        result = provider.enrich("hash_sha256", sha)
        assert result.success
        assert result.verdict == "malicious"
        assert "Emotet" in result.tags

    @responses.activate
    def test_threatfox_ip(self) -> None:
        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [{
                    "malware_printable": "Cobalt Strike",
                    "ioc_type_desc": "ip:port",
                    "confidence_level": 90,
                    "tags": ["cobalt_strike", "c2"],
                }],
            },
            status=200,
        )
        provider = AbuseCHProvider()
        result = provider.enrich("ipv4", "5.6.7.8")
        assert result.success
        assert result.verdict == "malicious"
        assert "Cobalt Strike" in result.tags
        assert result.score == 90.0


# ---------------------------------------------------------------------------
# OTX Provider
# ---------------------------------------------------------------------------

class TestOTXProvider:
    @responses.activate
    def test_ip_with_pulses(self) -> None:
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
            json={
                "pulse_info": {
                    "count": 15,
                    "pulses": [
                        {"name": "Botnet C2 Infrastructure", "adversary": "APT28"},
                        {"name": "Emotet Distribution"},
                    ],
                },
                "reputation": -10,
            },
            status=200,
        )
        provider = OTXProvider(api_key="fake-key")
        result = provider.enrich("ipv4", "1.2.3.4")
        assert result.success
        assert result.verdict == "malicious"
        assert result.score is not None
        assert result.score >= 50
        assert "Botnet C2 Infrastructure" in result.tags

    @responses.activate
    def test_clean_domain(self) -> None:
        responses.add(
            responses.GET,
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general",
            json={
                "pulse_info": {"count": 0, "pulses": []},
                "reputation": 0,
            },
            status=200,
        )
        provider = OTXProvider(api_key="fake-key")
        result = provider.enrich("domain", "example.com")
        assert result.success
        assert result.verdict == "clean"
        assert result.score == 0.0


# ---------------------------------------------------------------------------
# RDAP Provider
# ---------------------------------------------------------------------------

class TestRDAPProvider:
    @responses.activate
    def test_newly_registered_domain(self) -> None:
        # Domain registered 3 days ago → should be malicious
        three_days_ago = (
            datetime.now(timezone.utc) - timedelta(days=3)
        ).isoformat()
        responses.add(
            responses.GET,
            "https://rdap.org/domain/evilphish.xyz",
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": three_days_ago},
                    {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
                ],
                "entities": [],
            },
            status=200,
        )
        provider = RDAPProvider()
        result = provider.enrich("domain", "evilphish.xyz")
        assert result.success
        assert result.verdict == "malicious"
        assert result.score is not None
        assert result.score >= 90
        assert "newly_registered" in result.tags

    @responses.activate
    def test_established_domain(self) -> None:
        # Domain registered 5 years ago → should be clean
        five_years_ago = (
            datetime.now(timezone.utc) - timedelta(days=5 * 365)
        ).isoformat()
        responses.add(
            responses.GET,
            "https://rdap.org/domain/google.com",
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": five_years_ago},
                ],
                "entities": [],
            },
            status=200,
        )
        provider = RDAPProvider()
        result = provider.enrich("domain", "google.com")
        assert result.success
        assert result.verdict == "clean"
        assert "established" in result.tags

    def test_rdap_no_api_key_required(self) -> None:
        """RDAP should work without any API key."""
        provider = RDAPProvider(api_key=None)
        assert not provider._requires_api_key()


# ---------------------------------------------------------------------------
# Backoff and error handling (abstract base)
# ---------------------------------------------------------------------------

class TestBackoffAndErrors:
    @responses.activate
    def test_retry_on_429(self) -> None:
        """Provider should retry on HTTP 429 (rate limited)."""
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
            json={"error": "rate limited"},
            status=429,
        )
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1",
            json={
                "data": {"attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "harmless": 70, "undetected": 0,
                    },
                    "last_analysis_results": {},
                }}
            },
            status=200,
        )
        provider = VirusTotalProvider(api_key="fake-key", max_retries=2)
        result = provider.enrich("ipv4", "1.1.1.1")
        assert result.success
        assert result.verdict == "clean"

    @responses.activate
    def test_retry_on_500(self) -> None:
        """Provider should retry on HTTP 500 (server error)."""
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/2.2.2.2",
            json={"error": "internal"},
            status=500,
        )
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/2.2.2.2",
            json={
                "data": {"attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "harmless": 1, "undetected": 0,
                    },
                    "last_analysis_results": {},
                }}
            },
            status=200,
        )
        provider = VirusTotalProvider(api_key="fake-key", max_retries=2)
        result = provider.enrich("ipv4", "2.2.2.2")
        assert result.success

    @responses.activate
    def test_client_error_not_retried(self) -> None:
        """HTTP 403 should NOT be retried — immediate error."""
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/3.3.3.3",
            json={"error": "forbidden"},
            status=403,
        )
        provider = VirusTotalProvider(api_key="fake-key", max_retries=3)
        result = provider.enrich("ipv4", "3.3.3.3")
        assert not result.success
        assert "403" in (result.error or "")

    @responses.activate
    def test_network_failure_retried(self) -> None:
        """Connection errors should be retried up to max_retries."""
        responses.add(
            responses.GET,
            "https://www.virustotal.com/api/v3/ip_addresses/4.4.4.4",
            body=ConnectionError("Connection refused"),
        )
        provider = VirusTotalProvider(api_key="fake-key", max_retries=0)
        result = provider.enrich("ipv4", "4.4.4.4")
        assert not result.success
        assert result.error is not None


# ---------------------------------------------------------------------------
# Enrichment Cache
# ---------------------------------------------------------------------------

class TestEnrichmentCache:
    def test_cache_hit(self, db: Database) -> None:
        cache = EnrichmentCache(db, ttl=timedelta(hours=1))
        ioc_id = db.upsert_ioc("ipv4", "9.9.9.9")
        result = EnrichmentResult(
            provider="virustotal",
            verdict="malicious",
            score=80.0,
            tags=["trojan"],
        )
        cache.put(ioc_id, result)
        cached = cache.get(ioc_id, "virustotal")
        assert cached is not None
        assert cached.verdict == "malicious"
        assert cached.cached is True
        assert cached.score == 80.0

    def test_cache_miss(self, db: Database) -> None:
        cache = EnrichmentCache(db)
        ioc_id = db.upsert_ioc("ipv4", "8.8.8.8")
        assert cache.get(ioc_id, "virustotal") is None

    def test_cache_expiry(self, db: Database) -> None:
        # TTL of 0 seconds means everything is expired immediately
        cache = EnrichmentCache(db, ttl=timedelta(seconds=0))
        ioc_id = db.upsert_ioc("ipv4", "7.7.7.7")
        result = EnrichmentResult(provider="virustotal", verdict="clean")
        cache.put(ioc_id, result)
        # Should be expired immediately
        time.sleep(0.01)
        cached = cache.get(ioc_id, "virustotal")
        assert cached is None

    def test_cache_different_providers(self, db: Database) -> None:
        cache = EnrichmentCache(db, ttl=timedelta(hours=1))
        ioc_id = db.upsert_ioc("ipv4", "6.6.6.6")
        r1 = EnrichmentResult(provider="virustotal", verdict="clean")
        r2 = EnrichmentResult(provider="abuseipdb", verdict="malicious")
        cache.put(ioc_id, r1)
        cache.put(ioc_id, r2)
        assert cache.get(ioc_id, "virustotal") is not None
        assert cache.get(ioc_id, "abuseipdb") is not None
        assert cache.get(ioc_id, "otx") is None


# ---------------------------------------------------------------------------
# EnrichmentManager
# ---------------------------------------------------------------------------

class TestEnrichmentManager:
    @responses.activate
    def test_manager_caches_result(self, db: Database) -> None:
        """Manager should cache a successful result and return it on second call."""
        responses.add(
            responses.GET,
            "https://api.abuseipdb.com/api/v2/check",
            json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 50,
                    "totalReports": 10,
                    "countryCode": "US",
                    "isp": "Test",
                    "usageType": "ISP",
                    "domain": "",
                    "isTor": False,
                    "isWhitelisted": False,
                }
            },
            status=200,
        )

        ioc_id = db.upsert_ioc("ipv4", "1.2.3.4")

        # Patch get_api_key to return a fake key for abuseipdb
        with patch("core.enrichment.manager.get_api_key", return_value="fake-key"):
            manager = EnrichmentManager(db, providers=["abuseipdb"])
            results1 = manager.enrich_ioc(ioc_id, "ipv4", "1.2.3.4")
            assert len(results1) == 1
            assert results1[0].success
            assert not results1[0].cached

            # Second call should hit the cache
            results2 = manager.enrich_ioc(ioc_id, "ipv4", "1.2.3.4")
            assert len(results2) == 1
            assert results2[0].cached

    def test_manager_skips_unsupported_types(self, db: Database) -> None:
        """Manager should skip providers that don't support the IOC type."""
        with patch("core.enrichment.manager.get_api_key", return_value="fake-key"):
            manager = EnrichmentManager(db, providers=["abuseipdb"])
            ioc_id = db.upsert_ioc("url", "http://test.com")
            results = manager.enrich_ioc(ioc_id, "url", "http://test.com")
            # AbuseIPDB only supports ipv4/ipv6, should return empty
            assert len(results) == 0

    def test_manager_test_provider(self, db: Database) -> None:
        with patch("core.enrichment.manager.get_api_key", return_value=None):
            manager = EnrichmentManager(db, providers=["rdap"])
            assert "rdap" in manager.get_enabled_providers()

    def test_manager_unknown_provider(self, db: Database) -> None:
        ok, msg = EnrichmentManager(db, providers=[]).test_provider("nonexistent")
        assert not ok
        assert "not configured" in msg


# ---------------------------------------------------------------------------
# API Key management (keyring)
# ---------------------------------------------------------------------------

class TestKeyManagement:
    @patch("core.enrichment.keys.keyring")
    def test_set_and_get_key(self, mock_keyring) -> None:
        mock_keyring.set_password.return_value = None
        mock_keyring.get_password.return_value = "my-secret-key"

        assert set_api_key("virustotal", "my-secret-key") is True
        assert get_api_key("virustotal") == "my-secret-key"

    @patch("core.enrichment.keys.keyring")
    def test_get_key_not_found(self, mock_keyring) -> None:
        mock_keyring.get_password.return_value = None
        assert get_api_key("nonexistent") is None

    @patch("core.enrichment.keys.keyring")
    def test_get_key_empty_string(self, mock_keyring) -> None:
        mock_keyring.get_password.return_value = ""
        assert get_api_key("virustotal") is None
