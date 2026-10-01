"""
core/enrichment/abuseipdb.py
AbuseIPDB v2 API enrichment provider.

Free-tier limits: 1 000 checks/day (≈1 req/1.5s sustained).
Supports: IPv4 and IPv6 addresses only.

API docs: https://docs.abuseipdb.com/
"""
from __future__ import annotations

import requests

from .base import BaseProvider, _safe_json
from .models import EnrichmentResult


class AbuseIPDBProvider(BaseProvider):
    """AbuseIPDB v2 enrichment provider."""

    PROVIDER_NAME = "abuseipdb"
    SUPPORTED_IOC_TYPES = frozenset({"ipv4", "ipv6"})

    # 1000 checks / day ≈ 1 req every 1.5 seconds sustained
    RATE_LIMIT_TOKENS = 5
    RATE_LIMIT_PERIOD = 10.0

    _BASE_URL = "https://api.abuseipdb.com/api/v2"

    def _query(self, ioc_type: str, ioc_value: str) -> requests.Response:
        """Execute an AbuseIPDB check endpoint request."""
        return self._session.get(
            f"{self._BASE_URL}/check",
            headers={
                "Key": self._api_key or "",
                "Accept": "application/json",
            },
            params={
                "ipAddress": ioc_value,
                "maxAgeInDays": "90",
                "verbose": "",
            },
            timeout=self._timeout,
        )

    def _normalize(
        self, ioc_type: str, ioc_value: str, response: requests.Response
    ) -> EnrichmentResult:
        """Parse AbuseIPDB response into an EnrichmentResult."""
        data = _safe_json(response)
        info = data.get("data", {})

        confidence = info.get("abuseConfidenceScore", 0)
        total_reports = info.get("totalReports", 0)
        country = info.get("countryCode", "")
        isp = info.get("isp", "")
        usage = info.get("usageType", "")
        domain = info.get("domain", "")

        # Score is the abuse confidence (0-100)
        score = float(confidence)

        # Verdict
        if confidence >= 75:
            verdict = "malicious"
        elif confidence >= 25:
            verdict = "suspicious"
        elif total_reports > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"

        # Tags
        tags: list[str] = []
        if country:
            tags.append(f"country:{country}")
        if isp:
            tags.append(f"isp:{isp}")
        if usage:
            tags.append(f"usage:{usage}")
        if domain:
            tags.append(f"domain:{domain}")
        if info.get("isTor"):
            tags.append("tor_exit_node")
        if info.get("isWhitelisted"):
            tags.append("whitelisted")

        return EnrichmentResult(
            provider=self.PROVIDER_NAME,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=score,
            tags=tags,
            raw=data,
        )

    def _test_connectivity(self) -> tuple[bool, str]:
        """Test AbuseIPDB by querying 8.8.8.8 (well-known clean IP)."""
        try:
            resp = self._session.get(
                f"{self._BASE_URL}/check",
                headers={
                    "Key": self._api_key or "",
                    "Accept": "application/json",
                },
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": "1"},
                timeout=self._timeout,
            )
            if resp.status_code == 200:
                return True, "HTTP 200 OK — AbuseIPDB key is valid"
            return False, f"HTTP {resp.status_code}: {resp.reason}"
        except requests.RequestException as exc:
            return False, f"Connection failed: {exc}"
