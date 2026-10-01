"""
core/enrichment/otx.py
AlienVault OTX (Open Threat Exchange) enrichment provider.

OTX is free with a DirectConnect API key.
Supports: IPs, domains, URLs, and file hashes.

API docs: https://otx.alienvault.com/api
"""
from __future__ import annotations

import requests

from .base import BaseProvider, _safe_json
from .models import EnrichmentResult


class OTXProvider(BaseProvider):
    """AlienVault OTX (Open Threat Exchange) enrichment provider."""

    PROVIDER_NAME = "otx"
    SUPPORTED_IOC_TYPES = frozenset({
        "ipv4", "ipv6", "domain", "url",
        "hash_md5", "hash_sha1", "hash_sha256",
    })

    # OTX is generous — 10 000 requests / hour
    RATE_LIMIT_TOKENS = 20
    RATE_LIMIT_PERIOD = 60.0

    _BASE_URL = "https://otx.alienvault.com/api/v1"

    def _query(self, ioc_type: str, ioc_value: str) -> requests.Response:
        """Execute an OTX indicator query."""
        url = self._build_url(ioc_type, ioc_value)
        headers = {"X-OTX-API-KEY": self._api_key or ""}
        return self._session.get(url, headers=headers, timeout=self._timeout)

    def _normalize(
        self, ioc_type: str, ioc_value: str, response: requests.Response
    ) -> EnrichmentResult:
        """Parse OTX response into an EnrichmentResult."""
        data = _safe_json(response)

        # Pulse count is the primary indicator of threat association
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        # Build tags from pulse names and adversary info
        tags: list[str] = []
        for pulse in pulses[:10]:
            name = pulse.get("name", "")
            if name:
                tags.append(name)
            adversary = pulse.get("adversary", "")
            if adversary and adversary not in tags:
                tags.append(f"adversary:{adversary}")

        # Score based on pulse count
        if pulse_count >= 10:
            verdict = "malicious"
            score = min(100.0, 50.0 + pulse_count * 2)
        elif pulse_count >= 3:
            verdict = "suspicious"
            score = 30.0 + pulse_count * 5
        elif pulse_count >= 1:
            verdict = "suspicious"
            score = 20.0
        else:
            verdict = "clean"
            score = 0.0

        # Check reputation if available
        reputation = data.get("reputation", 0)
        if isinstance(reputation, (int, float)) and reputation < -5:
            verdict = "malicious"
            score = max(score, 80.0)

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
        """Test OTX API key by querying user info."""
        try:
            resp = self._session.get(
                f"{self._BASE_URL}/user/me",
                headers={"X-OTX-API-KEY": self._api_key or ""},
                timeout=self._timeout,
            )
            if resp.status_code == 200:
                data = _safe_json(resp)
                user = data.get("username", "unknown")
                return True, f"HTTP 200 OK — authenticated as '{user}'"
            return False, f"HTTP {resp.status_code}: {resp.reason}"
        except requests.RequestException as exc:
            return False, f"Connection failed: {exc}"

    def _build_url(self, ioc_type: str, ioc_value: str) -> str:
        """Build the correct OTX endpoint URL for the IOC type."""
        if ioc_type in ("ipv4", "ipv6"):
            return f"{self._BASE_URL}/indicators/IPv4/{ioc_value}/general"
        if ioc_type == "domain":
            return f"{self._BASE_URL}/indicators/domain/{ioc_value}/general"
        if ioc_type == "url":
            return f"{self._BASE_URL}/indicators/url/{ioc_value}/general"
        if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            return f"{self._BASE_URL}/indicators/file/{ioc_value}/general"
        return f"{self._BASE_URL}/indicators/file/{ioc_value}/general"
