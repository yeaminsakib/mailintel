"""
core/enrichment/virustotal.py
VirusTotal v3 API enrichment provider.

Free-tier limits: ~4 requests/minute, 500/day.
Supports: IP addresses, domains, URLs, and file hashes.

API docs: https://docs.virustotal.com/reference/overview
"""
from __future__ import annotations

from urllib.parse import quote

import requests

from .base import BaseProvider, _safe_json
from .models import EnrichmentResult


class VirusTotalProvider(BaseProvider):
    """VirusTotal v3 enrichment provider."""

    PROVIDER_NAME = "virustotal"
    SUPPORTED_IOC_TYPES = frozenset({
        "ipv4", "ipv6", "domain", "url",
        "hash_md5", "hash_sha1", "hash_sha256",
    })

    # VT free tier: 4 requests / 60 seconds
    RATE_LIMIT_TOKENS = 4
    RATE_LIMIT_PERIOD = 60.0

    _BASE_URL = "https://www.virustotal.com/api/v3"

    def _query(self, ioc_type: str, ioc_value: str) -> requests.Response:
        """Execute a VirusTotal v3 GET request."""
        url = self._build_url(ioc_type, ioc_value)
        headers = {"x-apikey": self._api_key or ""}
        return self._session.get(url, headers=headers, timeout=self._timeout)

    def _normalize(
        self, ioc_type: str, ioc_value: str, response: requests.Response
    ) -> EnrichmentResult:
        """Parse VT v3 response into an EnrichmentResult."""
        data = _safe_json(response)
        attrs = data.get("data", {}).get("attributes", {})

        # VT analysis stats
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Compute score (0-100)
        score: float | None = None
        if total > 0:
            score = round((malicious + suspicious * 0.5) / total * 100, 1)

        # Verdict
        if malicious >= 5:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "suspicious"
        elif total > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        # Tags
        tags: list[str] = []
        if attrs.get("type_description"):
            tags.append(attrs["type_description"])
        for engine_result in attrs.get("last_analysis_results", {}).values():
            if engine_result.get("category") == "malicious":
                result_name = engine_result.get("result", "")
                if result_name and result_name not in tags:
                    tags.append(result_name)
                    if len(tags) >= 10:
                        break

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
        """Test VT API key by querying the /users/me endpoint."""
        try:
            resp = self._session.get(
                f"{self._BASE_URL}/users/me",
                headers={"x-apikey": self._api_key or ""},
                timeout=self._timeout,
            )
            if resp.status_code == 200:
                data = _safe_json(resp)
                user = data.get("data", {}).get("id", "unknown")
                return True, f"HTTP 200 OK — authenticated as '{user}'"
            return False, f"HTTP {resp.status_code}: {resp.reason}"
        except requests.RequestException as exc:
            return False, f"Connection failed: {exc}"

    def _build_url(self, ioc_type: str, ioc_value: str) -> str:
        """Build the correct VT v3 endpoint URL for the IOC type."""
        if ioc_type in ("ipv4", "ipv6"):
            return f"{self._BASE_URL}/ip_addresses/{ioc_value}"
        if ioc_type == "domain":
            return f"{self._BASE_URL}/domains/{ioc_value}"
        if ioc_type == "url":
            # VT v3 requires base64url-encoded URL identifiers
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
            return f"{self._BASE_URL}/urls/{url_id}"
        if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            return f"{self._BASE_URL}/files/{ioc_value}"
        return f"{self._BASE_URL}/search?query={quote(ioc_value)}"
