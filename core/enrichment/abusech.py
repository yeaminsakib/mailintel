"""
core/enrichment/abusech.py
abuse.ch enrichment provider (URLhaus, ThreatFox, MalwareBazaar).

abuse.ch is free and requires an API key only for some endpoints.
This provider queries three sub-services:

- **URLhaus**: malicious URL lookups
- **ThreatFox**: IOC lookups (IP:port, domain, URL, hash)
- **MalwareBazaar**: malware hash lookups

API docs:
    https://urlhaus-api.abuse.ch/
    https://threatfox-api.abuse.ch/
    https://bazaar.abuse.ch/api/
"""
from __future__ import annotations

import requests

from .base import BaseProvider, _safe_json
from .models import EnrichmentResult


class AbuseCHProvider(BaseProvider):
    """abuse.ch composite provider (URLhaus + ThreatFox + MalwareBazaar)."""

    PROVIDER_NAME = "abusech"
    SUPPORTED_IOC_TYPES = frozenset({
        "ipv4", "domain", "url",
        "hash_md5", "hash_sha256",
    })

    # abuse.ch is generous with rate limits
    RATE_LIMIT_TOKENS = 10
    RATE_LIMIT_PERIOD = 60.0

    _URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1"
    _THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1"
    _BAZAAR_URL = "https://mb-api.abuse.ch/api/v1"

    def _requires_api_key(self) -> bool:
        """abuse.ch does not require an API key for basic lookups."""
        return False

    def _query(self, ioc_type: str, ioc_value: str) -> requests.Response:
        """Route to the appropriate abuse.ch sub-service."""
        if ioc_type == "url":
            return self._query_urlhaus(ioc_value)
        if ioc_type in ("hash_md5", "hash_sha256"):
            return self._query_bazaar(ioc_type, ioc_value)
        # IP and domain → ThreatFox
        return self._query_threatfox(ioc_type, ioc_value)

    def _normalize(
        self, ioc_type: str, ioc_value: str, response: requests.Response
    ) -> EnrichmentResult:
        """Parse abuse.ch response into an EnrichmentResult."""
        data = _safe_json(response)

        if ioc_type == "url":
            return self._normalize_urlhaus(ioc_type, ioc_value, data)
        if ioc_type in ("hash_md5", "hash_sha256"):
            return self._normalize_bazaar(ioc_type, ioc_value, data)
        return self._normalize_threatfox(ioc_type, ioc_value, data)

    # ------------------------------------------------------------------
    # URLhaus
    # ------------------------------------------------------------------

    def _query_urlhaus(self, url: str) -> requests.Response:
        return self._session.post(
            f"{self._URLHAUS_URL}/url/",
            data={"url": url},
            timeout=self._timeout,
        )

    def _normalize_urlhaus(
        self, ioc_type: str, ioc_value: str, data: dict
    ) -> EnrichmentResult:
        status = data.get("query_status", "")
        if status == "no_results":
            return EnrichmentResult(
                provider=self.PROVIDER_NAME,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict="clean",
                raw=data,
            )

        url_status = data.get("url_status", "")
        threat = data.get("threat", "")
        tags_raw = data.get("tags") or []

        if url_status == "online":
            verdict = "malicious"
            score = 90.0
        elif url_status == "offline":
            verdict = "suspicious"
            score = 50.0
        else:
            verdict = "unknown"
            score = None

        tags = list(tags_raw)
        if threat:
            tags.insert(0, threat)

        return EnrichmentResult(
            provider=self.PROVIDER_NAME,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=score,
            tags=tags,
            raw=data,
        )

    # ------------------------------------------------------------------
    # MalwareBazaar
    # ------------------------------------------------------------------

    def _query_bazaar(self, ioc_type: str, ioc_value: str) -> requests.Response:
        hash_type = "sha256_hash" if ioc_type == "hash_sha256" else "md5_hash"
        return self._session.post(
            f"{self._BAZAAR_URL}/",
            data={"query": "get_info", hash_type: ioc_value},
            timeout=self._timeout,
        )

    def _normalize_bazaar(
        self, ioc_type: str, ioc_value: str, data: dict
    ) -> EnrichmentResult:
        status = data.get("query_status", "")
        if status in ("hash_not_found", "no_results"):
            return EnrichmentResult(
                provider=self.PROVIDER_NAME,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict="clean",
                raw=data,
            )

        sample = {}
        if isinstance(data.get("data"), list) and data["data"]:
            sample = data["data"][0]

        sig = sample.get("signature") or ""
        file_type = sample.get("file_type") or ""
        tags_raw = sample.get("tags") or []
        delivery = sample.get("delivery_method") or ""

        tags = list(tags_raw)
        if sig:
            tags.insert(0, sig)
        if file_type:
            tags.append(f"filetype:{file_type}")
        if delivery:
            tags.append(f"delivery:{delivery}")

        return EnrichmentResult(
            provider=self.PROVIDER_NAME,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict="malicious",
            score=95.0,
            tags=tags,
            raw=data,
        )

    # ------------------------------------------------------------------
    # ThreatFox
    # ------------------------------------------------------------------

    def _query_threatfox(self, ioc_type: str, ioc_value: str) -> requests.Response:
        return self._session.post(
            f"{self._THREATFOX_URL}/",
            json={"query": "search_ioc", "search_term": ioc_value},
            timeout=self._timeout,
        )

    def _normalize_threatfox(
        self, ioc_type: str, ioc_value: str, data: dict
    ) -> EnrichmentResult:
        status = data.get("query_status", "")
        if status in ("no_result", "no_results"):
            return EnrichmentResult(
                provider=self.PROVIDER_NAME,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict="clean",
                raw=data,
            )

        entries = data.get("data", [])
        if not isinstance(entries, list) or not entries:
            return EnrichmentResult(
                provider=self.PROVIDER_NAME,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict="unknown",
                raw=data,
            )

        entry = entries[0]
        malware = entry.get("malware_printable", "")
        ioc_type_tf = entry.get("ioc_type_desc", "")
        confidence = entry.get("confidence_level", 0)
        tags_raw = entry.get("tags") or []

        tags = list(tags_raw)
        if malware:
            tags.insert(0, malware)
        if ioc_type_tf:
            tags.append(ioc_type_tf)

        score = float(confidence) if confidence else 80.0

        return EnrichmentResult(
            provider=self.PROVIDER_NAME,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict="malicious",
            score=score,
            tags=tags,
            raw=data,
        )

    def _test_connectivity(self) -> tuple[bool, str]:
        """Test by querying ThreatFox for a known-benign search."""
        try:
            resp = self._session.post(
                f"{self._THREATFOX_URL}/",
                json={"query": "get_ioc_types"},
                timeout=self._timeout,
            )
            if resp.status_code == 200:
                return True, "HTTP 200 OK — abuse.ch ThreatFox reachable"
            return False, f"HTTP {resp.status_code}: {resp.reason}"
        except requests.RequestException as exc:
            return False, f"Connection failed: {exc}"
