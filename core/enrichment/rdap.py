"""
core/enrichment/rdap.py
RDAP (Registration Data Access Protocol) enrichment provider.

Queries domain WHOIS/RDAP data to determine **domain age** — newly
registered domains are a strong phishing signal.

This provider does NOT require an API key — RDAP is a public protocol.

RFCs: RFC 7482, RFC 7483, RFC 9082, RFC 9083
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests

from .base import BaseProvider, _safe_json
from .models import EnrichmentResult


class RDAPProvider(BaseProvider):
    """RDAP / domain-age enrichment provider."""

    PROVIDER_NAME = "rdap"
    SUPPORTED_IOC_TYPES = frozenset({"domain"})

    # RDAP is public and generally unrestricted
    RATE_LIMIT_TOKENS = 10
    RATE_LIMIT_PERIOD = 60.0

    _RDAP_BOOTSTRAP = "https://rdap.org/domain"

    def _requires_api_key(self) -> bool:
        """RDAP is keyless."""
        return False

    def _query(self, ioc_type: str, ioc_value: str) -> requests.Response:
        """Query RDAP for domain registration data."""
        return self._session.get(
            f"{self._RDAP_BOOTSTRAP}/{ioc_value}",
            timeout=self._timeout,
            headers={"Accept": "application/rdap+json"},
        )

    def _normalize(
        self, ioc_type: str, ioc_value: str, response: requests.Response
    ) -> EnrichmentResult:
        """Parse RDAP response — focus on domain age and registrar."""
        data = _safe_json(response)

        # Extract event dates
        registration_date = _extract_event_date(data, "registration")
        last_changed = _extract_event_date(data, "last changed")
        expiration_date = _extract_event_date(data, "expiration")

        # Registrar
        registrar = ""
        entities = data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) >= 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                            registrar = str(item[3])
                            break
                if not registrar:
                    registrar = entity.get("handle", "")
                break

        # Domain age analysis
        tags: list[str] = []
        score: float | None = None
        verdict = "unknown"

        if registration_date:
            now = datetime.now(timezone.utc)
            age_days = (now - registration_date).days
            tags.append(f"age:{age_days}d")

            if age_days < 7:
                verdict = "malicious"
                score = 95.0
                tags.append("newly_registered")
            elif age_days < 30:
                verdict = "suspicious"
                score = 70.0
                tags.append("recently_registered")
            elif age_days < 90:
                verdict = "suspicious"
                score = 40.0
                tags.append("young_domain")
            elif age_days < 365:
                verdict = "clean"
                score = 15.0
            else:
                verdict = "clean"
                score = 5.0
                tags.append("established")

        if registrar:
            tags.append(f"registrar:{registrar}")
        if expiration_date:
            tags.append(f"expires:{expiration_date.date().isoformat()}")

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
        """Test by querying RDAP for 'example.com'."""
        try:
            resp = self._session.get(
                f"{self._RDAP_BOOTSTRAP}/example.com",
                timeout=self._timeout,
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code == 200:
                return True, "HTTP 200 OK — RDAP service reachable"
            return False, f"HTTP {resp.status_code}: {resp.reason}"
        except requests.RequestException as exc:
            return False, f"Connection failed: {exc}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_event_date(data: dict[str, Any], action: str) -> datetime | None:
    """Extract an event date from RDAP events array."""
    events = data.get("events", [])
    for event in events:
        if event.get("eventAction", "").lower() == action.lower():
            date_str = event.get("eventDate", "")
            if date_str:
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except (ValueError, TypeError):
                    pass
    return None
