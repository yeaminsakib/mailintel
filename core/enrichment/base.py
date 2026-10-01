"""
core/enrichment/base.py
Abstract base class for enrichment providers.

Every provider must:
1. Subclass :class:`BaseProvider`.
2. Implement :meth:`_query` (the actual HTTP call).
3. Implement :meth:`_normalize` (convert raw response → EnrichmentResult).
4. Set :attr:`PROVIDER_NAME` and :attr:`SUPPORTED_IOC_TYPES`.

The base class supplies:
- Rate limiting via :class:`RateLimiter`.
- Exponential backoff with jitter on HTTP 429 / 5xx.
- Request timeout enforcement.
- Structured logging for audit trails.
"""
from __future__ import annotations

import logging
import random
import time
from abc import ABC, abstractmethod
from typing import Any

import requests

from .models import EnrichmentResult
from .rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class BaseProvider(ABC):
    """Abstract enrichment provider.

    Subclasses must implement :meth:`_query` and :meth:`_normalize`.

    Parameters
    ----------
    api_key : str or None
        Provider API key (``None`` for keyless providers like RDAP).
    timeout : float
        HTTP request timeout in seconds.
    max_retries : int
        Maximum number of retries on transient errors (429 / 5xx).
    """

    # Subclasses MUST override these
    PROVIDER_NAME: str = ""
    SUPPORTED_IOC_TYPES: frozenset[str] = frozenset()

    # Default rate limit — subclasses should override for tighter limits
    RATE_LIMIT_TOKENS: int = 4
    RATE_LIMIT_PERIOD: float = 60.0  # seconds

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 15.0,
        max_retries: int = 3,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max_retries
        self._session = requests.Session()
        self._limiter = RateLimiter(
            max_tokens=self.RATE_LIMIT_TOKENS,
            refill_seconds=self.RATE_LIMIT_PERIOD,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Query the provider for *ioc_value* and return a normalized result.

        This is the only method callers should use.  It handles rate
        limiting, retries with backoff, and error wrapping.

        Parameters
        ----------
        ioc_type : str
            IOC type (``'ipv4'``, ``'domain'``, ``'url'``, etc.).
        ioc_value : str
            The IOC value to query.

        Returns
        -------
        EnrichmentResult
            Always returns a result — on failure, :attr:`EnrichmentResult.error`
            contains the reason.
        """
        if ioc_type not in self.SUPPORTED_IOC_TYPES:
            return EnrichmentResult(
                provider=self.PROVIDER_NAME,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                error=f"IOC type '{ioc_type}' not supported by {self.PROVIDER_NAME}",
            )

        if not self._api_key and self._requires_api_key():
            return EnrichmentResult(
                provider=self.PROVIDER_NAME,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                error=f"No API key configured for {self.PROVIDER_NAME}",
            )

        # Rate limiting — wait up to 30s for a token
        if not self._limiter.acquire(timeout=30.0):
            return EnrichmentResult(
                provider=self.PROVIDER_NAME,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                error=f"Rate limit exceeded for {self.PROVIDER_NAME}",
            )

        return self._query_with_backoff(ioc_type, ioc_value)

    def test_connectivity(self) -> tuple[bool, str]:
        """Test that the provider is reachable and the API key is valid.

        Returns ``(True, status_message)`` on success or
        ``(False, error_message)`` on failure.
        """
        try:
            ok, msg = self._test_connectivity()
            return ok, msg
        except Exception as exc:  # noqa: BLE001
            return False, f"Connection error: {exc}"

    @property
    def name(self) -> str:
        """Human-readable provider name."""
        return self.PROVIDER_NAME

    # ------------------------------------------------------------------
    # Abstract methods — subclasses MUST implement
    # ------------------------------------------------------------------

    @abstractmethod
    def _query(
        self, ioc_type: str, ioc_value: str
    ) -> requests.Response:
        """Execute the HTTP request to the provider API.

        Should raise ``requests.RequestException`` on network errors.
        The base class handles retries and error wrapping.
        """

    @abstractmethod
    def _normalize(
        self, ioc_type: str, ioc_value: str, response: requests.Response
    ) -> EnrichmentResult:
        """Parse the provider response into a normalized :class:`EnrichmentResult`."""

    # ------------------------------------------------------------------
    # Optional overrides
    # ------------------------------------------------------------------

    def _requires_api_key(self) -> bool:
        """Return ``True`` if this provider needs an API key.  Default: ``True``."""
        return True

    def _test_connectivity(self) -> tuple[bool, str]:
        """Override to implement a lightweight API health-check.

        Default: make a generic request and check the status code.
        """
        return False, "Connectivity test not implemented"

    # ------------------------------------------------------------------
    # Internals — retry with exponential backoff
    # ------------------------------------------------------------------

    def _query_with_backoff(
        self, ioc_type: str, ioc_value: str
    ) -> EnrichmentResult:
        """Execute ``_query`` with exponential backoff on transient failures."""
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                resp = self._query(ioc_type, ioc_value)

                # Success path
                if resp.status_code < 400:
                    return self._normalize(ioc_type, ioc_value, resp)

                # Client error (not retryable) — except 429
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    return EnrichmentResult(
                        provider=self.PROVIDER_NAME,
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        error=f"HTTP {resp.status_code}: {resp.reason}",
                        raw=_safe_json(resp),
                    )

                # 429 or 5xx — transient, retry with backoff
                logger.warning(
                    "%s: HTTP %d for %s %s (attempt %d/%d)",
                    self.PROVIDER_NAME, resp.status_code,
                    ioc_type, ioc_value,
                    attempt + 1, self._max_retries + 1,
                )

            except (requests.RequestException, ConnectionError, OSError) as exc:
                last_exc = exc
                logger.warning(
                    "%s: request failed for %s %s: %s (attempt %d/%d)",
                    self.PROVIDER_NAME, ioc_type, ioc_value, exc,
                    attempt + 1, self._max_retries + 1,
                )

            # Backoff: 1s, 2s, 4s + jitter
            if attempt < self._max_retries:
                delay = (2 ** attempt) + random.uniform(0, 0.5)
                time.sleep(delay)

        # All retries exhausted
        err_msg = str(last_exc) if last_exc else "Max retries exceeded"
        return EnrichmentResult(
            provider=self.PROVIDER_NAME,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            error=err_msg,
        )


def _safe_json(resp: requests.Response) -> dict[str, Any]:
    """Parse response JSON, returning empty dict on failure."""
    try:
        return resp.json()  # type: ignore[no-any-return]
    except (ValueError, AttributeError):
        return {}
