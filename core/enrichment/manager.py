"""
core/enrichment/manager.py
Enrichment orchestrator — coordinates providers, cache, and DB writes.

The :class:`EnrichmentManager` is the single entry point for all enrichment
operations.  It:

1. Loads API keys from the OS keyring.
2. Initializes all configured providers.
3. Checks the SQLite cache (TTL-based) before hitting the network.
4. Writes results back to the enrichments table.
5. Never crashes — all provider errors are caught and logged.
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from core.storage.database import Database

from .abuseipdb import AbuseIPDBProvider
from .abusech import AbuseCHProvider
from .base import BaseProvider
from .cache import EnrichmentCache
from .keys import get_api_key
from .models import EnrichmentResult
from .otx import OTXProvider
from .rdap import RDAPProvider
from .virustotal import VirusTotalProvider

logger = logging.getLogger(__name__)


# Provider registry — maps provider slugs to their classes and
# which IOC types they support.
_PROVIDER_CLASSES: dict[str, type[BaseProvider]] = {
    "virustotal": VirusTotalProvider,
    "abuseipdb":  AbuseIPDBProvider,
    "abusech":    AbuseCHProvider,
    "otx":        OTXProvider,
    "rdap":       RDAPProvider,
}


class EnrichmentManager:
    """Central enrichment orchestrator.

    Parameters
    ----------
    db : Database
        Open database instance for cache reads/writes.
    cache_ttl : timedelta or None
        TTL for cached results.  Defaults to 24 hours.
    providers : list[str] or None
        Subset of provider names to enable.  Defaults to all.
    """

    def __init__(
        self,
        db: Database,
        cache_ttl: timedelta | None = None,
        providers: list[str] | None = None,
    ) -> None:
        self._db = db
        self._cache = EnrichmentCache(db, ttl=cache_ttl)
        self._providers: dict[str, BaseProvider] = {}

        enabled = providers if providers is not None else list(_PROVIDER_CLASSES.keys())
        for name in enabled:
            self._init_provider(name)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_ioc(
        self,
        ioc_id: int,
        ioc_type: str,
        ioc_value: str,
        provider_names: list[str] | None = None,
    ) -> list[EnrichmentResult]:
        """Enrich a single IOC across all (or selected) providers.

        Steps per provider:
        1. Check SQLite cache.  If hit and not expired → return cached.
        2. Call provider API.
        3. Write result to cache / enrichments table.

        Parameters
        ----------
        ioc_id : int
            Database row id of the IOC.
        ioc_type : str
            IOC type (``'ipv4'``, ``'domain'``, etc.).
        ioc_value : str
            The IOC value.
        provider_names : list[str] or None
            Restrict to specific providers.  ``None`` = all enabled.

        Returns
        -------
        list[EnrichmentResult]
            One result per provider (may include errors or cache hits).
        """
        results: list[EnrichmentResult] = []
        targets = provider_names if provider_names else list(self._providers.keys())

        for name in targets:
            provider = self._providers.get(name)
            if provider is None:
                continue
            if ioc_type not in provider.SUPPORTED_IOC_TYPES:
                continue

            # 1. Cache check
            cached = self._cache.get(ioc_id, name)
            if cached is not None:
                cached.ioc_type = ioc_type
                cached.ioc_value = ioc_value
                results.append(cached)
                continue

            # 2. Live query
            try:
                result = provider.enrich(ioc_type, ioc_value)
            except Exception as exc:  # noqa: BLE001
                logger.error("Provider %s crashed: %s", name, exc)
                result = EnrichmentResult(
                    provider=name,
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    error=f"Internal error: {exc}",
                )

            # 3. Cache write (only successful results)
            if result.success:
                try:
                    self._cache.put(ioc_id, result)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Cache write failed for %s: %s", name, exc)

            results.append(result)

        return results

    def enrich_all_iocs(
        self,
        provider_names: list[str] | None = None,
        limit: int | None = None,
    ) -> dict[int, list[EnrichmentResult]]:
        """Enrich all IOCs in the database.

        Parameters
        ----------
        provider_names : list[str] or None
            Restrict to specific providers.
        limit : int or None
            Maximum number of IOCs to enrich (for testing / quota management).

        Returns
        -------
        dict[int, list[EnrichmentResult]]
            Mapping of ioc_id → list of results.
        """
        all_iocs = self._db.get_all_iocs()
        if limit:
            all_iocs = all_iocs[:limit]

        results_map: dict[int, list[EnrichmentResult]] = {}
        for ioc in all_iocs:
            ioc_id = ioc["id"]
            results = self.enrich_ioc(
                ioc_id=ioc_id,
                ioc_type=ioc["type"],
                ioc_value=ioc["value"],
                provider_names=provider_names,
            )
            results_map[ioc_id] = results

        return results_map

    def test_provider(self, provider_name: str) -> tuple[bool, str]:
        """Test connectivity for a single provider.

        Returns ``(True, message)`` on success or ``(False, message)`` on failure.
        """
        provider = self._providers.get(provider_name)
        if provider is None:
            return False, f"Provider '{provider_name}' is not configured"
        return provider.test_connectivity()

    def get_enabled_providers(self) -> list[str]:
        """Return names of all initialized providers."""
        return list(self._providers.keys())

    def get_provider(self, name: str) -> BaseProvider | None:
        """Return a provider instance by name, or ``None``."""
        return self._providers.get(name)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _init_provider(self, name: str) -> None:
        """Initialize a provider by name, loading its API key from keyring."""
        cls = _PROVIDER_CLASSES.get(name)
        if cls is None:
            logger.warning("Unknown provider: %s", name)
            return

        # Load API key from keyring (some providers don't need one)
        api_key = get_api_key(name)

        try:
            instance = cls(api_key=api_key)
            self._providers[name] = instance
            logger.info(
                "Initialized provider: %s (key: %s)",
                name, "configured" if api_key else "none",
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to initialize provider %s: %s", name, exc)
