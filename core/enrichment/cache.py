"""
core/enrichment/cache.py
SQLite-backed enrichment cache with TTL.

Wraps :meth:`Database.upsert_enrichment` / :meth:`Database.get_enrichments_for_ioc`
to provide TTL-based expiry.  Expired entries are treated as cache misses and
transparently refreshed by the provider.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from core.storage.database import Database
from .models import EnrichmentResult


# Default TTL for cached enrichment results
DEFAULT_TTL: timedelta = timedelta(hours=24)


class EnrichmentCache:
    """SQLite-backed TTL cache for enrichment results.

    Parameters
    ----------
    db : Database
        Open database instance.
    ttl : timedelta
        Maximum age for cached results.  Entries older than *ttl* are
        considered stale and will be re-fetched.
    """

    def __init__(self, db: Database, ttl: timedelta | None = None) -> None:
        self._db = db
        self._ttl = ttl if ttl is not None else DEFAULT_TTL

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(
        self,
        ioc_id: int,
        provider: str,
    ) -> EnrichmentResult | None:
        """Return a cached result if it exists and hasn't expired.

        Returns ``None`` on cache miss or expiry.
        """
        rows = self._db.get_enrichments_for_ioc(ioc_id)
        for row in rows:
            if row["provider"] != provider:
                continue
            # Check TTL
            fetched_at = datetime.fromisoformat(row["fetched_at"])
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - fetched_at
            if age >= self._ttl:
                return None  # expired

            raw = _safe_json_loads(row.get("raw_json", "{}"))
            return EnrichmentResult(
                provider=provider,
                verdict=row.get("verdict", "unknown"),
                score=row.get("score"),
                tags=raw.get("_tags", []),
                raw=raw,
                cached=True,
            )
        return None

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def put(
        self,
        ioc_id: int,
        result: EnrichmentResult,
    ) -> None:
        """Store an enrichment result in the cache.

        The raw dict is augmented with a ``_tags`` key so tags survive
        the round-trip through JSON.
        """
        raw_copy = dict(result.raw)
        raw_copy["_tags"] = result.tags
        self._db.upsert_enrichment(
            ioc_id=ioc_id,
            provider=result.provider,
            raw_json=json.dumps(raw_copy, default=str),
            verdict=result.verdict,
            score=result.score,
        )


def _safe_json_loads(s: str) -> dict[str, Any]:
    """Parse JSON, returning an empty dict on failure."""
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}
