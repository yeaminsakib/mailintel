"""
core/enrichment/models.py
Normalized data models for enrichment results.

All providers return their results as an :class:`EnrichmentResult`, ensuring
a uniform interface for the scoring engine, the UI, and the SQLite cache.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrichmentResult:
    """Normalized enrichment result from any provider.

    Attributes
    ----------
    provider : str
        Provider slug (``'virustotal'``, ``'abuseipdb'``, etc.).
    ioc_type : str
        IOC type that was queried (``'ipv4'``, ``'domain'``, ``'url'``,
        ``'hash_sha256'``, etc.).
    ioc_value : str
        The raw IOC value that was queried.
    verdict : str
        One of ``'malicious'``, ``'suspicious'``, ``'clean'``, ``'unknown'``.
    score : float | None
        Numeric score (0–100) if the provider exposes one, else ``None``.
    tags : list[str]
        Free-form labels (e.g. ``['trojan', 'emotet']``).
    raw : dict[str, Any]
        Full provider response for auditability.
    error : str | None
        Error message if the query failed.
    cached : bool
        ``True`` if this result was served from the SQLite cache.
    """

    provider: str
    ioc_type: str = ""
    ioc_value: str = ""
    verdict: str = "unknown"
    score: float | None = None
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    cached: bool = False

    @property
    def success(self) -> bool:
        """Return ``True`` if the query succeeded without errors."""
        return self.error is None
