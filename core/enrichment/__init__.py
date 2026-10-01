"""
Threat intelligence enrichment providers.

Public API
----------
EnrichmentManager
    Central orchestrator — the only class callers need.
EnrichmentResult
    Normalized result dataclass returned by all providers.
get_api_key / set_api_key / delete_api_key
    Secure API key management via the OS keyring.
"""
from .keys import delete_api_key, get_api_key, set_api_key
from .manager import EnrichmentManager
from .models import EnrichmentResult

__all__ = [
    "EnrichmentManager",
    "EnrichmentResult",
    "delete_api_key",
    "get_api_key",
    "set_api_key",
]
