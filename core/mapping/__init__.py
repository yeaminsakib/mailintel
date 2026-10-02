"""
MITRE ATT&CK technique mapping (Phase 3).

Public API
----------
MitreMapper
    Look up ATT&CK techniques from behaviour tags.
Technique
    Dataclass for a single mapped technique.
"""
from .mitre_attack import MitreMapper, Technique

__all__ = [
    "MitreMapper",
    "Technique",
]
